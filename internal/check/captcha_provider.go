package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"strings"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

const (
	CaptchaProviderHCaptcha = "hcaptcha"
	CaptchaProviderAltcha   = "altcha"

	altchaAlgorithm = "PBKDF2/SHA-512"
	altchaKeyLength = 32
)

type HCaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

type captchaVerificationResult uint8

const (
	captchaVerificationInvalid captchaVerificationResult = iota
	captchaVerificationValid
	captchaVerificationSessionMismatch
)

func hasCaptchaResponse(r *http.Request, ruleSet *config.RuleSet) bool {
	if captchaProvider(ruleSet.CAPTCHARule) == CaptchaProviderAltcha {
		return r.FormValue("altcha") != ""
	}
	return r.FormValue("h-captcha-response") != ""
}

func verifyCaptchaResponse(r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet) (captchaVerificationResult, error) {
	if captchaProvider(ruleSet.CAPTCHARule) == CaptchaProviderAltcha {
		return verifyAltchaResponse(r, reqData, ruleSet)
	}

	ok, err := verifyHCaptchaResponse(r, reqData, ruleSet)
	if err != nil {
		return captchaVerificationInvalid, err
	}
	if ok {
		return captchaVerificationValid, nil
	}
	return captchaVerificationInvalid, nil
}

func verifyHCaptchaResponse(r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet) (bool, error) {
	hCaptchaResponse := r.FormValue("h-captcha-response")
	if hCaptchaResponse == "" {
		return false, nil
	}

	data := url.Values{}
	data.Set("secret", ruleSet.CAPTCHARule.HCaptchaSecret)
	data.Set("response", hCaptchaResponse)
	data.Set("remoteip", reqData.RemoteIP)

	httpClient := http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.PostForm("https://api.hcaptcha.com/siteverify", data)
	if err != nil {
		return false, fmt.Errorf("error sending request to hCaptcha: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logx.LogError(reqData, "", fmt.Sprintf("Error closing response body: %v", err))
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hCaptcha siteverify returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading response from hCaptcha: %v", err)
	}

	var hCaptchaResp HCaptchaResponse
	err = json.Unmarshal(body, &hCaptchaResp)
	if err != nil {
		return false, fmt.Errorf("error parsing response from hCaptcha: %v", err)
	}

	return hCaptchaResp.Success, nil
}

func verifyAltchaResponse(r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet) (captchaVerificationResult, error) {
	altchaResponse := r.FormValue("altcha")
	if altchaResponse == "" {
		return captchaVerificationInvalid, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(altchaResponse)
	if err != nil {
		return captchaVerificationInvalid, nil
	}

	var payload altcha.Payload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return captchaVerificationInvalid, nil
	}

	actualSessionBinding, ok := altchaChallengeSessionBinding(payload.Challenge)
	if !ok {
		return captchaVerificationInvalid, nil
	}

	result, err := altcha.VerifySolution(altcha.VerifySolutionOptions{
		Challenge:           payload.Challenge,
		Solution:            payload.Solution,
		DeriveKey:           altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret: altchaHMACSecret(ruleSet.CAPTCHARule),
	})
	if err != nil {
		return captchaVerificationInvalid, fmt.Errorf("error verifying ALTCHA response: %v", err)
	}
	if !result.Verified {
		return captchaVerificationInvalid, nil
	}

	expectedSessionBinding := altchaSessionBinding(reqData, *ruleSet)
	if !hmac.Equal([]byte(actualSessionBinding), []byte(expectedSessionBinding)) {
		return captchaVerificationSessionMismatch, nil
	}

	return captchaVerificationValid, nil
}

func altchaChallengeSessionBinding(challenge altcha.Challenge) (string, bool) {
	if challenge.Parameters.Data == nil {
		return "", false
	}

	actual, ok := challenge.Parameters.Data[("toriiSession")].(string)
	if !ok || actual == "" {
		return "", false
	}

	return actual, true
}

func altchaSessionBinding(reqData request.UserRequest, ruleSet config.RuleSet) string {
	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(reqData.ToriiSessionID))
	mac.Write([]byte(reqData.Host))
	mac.Write([]byte(GetClearanceUserAgent(reqData.UserAgent)))
	mac.Write([]byte(("ALTCHA-SESSION-BINDING")))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func GenAltchaChallenge(ruleSet config.RuleSet, reqData request.UserRequest) (altcha.Challenge, error) {
	expiresAt := time.Now().Add(time.Duration(ruleSet.CAPTCHARule.CaptchaChallengeSessionTimeout) * time.Second)
	return altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:           altchaAlgorithm,
		DeriveKey:           altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret: altchaHMACSecret(ruleSet.CAPTCHARule),
		Cost:                ruleSet.CAPTCHARule.AltchaCost,
		KeyLength:           altchaKeyLength,
		ExpiresAt:           &expiresAt,
		Data: map[string]interface{}{
			"toriiSession": altchaSessionBinding(reqData, ruleSet),
		},
	})
}

func IsAltchaProvider(rule *config.CaptchaRule) bool {
	return captchaProvider(rule) == CaptchaProviderAltcha
}

func captchaProvider(rule *config.CaptchaRule) string {
	if rule == nil || rule.Provider == "" {
		return CaptchaProviderHCaptcha
	}
	return strings.ToLower(rule.Provider)
}

func altchaHMACSecret(rule *config.CaptchaRule) string {
	if rule.AltchaHMACSecret != "" {
		return rule.AltchaHMACSecret
	}
	return rule.SecretKey
}
