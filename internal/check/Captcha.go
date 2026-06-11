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
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strconv"
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

func Captcha(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	// Check if Captcha feature is enabled using binary operation
	if (reqData.FeatureControl & dataType.FeatureCaptcha) == 0 {
		decision.Set(action.Continue)
		return
	}

	failureCounter := sharedMem.CaptchaFailureLimitCounter.Load()
	if failureCounter == nil {
		utils.LogError(reqData, "", "Captcha failure counter is not initialized, skipping captcha rate checks")
		decision.Set(action.Continue)
		return
	}

	ipKey := reqData.RemoteIP

	// Check failure limit
	for limitTime, limitCount := range ruleSet.CAPTCHARule.CaptchaFailureLimit {
		count := failureCounter.Query(ipKey, limitTime)
		if count > limitCount {

			if ruleSet.CAPTCHARule.FailureBlockDuration > 0 {
				if engine, ok := sharedMem.ActionRuleEngine.(*action.ActionRuleEngine); ok {
					engine.AddIPRule(ipKey, action.ActionBlock, time.Duration(ruleSet.CAPTCHARule.FailureBlockDuration)*time.Second)
					utils.BroadcastActionRule(config.GlobalConfig.NodeName, "IP", ipKey, string(action.ActionBlock), time.Duration(ruleSet.CAPTCHARule.FailureBlockDuration)*time.Second, sharedMem.GossipChan)
				} else {
					utils.LogError(reqData, "", "Failed to cast ActionRuleEngine, skipping block and broadcast")
				}
				utils.LogInfo(reqData, "", fmt.Sprintf("Captcha failure rate limit exceeded and blocked: IP %s window %d limit %d", ipKey, limitTime, limitCount))
				failureCounter.Reset(ipKey)
				decision.SetCode(action.Done, []byte("403"))
				return
			}
		}
	}

	if !verifyClearanceCookie(reqData, *ruleSet) {
		failureCounter.Add(reqData.RemoteIP, 1)
		decision.SetCode(action.Done, []byte("CAPTCHA"))
		return
	}

	decision.Set(action.Continue)

}

func CheckCaptcha(r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	failureCounter := sharedMem.CaptchaFailureLimitCounter.Load()

	if r.Method != "POST" {
		decision.SetResponse(action.Done, []byte("403"), nil)
		return
	}

	if !hasCaptchaResponse(r, ruleSet) {
		if failureCounter != nil {
			failureCounter.Add(reqData.RemoteIP, 1)
		} else {
			utils.LogError(reqData, "", "Captcha failure counter is not initialized, skipping captcha failure increment")
		}
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	if !VerifySessionIDCookie(reqData, *ruleSet) {
		if failureCounter != nil {
			failureCounter.Add(reqData.RemoteIP, 1)
		} else {
			utils.LogError(reqData, "", "Captcha failure counter is not initialized, skipping captcha failure increment")
		}
		decision.SetResponse(action.Done, []byte("200"), []byte("badSession"))
		return
	}

	ok, err := verifyCaptchaResponse(r, reqData, ruleSet)
	if err != nil {
		utils.LogError(reqData, "", err.Error())
		decision.SetResponse(action.Done, []byte("500"), []byte("bad"))
		return
	}
	if !ok {
		if failureCounter != nil {
			failureCounter.Add(reqData.RemoteIP, 1)
		} else {
			utils.LogError(reqData, "", "Captcha failure counter is not initialized, skipping captcha failure increment")
		}
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	decision.SetResponse(action.Done, []byte("200"), []byte("good"))
}

func hasCaptchaResponse(r *http.Request, ruleSet *config.RuleSet) bool {
	if captchaProvider(ruleSet.CAPTCHARule) == CaptchaProviderAltcha {
		return r.FormValue("altcha") != ""
	}
	return r.FormValue("h-captcha-response") != ""
}

func verifyCaptchaResponse(r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet) (bool, error) {
	if captchaProvider(ruleSet.CAPTCHARule) == CaptchaProviderAltcha {
		return verifyAltchaResponse(r, reqData, ruleSet)
	}
	return verifyHCaptchaResponse(r, reqData, ruleSet)
}

func verifyHCaptchaResponse(r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet) (bool, error) {
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
			utils.LogError(reqData, "", fmt.Sprintf("Error closing response body: %v", err))
		}
	}(resp.Body)

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

func verifyAltchaResponse(r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet) (bool, error) {
	altchaResponse := r.FormValue("altcha")
	if altchaResponse == "" {
		return false, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(altchaResponse)
	if err != nil {
		return false, nil
	}

	var payload altcha.Payload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return false, nil
	}

	if !verifyAltchaSessionBinding(payload.Challenge, reqData, *ruleSet) {
		return false, nil
	}

	result, err := altcha.VerifySolution(altcha.VerifySolutionOptions{
		Challenge:           payload.Challenge,
		Solution:            payload.Solution,
		DeriveKey:           altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret: altchaHMACSecret(ruleSet.CAPTCHARule),
	})
	if err != nil {
		return false, fmt.Errorf("error verifying ALTCHA response: %v", err)
	}

	return result.Verified, nil
}

func verifyAltchaSessionBinding(challenge altcha.Challenge, reqData dataType.UserRequest, ruleSet config.RuleSet) bool {
	if challenge.Parameters.Data == nil {
		return false
	}

	actual, ok := challenge.Parameters.Data[("toriiSession")].(string)
	if !ok || actual == "" {
		return false
	}

	expected := altchaSessionBinding(reqData, ruleSet)
	return hmac.Equal([]byte(actual), []byte(expected))
}

func altchaSessionBinding(reqData dataType.UserRequest, ruleSet config.RuleSet) string {
	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(reqData.ToriiSessionID))
	mac.Write([]byte(reqData.Host))
	mac.Write([]byte(utils.GetClearanceUserAgent(reqData.UserAgent)))
	mac.Write([]byte(("ALTCHA-SESSION-BINDING")))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func GenAltchaChallenge(ruleSet config.RuleSet, reqData dataType.UserRequest) (altcha.Challenge, error) {
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

func IsAltchaProvider(rule *dataType.CaptchaRule) bool {
	return captchaProvider(rule) == CaptchaProviderAltcha
}

func captchaProvider(rule *dataType.CaptchaRule) string {
	if rule == nil || rule.Provider == "" {
		return CaptchaProviderHCaptcha
	}
	return strings.ToLower(rule.Provider)
}

func altchaHMACSecret(rule *dataType.CaptchaRule) string {
	if rule.AltchaHMACSecret != "" {
		return rule.AltchaHMACSecret
	}
	return rule.SecretKey
}

func GenClearance(reqData dataType.UserRequest, ruleSet config.RuleSet) []byte {
	timeNow := time.Now().Unix()
	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sCAPTCHA-CLEARANCE", timeNow, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	return []byte(fmt.Sprintf("%s:%s", fmt.Sprintf("%d", timeNow), fmt.Sprintf("%x", mac.Sum(nil))))
}

func verifyClearanceCookie(reqData dataType.UserRequest, ruleSet config.RuleSet) bool {
	if reqData.ToriiClearance == "" {
		return false
	}
	parts := strings.Split(reqData.ToriiClearance, ":")
	if len(parts) != 2 {
		return false
	}
	timestamp := parts[0]
	expectedHash := parts[1]

	timeNow := time.Now().Unix()
	parsedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		utils.LogError(reqData, "", fmt.Sprintf("Error parsing timestamp: %v", err))
		return false
	}

	if timeNow-parsedTimestamp > ruleSet.CAPTCHARule.CaptchaValidateTime {
		return false
	}

	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sCAPTCHA-CLEARANCE", parsedTimestamp, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	computedHash := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(computedHash), []byte(expectedHash))

}

func GenSessionID(reqData dataType.UserRequest, ruleSet config.RuleSet) []byte {
	timeNow := time.Now().Unix()
	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sCAPTCHA-SESSION", timeNow, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	return []byte(fmt.Sprintf("%s:%s", fmt.Sprintf("%d", timeNow), fmt.Sprintf("%x", mac.Sum(nil))))
}

func VerifySessionIDCookie(reqData dataType.UserRequest, ruleSet config.RuleSet) bool {
	if reqData.ToriiSessionID == "" {
		return false
	}
	parts := strings.Split(reqData.ToriiSessionID, ":")
	if len(parts) != 2 {
		return false
	}
	timestamp := parts[0]
	expectedHash := parts[1]

	timeNow := time.Now().Unix()
	parsedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		utils.LogError(reqData, "", fmt.Sprintf("Error parsing timestamp: %v", err))
		return false
	}

	if timeNow-parsedTimestamp > ruleSet.CAPTCHARule.CaptchaChallengeSessionTimeout {
		return false
	}

	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sCAPTCHA-SESSION", parsedTimestamp, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	computedHash := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(computedHash), []byte(expectedHash))

}
