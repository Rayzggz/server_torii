package check

import (
	"crypto/hmac"
	"crypto/sha512"
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

	ipKey := reqData.RemoteIP
	// Check failure limit
	for window, limit := range ruleSet.CAPTCHARule.CaptchaFailureLimit {
		if sharedMem.CaptchaFailureLimitCounter.Query(ipKey, window) > limit {
			utils.LogInfo(reqData, "", fmt.Sprintf("Captcha failure rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
			decision.SetCode(action.Done, []byte("403"))
			return
		}
	}

	if !verifyClearanceCookie(reqData, *ruleSet) {
		decision.SetCode(action.Done, []byte("CAPTCHA"))
		return
	}

	decision.Set(action.Continue)

}

func CheckCaptcha(r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if r.Method != "POST" {
		decision.SetResponse(action.Done, []byte("403"), nil)
		return
	}

	hCaptchaResponse := r.FormValue("h-captcha-response")
	if hCaptchaResponse == "" {
		sharedMem.CaptchaFailureLimitCounter.Add(reqData.RemoteIP, 1)
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	if !verifySessionIDCookie(reqData, *ruleSet) {
		sharedMem.CaptchaFailureLimitCounter.Add(reqData.RemoteIP, 1)
		decision.SetResponse(action.Done, []byte("200"), []byte("badSession"))
		return
	}

	data := url.Values{}
	data.Set("secret", ruleSet.CAPTCHARule.HCaptchaSecret)
	data.Set("response", hCaptchaResponse)
	data.Set("remoteip", reqData.RemoteIP)

	resp, err := http.PostForm("https://api.hcaptcha.com/siteverify", data)
	if err != nil {
		utils.LogError(reqData, "", fmt.Sprintf("Error sending request to hCaptcha: %v", err))
		sharedMem.CaptchaFailureLimitCounter.Add(reqData.RemoteIP, 1)
		decision.SetResponse(action.Done, []byte("500"), []byte("bad"))
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			utils.LogError(reqData, "", fmt.Sprintf("Error closing response body: %v", err))
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.LogError(reqData, "", fmt.Sprintf("Error reading response from hCaptcha: %v", err))
		sharedMem.CaptchaFailureLimitCounter.Add(reqData.RemoteIP, 1)
		decision.SetResponse(action.Done, []byte("500"), []byte("bad"))
		return
	}

	var hCaptchaResp HCaptchaResponse
	err = json.Unmarshal(body, &hCaptchaResp)
	if err != nil {
		utils.LogError(reqData, "", fmt.Sprintf("Error parsing response from hCaptcha: %v", err))
		sharedMem.CaptchaFailureLimitCounter.Add(reqData.RemoteIP, 1)
		decision.SetResponse(action.Done, []byte("500"), []byte("bad"))
		return
	}

	if !hCaptchaResp.Success {
		sharedMem.CaptchaFailureLimitCounter.Add(reqData.RemoteIP, 1)
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	decision.SetResponse(action.Done, []byte("200"), []byte("good"))
	return

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

func verifySessionIDCookie(reqData dataType.UserRequest, ruleSet config.RuleSet) bool {
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
