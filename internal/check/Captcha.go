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

func Captcha(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision) {
	if !reqData.Captcha {
		decision.Set(action.Continue)
		return
	}

	if !verifyClearanceCookie(reqData, *ruleSet) {
		decision.SetCode(action.Done, []byte("CAPTCHA"))
		return
	}

	decision.Set(action.Continue)

}

func CheckCaptcha(r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision) {
	if r.Method != "POST" {
		decision.SetResponse(action.Done, []byte("403"), nil)
		return
	}

	hCaptchaResponse := r.FormValue("h-captcha-response")
	if hCaptchaResponse == "" {
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	data := url.Values{}
	data.Set("secret", ruleSet.CAPTCHARule.HCaptchaSecret)
	data.Set("response", hCaptchaResponse)
	data.Set("remoteip", reqData.RemoteIP)

	resp, err := http.PostForm("https://api.hcaptcha.com/siteverify", data)
	if err != nil {
		decision.SetResponse(action.Done, []byte("500"), []byte("bad"))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		decision.SetResponse(action.Done, []byte("500"), []byte("bad"))
		return
	}

	var hCaptchaResp HCaptchaResponse
	err = json.Unmarshal(body, &hCaptchaResp)
	if err != nil {
		decision.SetResponse(action.Done, []byte("500"), []byte("bad"))
		return
	}

	if !hCaptchaResp.Success {
		decision.SetResponse(action.Done, []byte("200"), []byte("bad4"))
		return
	}

	decision.SetResponse(action.Done, []byte("200"), []byte("good"))
	return

}

func GenClearance(reqData dataType.UserRequest, ruleSet config.RuleSet) []byte {
	timeNow := time.Now().Unix()
	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%s", timeNow, reqData.Host, reqData.UserAgent)))
	return []byte(fmt.Sprintf("%s:%s", fmt.Sprintf("%d", time.Now().Unix()), fmt.Sprintf("%x", mac.Sum(nil))))
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
		return false
	}

	if timeNow-parsedTimestamp > ruleSet.CAPTCHARule.CaptchaValidateTime {
		return false
	}

	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%s", parsedTimestamp, reqData.Host, reqData.UserAgent)))
	computedHash := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(computedHash), []byte(expectedHash))

}
