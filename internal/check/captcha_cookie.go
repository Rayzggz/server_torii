package check

import (
	"fmt"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/token"
	"time"
)

// verifyToken checks a cookie value against the request's host and user agent.
func verifyToken(reqData request.UserRequest, signer token.Signer, value string, maxAge int64) bool {
	if value == "" {
		return false
	}
	ok, err := signer.Verify(value, reqData.Host, GetClearanceUserAgent(reqData.UserAgent), maxAge, time.Now())
	if err != nil {
		logx.Error(reqData, "", fmt.Sprintf("Error parsing timestamp: %v", err))
	}
	return ok
}

func signToken(reqData request.UserRequest, signer token.Signer) []byte {
	return []byte(signer.Sign(reqData.Host, GetClearanceUserAgent(reqData.UserAgent), time.Now()))
}

// siteLabel makes a token of one site useless on another, also when two sites share a secret
// key and a host name.
func siteLabel(ruleSet config.RuleSet, kind string) string {
	return kind + "@" + ruleSet.ID
}

func captchaClearanceSigner(ruleSet config.RuleSet) token.Signer {
	return token.Signer{Key: ruleSet.CAPTCHARule.SecretKey, Label: siteLabel(ruleSet, "CAPTCHA-CLEARANCE")}
}

func captchaSessionSigner(ruleSet config.RuleSet) token.Signer {
	return token.Signer{Key: ruleSet.CAPTCHARule.SecretKey, Label: siteLabel(ruleSet, "CAPTCHA-SESSION")}
}

// GenClearance issues the cookie that lets a client who solved a CAPTCHA through.
func GenClearance(reqData request.UserRequest, ruleSet config.RuleSet) []byte {
	return signToken(reqData, captchaClearanceSigner(ruleSet))
}

func verifyClearanceCookie(reqData request.UserRequest, ruleSet config.RuleSet) bool {
	return verifyToken(reqData, captchaClearanceSigner(ruleSet), reqData.ToriiClearance, ruleSet.CAPTCHARule.CaptchaValidateTime)
}

// GenSessionID issues the challenge session cookie, keeping the client's current one while it is valid.
func GenSessionID(reqData request.UserRequest, ruleSet config.RuleSet) []byte {
	if VerifySessionIDCookie(reqData, ruleSet) {
		return []byte(reqData.ToriiSessionID)
	}
	return signToken(reqData, captchaSessionSigner(ruleSet))
}

// VerifySessionIDCookie reports whether the client holds an unexpired challenge session.
func VerifySessionIDCookie(reqData request.UserRequest, ruleSet config.RuleSet) bool {
	return verifyToken(reqData, captchaSessionSigner(ruleSet), reqData.ToriiSessionID, ruleSet.CAPTCHARule.CaptchaChallengeSessionTimeout)
}
