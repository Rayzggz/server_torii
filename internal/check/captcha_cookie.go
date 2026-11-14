package check

import (
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/token"
	"time"
)

// verifyToken checks a cookie value against the request's host and user agent.
func verifyToken(reqData request.UserRequest, signer token.Signer, value string, maxAge int64) bool {
	if value == "" {
		return false
	}
	return signer.Verify(value, reqData.Host, GetClearanceUserAgent(reqData.UserAgent), maxAge, time.Now())
}

func signToken(reqData request.UserRequest, signer token.Signer) []byte {
	return []byte(signer.Sign(reqData.Host, GetClearanceUserAgent(reqData.UserAgent), time.Now()))
}

// challengeSigner signs one kind of token, "CLEARANCE" or "SESSION", of the site's challenge.
// The label carries the mode and the site: a token of one site is useless on another, also when
// two sites share a secret key and a host name, and a token earned with a CAPTCHA is useless
// once the site hands its clients to the external provider.
func challengeSigner(ruleSet config.RuleSet, kind string) token.Signer {
	family := "CAPTCHA"
	if ruleSet.Challenge.Mode == config.ChallengeExternal {
		family = "EXTERNAL"
	}
	return token.Signer{Keys: ruleSet.Challenge.Keys, Label: family + "-" + kind + "@" + ruleSet.ID}
}

// GenClearance issues the cookie that lets a client who passed the challenge through.
func GenClearance(reqData request.UserRequest, ruleSet config.RuleSet) []byte {
	return signToken(reqData, challengeSigner(ruleSet, "CLEARANCE"))
}

func verifyClearanceCookie(reqData request.UserRequest, ruleSet config.RuleSet) bool {
	return verifyToken(reqData, challengeSigner(ruleSet, "CLEARANCE"), reqData.ToriiClearance, ruleSet.Challenge.ClearanceTTL)
}

// GenSessionID issues the challenge session cookie. A CAPTCHA session the client already holds
// is kept while it is valid. A client sent to the external provider always gets a new one, in
// the form the provider expects: its timestamp is part of the link that brings the client back.
func GenSessionID(reqData request.UserRequest, ruleSet config.RuleSet) []byte {
	if !ruleSet.Challenge.ShowsCaptcha() {
		return []byte(externalSession(reqData, ruleSet, ruleSet.Challenge.SigningKey(), time.Now().Unix()))
	}
	if VerifySessionIDCookie(reqData, ruleSet) {
		return []byte(reqData.ToriiSessionID)
	}
	return signToken(reqData, challengeSigner(ruleSet, "SESSION"))
}

// VerifySessionIDCookie reports whether the client holds a challenge session of the site. A
// CAPTCHA session expires after SessionTTL. For the external provider only the signature is
// checked: the age is bounded by the 30-second lifetime of the link that must accompany it.
func VerifySessionIDCookie(reqData request.UserRequest, ruleSet config.RuleSet) bool {
	if !ruleSet.Challenge.ShowsCaptcha() {
		return verifyExternalSession(reqData, ruleSet)
	}
	return verifyToken(reqData, challengeSigner(ruleSet, "SESSION"), reqData.ToriiSessionID, ruleSet.Challenge.SessionTTL)
}
