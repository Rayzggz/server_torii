package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"strconv"
	"strings"
)

// What is exchanged with the external provider: two signatures and the session ID. Their format
// is part of the protocol the provider implements and must not change.

// CalculateExternalMigrationHMAC signs the link the provider sends a cleared client back with.
func CalculateExternalMigrationHMAC(sessionID, timestampStr, originalURI, secretKey string) string {
	mac := hmac.New(sha512.New, []byte(secretKey))
	mac.Write(fmt.Appendf(nil, "%s%s%s", sessionID, timestampStr, originalURI))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// CalculateRedirectHMAC signs the redirect that hands a client to the provider.
func CalculateRedirectHMAC(domain, timestampStr, originalUri, secretKey string) string {
	mac := hmac.New(sha512.New, []byte(secretKey))
	mac.Write(fmt.Appendf(nil, "%s:%s:%s", domain, timestampStr, originalUri))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// externalSession is the session handed to the provider: "<unix seconds>:<hex HMAC-SHA512>".
// It does not use the token format of the other cookies, because the provider reads the
// timestamp in front of the colon to verify the signature of the redirect.
func externalSession(reqData request.UserRequest, ruleSet config.RuleSet, key string, ts int64) string {
	mac := hmac.New(sha512.New, []byte(key))
	mac.Write(fmt.Appendf(nil, "%d%s%sEXTERNAL-SESSION@%s", ts, reqData.Host, GetClearanceUserAgent(reqData.UserAgent), ruleSet.ID))
	return fmt.Sprintf("%d:%x", ts, mac.Sum(nil))
}

// verifyExternalSession checks the signature of the session against every key of the site. The
// age is not checked: it is bounded by the 30-second lifetime of the link that must accompany it.
func verifyExternalSession(reqData request.UserRequest, ruleSet config.RuleSet) bool {
	stamp, ok := ExternalSessionTimestamp(reqData.ToriiSessionID)
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return false
	}
	for _, key := range ruleSet.Challenge.Keys {
		if hmac.Equal([]byte(externalSession(reqData, ruleSet, key, ts)), []byte(reqData.ToriiSessionID)) {
			return true
		}
	}
	return false
}

// ExternalSessionTimestamp returns the timestamp of an external session, as it is written.
func ExternalSessionTimestamp(session string) (string, bool) {
	parts := strings.Split(session, ":")
	if len(parts) != 2 || parts[0] == "" {
		return "", false
	}
	return parts[0], true
}
