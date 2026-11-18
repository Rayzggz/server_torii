package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"strconv"
	"strings"
)

// What is exchanged with the external provider: two signatures and the session ID. The format
// of the signatures and the form of the session ID are part of the protocol the provider
// implements and must not change.

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
// Only Torii verifies it, so it is signed with the cookie key, not with the key of the provider.
// It does not use the token format of the other cookies, because the provider reads the
// timestamp in front of the colon to verify the signature of the redirect.
//
// The signature is over the label, the timestamp, the host and the user agent, each preceded by
// its length as four big-endian bytes, so that no two different sets of fields sign alike.
func externalSession(reqData request.UserRequest, ruleSet config.RuleSet, ts int64) string {
	mac := hmac.New(sha512.New, []byte(ruleSet.Challenge.CookieKey))
	stamp := strconv.FormatInt(ts, 10)
	for _, field := range []string{"EXTERNAL-SESSION@" + ruleSet.ID, stamp, reqData.Host, GetClearanceUserAgent(reqData.UserAgent)} {
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(field))))
		mac.Write([]byte(field))
	}
	return fmt.Sprintf("%s:%x", stamp, mac.Sum(nil))
}

// verifyExternalSession checks the signature of the session. The
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
	return hmac.Equal([]byte(externalSession(reqData, ruleSet, ts)), []byte(reqData.ToriiSessionID))
}

// ExternalSessionTimestamp returns the timestamp of an external session, as it is written.
func ExternalSessionTimestamp(session string) (string, bool) {
	parts := strings.Split(session, ":")
	if len(parts) != 2 || parts[0] == "" {
		return "", false
	}
	return parts[0], true
}
