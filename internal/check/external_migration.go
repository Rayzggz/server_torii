package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
)

// The two signatures exchanged with the external provider. Their format is part of the protocol
// the provider implements and must not change.

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
