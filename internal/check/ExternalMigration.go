package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"server_torii/internal/token"
)

// ExternalMigration is the pipeline step: it hands every client without a clearance to the external provider when the feature is on.
func ExternalMigration(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if ExternalMigration feature is enabled using binary operation
	if (reqData.FeatureControl & request.FeatureExternalMigration) == 0 {
		decision.Set(action.Continue)
		return
	}
	requireExternalMigration(reqData, ruleSet, decision, rt)
}

// requireExternalMigration does so regardless of the feature switch, for a custom rule with the external action.
func requireExternalMigration(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, _ *state.Runtime) {
	if !verifyExternalMigrationClearanceCookie(reqData, *ruleSet) {
		decision.SetVerdict(action.Done, action.VerdictExternal)
		return
	}

	decision.Set(action.Continue)
}

func externalClearanceSigner(ruleSet config.RuleSet) token.Signer {
	return token.Signer{Key: ruleSet.ExternalMigrationRule.SecretKey, Label: "EXTERNAL-CLEARANCE"}
}

func externalSessionSigner(ruleSet config.RuleSet) token.Signer {
	return token.Signer{Key: ruleSet.ExternalMigrationRule.SecretKey, Label: "EXTERNAL-SESSION"}
}

// GenExternalMigrationClearance issues the cookie that lets a client back in after the external provider cleared it.
func GenExternalMigrationClearance(reqData request.UserRequest, ruleSet config.RuleSet) []byte {
	return signToken(reqData, externalClearanceSigner(ruleSet))
}

func verifyExternalMigrationClearanceCookie(reqData request.UserRequest, ruleSet config.RuleSet) bool {
	return verifyToken(reqData, externalClearanceSigner(ruleSet), reqData.ToriiClearance, ruleSet.ExternalMigrationRule.SessionTimeout)
}

// GenExternalMigrationSessionID issues the session a client carries to the external provider and back.
func GenExternalMigrationSessionID(reqData request.UserRequest, ruleSet config.RuleSet) []byte {
	return signToken(reqData, externalSessionSigner(ruleSet))
}

// VerifyExternalMigrationSessionIDCookie checks the session's signature only: its age is bounded
// by the 30-second lifetime of the migration link that must accompany it.
func VerifyExternalMigrationSessionIDCookie(reqData request.UserRequest, ruleSet config.RuleSet) bool {
	return verifyToken(reqData, externalSessionSigner(ruleSet), reqData.ToriiSessionID, 0)
}

func CalculateExternalMigrationHMAC(sessionID, timestampStr, originalURI, secretKey string) string {
	mac := hmac.New(sha512.New, []byte(secretKey))
	mac.Write(fmt.Appendf(nil, "%s%s%s", sessionID, timestampStr, originalURI))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func CalculateRedirectHMAC(domain, timestampStr, originalUri, secretKey string) string {
	mac := hmac.New(sha512.New, []byte(secretKey))
	mac.Write(fmt.Appendf(nil, "%s:%s:%s", domain, timestampStr, originalUri))
	return fmt.Sprintf("%x", mac.Sum(nil))
}
