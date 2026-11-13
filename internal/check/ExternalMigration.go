package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"strconv"
	"strings"
	"time"
)

func ExternalMigration(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if ExternalMigration feature is enabled using binary operation
	if (reqData.FeatureControl & request.FeatureExternalMigration) == 0 {
		decision.Set(action.Continue)
		return
	}

	if !verifyExternalMigrationClearanceCookie(reqData, *ruleSet) {
		decision.SetVerdict(action.Done, action.VerdictExternal)
		return
	}

	decision.Set(action.Continue)
}

func GenExternalMigrationClearance(reqData request.UserRequest, ruleSet config.RuleSet) []byte {
	timeNow := time.Now().Unix()
	mac := hmac.New(sha512.New, []byte(ruleSet.ExternalMigrationRule.SecretKey))
	mac.Write(fmt.Appendf(nil, "%d%s%sEXTERNAL-CLEARANCE", timeNow, reqData.Host, GetClearanceUserAgent(reqData.UserAgent)))
	return []byte(fmt.Sprintf("%s:%s", fmt.Sprintf("%d", timeNow), fmt.Sprintf("%x", mac.Sum(nil))))
}

func verifyExternalMigrationClearanceCookie(reqData request.UserRequest, ruleSet config.RuleSet) bool {
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
		logx.LogError(reqData, "", fmt.Sprintf("Error parsing timestamp: %v", err))
		return false
	}

	if timeNow-parsedTimestamp > ruleSet.ExternalMigrationRule.SessionTimeout {
		return false
	}

	mac := hmac.New(sha512.New, []byte(ruleSet.ExternalMigrationRule.SecretKey))
	mac.Write(fmt.Appendf(nil, "%d%s%sEXTERNAL-CLEARANCE", parsedTimestamp, reqData.Host, GetClearanceUserAgent(reqData.UserAgent)))
	computedHash := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(computedHash), []byte(expectedHash))

}

func GenExternalMigrationSessionID(reqData request.UserRequest, ruleSet config.RuleSet) []byte {
	timeNow := time.Now().Unix()
	mac := hmac.New(sha512.New, []byte(ruleSet.ExternalMigrationRule.SecretKey))
	mac.Write(fmt.Appendf(nil, "%d%s%sEXTERNAL-SESSION", timeNow, reqData.Host, GetClearanceUserAgent(reqData.UserAgent)))
	return []byte(fmt.Sprintf("%s:%s", fmt.Sprintf("%d", timeNow), fmt.Sprintf("%x", mac.Sum(nil))))
}

func VerifyExternalMigrationSessionIDCookie(reqData request.UserRequest, ruleSet config.RuleSet) bool {
	if reqData.ToriiSessionID == "" {
		return false
	}
	parts := strings.Split(reqData.ToriiSessionID, ":")
	if len(parts) != 2 {
		return false
	}
	timestamp := parts[0]
	expectedHash := parts[1]

	parsedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		logx.LogError(reqData, "", fmt.Sprintf("Error parsing timestamp: %v", err))
		return false
	}

	mac := hmac.New(sha512.New, []byte(ruleSet.ExternalMigrationRule.SecretKey))
	mac.Write(fmt.Appendf(nil, "%d%s%sEXTERNAL-SESSION", parsedTimestamp, reqData.Host, GetClearanceUserAgent(reqData.UserAgent)))
	computedHash := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(computedHash), []byte(expectedHash))

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
