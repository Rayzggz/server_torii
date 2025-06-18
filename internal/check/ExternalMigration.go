package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strconv"
	"strings"
	"time"
)

func ExternalMigration(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if !ruleSet.ExternalMigrationRule.Enabled {
		decision.Set(action.Continue)
		return
	}

	if !verifyExternalMigrationClearanceCookie(reqData, *ruleSet) {
		decision.SetResponse(action.Done, []byte("EXTERNAL"), genExternalMigrationSessionID(reqData, *ruleSet))
		return
	}

	decision.Set(action.Continue)
}

func GenExternalMigrationClearance(reqData dataType.UserRequest, ruleSet config.RuleSet) []byte {
	timeNow := time.Now().Unix()
	mac := hmac.New(sha512.New, []byte(ruleSet.ExternalMigrationRule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sEXTERNAL-CLEARANCE", timeNow, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	return []byte(fmt.Sprintf("%s:%s", fmt.Sprintf("%d", time.Now().Unix()), fmt.Sprintf("%x", mac.Sum(nil))))
}

func verifyExternalMigrationClearanceCookie(reqData dataType.UserRequest, ruleSet config.RuleSet) bool {
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

	if timeNow-parsedTimestamp > ruleSet.ExternalMigrationRule.SessionTimeout {
		return false
	}

	mac := hmac.New(sha512.New, []byte(ruleSet.ExternalMigrationRule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sEXTERNAL-CLEARANCE", parsedTimestamp, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	computedHash := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(computedHash), []byte(expectedHash))

}

func genExternalMigrationSessionID(reqData dataType.UserRequest, ruleSet config.RuleSet) []byte {
	timeNow := time.Now().Unix()
	mac := hmac.New(sha512.New, []byte(ruleSet.ExternalMigrationRule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sEXTERNAL-SESSION", timeNow, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	return []byte(fmt.Sprintf("%s:%s", fmt.Sprintf("%d", time.Now().Unix()), fmt.Sprintf("%x", mac.Sum(nil))))
}

func VerifyExternalMigrationSessionIDCookie(reqData dataType.UserRequest, ruleSet config.RuleSet) bool {
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
		utils.LogError(reqData, "", fmt.Sprintf("Error parsing timestamp: %v", err))
		return false
	}

	mac := hmac.New(sha512.New, []byte(ruleSet.ExternalMigrationRule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sEXTERNAL-SESSION", parsedTimestamp, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	computedHash := fmt.Sprintf("%x", mac.Sum(nil))

	return hmac.Equal([]byte(computedHash), []byte(expectedHash))

}

func CalculateExternalMigrationHMAC(sessionID, timestampStr, secretKey string) string {
	mac := hmac.New(sha512.New, []byte(secretKey))
	mac.Write([]byte(fmt.Sprintf("%s%s", sessionID, timestampStr)))
	return fmt.Sprintf("%x", mac.Sum(nil))
}
