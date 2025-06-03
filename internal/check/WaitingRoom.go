package check

import (
	"fmt"
	"github.com/cespare/xxhash/v2"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strconv"
	"strings"
	"time"
)

func WaitingRoom(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if !ruleSet.WaitingRoomRule.Enabled {
		decision.Set(action.Continue)
		return
	}

	sessionID := reqData.ToriiSessionID
	userKey := generateUserKey(reqData)

	// 验证现有session ID
	var validSessionID bool
	if sessionID != "" {
		validSessionID = verifyWaitingRoomSessionID(sessionID, reqData, ruleSet.CAPTCHARule.SecretKey, ruleSet.WaitingRoomRule.SessionTimeout)
	}

	if validSessionID {
		// 检查是否可以进入
		canEnter, _ := sharedMem.WaitingRoom.CanEnterSite(sessionID, userKey)
		if canEnter {
			sharedMem.WaitingRoom.AddToActiveSession(sessionID, userKey)
			sharedMem.WaitingRoom.UpdateLastAccess(sessionID, userKey)
			decision.Set(action.Continue)
			return
		}
		// 仍在队列中，返回等待页面
		decision.SetResponse(action.Done, []byte("WAITING_ROOM"), []byte(sessionID))
		return
	}

	// 生成新的session ID
	newSessionID := genWaitingRoomSessionID(reqData, ruleSet.CAPTCHARule.SecretKey)

	// 检查是否可以直接进入或需要排队
	canEnter, _ := sharedMem.WaitingRoom.CanEnterSite("", userKey)
	if canEnter {
		sharedMem.WaitingRoom.AddToActiveSession(newSessionID, userKey)
		decision.Set(action.Continue)
		return
	}

	// 需要排队
	sharedMem.WaitingRoom.AddToQueue(newSessionID, userKey)
	decision.SetResponse(action.Done, []byte("WAITING_ROOM"), []byte(newSessionID))
}

func generateUserKey(reqData dataType.UserRequest) string {
	ua := reqData.UserAgent
	if ua == "" {
		ua = "undefined"
	}
	return fmt.Sprintf("%s:%s:%s", reqData.RemoteIP, reqData.Host, utils.GetClearanceUserAgent(ua))
}

func genWaitingRoomSessionID(reqData dataType.UserRequest, secretKey string) string {
	timeNow := time.Now().Unix()
	userKey := generateUserKey(reqData)
	data := fmt.Sprintf("%d%s%sWAITING-ROOM-SESSION", timeNow, userKey, secretKey)
	hash := xxhash.Sum64String(data)
	return fmt.Sprintf("%d:%x", timeNow, hash)
}

func verifyWaitingRoomSessionID(sessionID string, reqData dataType.UserRequest, secretKey string, timeout int64) bool {
	if sessionID == "" {
		return false
	}
	parts := strings.Split(sessionID, ":")
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

	if timeNow-parsedTimestamp > timeout {
		return false
	}

	userKey := generateUserKey(reqData)
	data := fmt.Sprintf("%d%s%sWAITING-ROOM-SESSION", parsedTimestamp, userKey, secretKey)
	computedHash := xxhash.Sum64String(data)
	expectedHashUint, err := strconv.ParseUint(expectedHash, 16, 64)
	if err != nil {
		return false
	}

	return computedHash == expectedHashUint
}
