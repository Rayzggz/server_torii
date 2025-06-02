package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func WaitingRoom(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if !ruleSet.WaitingRoomRule.Enabled {
		decision.Set(action.Continue)
		return
	}

	sessionID := reqData.ToriiSessionID
	canEnter, newSessionID, _ := sharedMem.WaitingRoom.CanEnterSite(reqData, sessionID, ruleSet.CAPTCHARule.SecretKey)

	if canEnter {
		sharedMem.WaitingRoom.UpdateLastAccess(newSessionID, reqData, ruleSet.CAPTCHARule.SecretKey)
		decision.Set(action.Continue)
		return
	}

	decision.SetResponse(action.Done, []byte("WAITING_ROOM"), []byte(newSessionID))
}
