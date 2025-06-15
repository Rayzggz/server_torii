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

	if !VerifyWaitingRoomClearance(reqData, *ruleSet) {
		decision.SetResponse(action.Done, []byte("WAITING-ROOM"), genSessionID(reqData, *ruleSet))
		return

	}

	decision.Set(action.Continue)
}
