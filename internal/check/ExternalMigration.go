package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func ExternalMigration(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if !ruleSet.ExternalMigrationRule.Enabled {
		decision.Set(action.Continue)
		return
	}

	if !verifyClearanceCookie(reqData, *ruleSet) {
		decision.SetResponse(action.Done, []byte("EXTERNAL"), genSessionID(reqData, *ruleSet))
		return
	}

	decision.Set(action.Continue)
}
