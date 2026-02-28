package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func ActionRule(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if sharedMem.ActionRuleEngine == nil {
		decision.Set(action.Continue)
		return
	}
	engine, ok := sharedMem.ActionRuleEngine.(*action.ActionRuleEngine)
	if !ok {
		decision.Set(action.Continue)
		return
	}

	act := engine.CheckRequest(reqData)

	switch act {
	case action.ActionBlock:
		decision.SetCode(action.Done, []byte("403"))
	case action.ActionCaptcha:
		reqData.FeatureControl |= dataType.FeatureCaptcha
		Captcha(reqData, ruleSet, decision, sharedMem)
	default:
		decision.Set(action.Continue)
	}
}
