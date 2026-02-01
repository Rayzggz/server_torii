package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func ActionRule(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if sharedMem.ActionRuleEngine == nil {
		return
	}
	engine, ok := sharedMem.ActionRuleEngine.(*action.ActionRuleEngine)
	if !ok {
		return
	}

	act := engine.CheckRequest(reqData)

	switch act {
	case action.ActionBlock:
		decision.SetCode(action.Done, []byte("403"))
	case action.ActionCaptcha:
		reqData.FeatureControl |= dataType.FeatureCaptcha
		Captcha(reqData, ruleSet, decision, sharedMem)
	}
}
