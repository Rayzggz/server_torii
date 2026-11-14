package server

import (
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// decide runs the check pipeline and returns the decision the connector would be told.
func decide(rt *state.Runtime, req request.UserRequest, rs *config.RuleSet) string {
	decision, _ := NewServer(&config.MainConfig{}, nil, rt, nil).runChecks(req, rs)
	return decision.Verdict.String()
}

// featureBits returns the feature control bits of a site with a Torii-Features header applied.
func featureBits(rs *config.RuleSet, overrides string) uint16 {
	bits, _ := applyFeatureOverrides(configFeatureBits(rs), overrides)
	return bits
}
