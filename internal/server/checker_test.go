package server

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
)

// The pipeline, not each check, decides whether a check runs: one whose switch is off is never
// called, and a check without a switch always is.
func TestRunChecksHonorsFeatureControl(t *testing.T) {
	original := checkFuncs
	t.Cleanup(func() { checkFuncs = original })

	var called [feature.Count]bool
	for _, c := range feature.Pipeline() {
		checkFuncs[c] = func(request.UserRequest, *config.RuleSet, *action.Decision, *state.Runtime) {
			called[c] = true
		}
	}
	var all uint16
	for _, c := range feature.Pipeline() {
		all |= c.ControlMask()
	}
	srv := NewServer(&config.MainConfig{}, nil, nil, nil)

	for _, off := range feature.Pipeline() {
		called = [feature.Count]bool{}
		srv.runChecks(request.UserRequest{FeatureControl: all &^ off.ControlMask()}, nil)
		for _, c := range feature.Pipeline() {
			want := c != off || c.ControlMask() == 0
			if called[c] != want {
				t.Errorf("%s switched off: %s called = %v, want %v", off, c, called[c], want)
			}
		}
	}

	called = [feature.Count]bool{}
	srv.runChecks(request.UserRequest{}, nil)
	for _, c := range feature.Pipeline() {
		if want := c.ControlMask() == 0; called[c] != want {
			t.Errorf("everything switched off: %s called = %v, want %v", c, called[c], want)
		}
	}
}
