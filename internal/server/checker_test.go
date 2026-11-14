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

// stubChecks replaces the checks with ones that record their calls; steps maps a check to what
// it does to the decision.
func stubChecks(t *testing.T, steps map[feature.Check]func(*action.Decision)) *[feature.Count]bool {
	t.Helper()
	original := checkFuncs
	t.Cleanup(func() { checkFuncs = original })
	called := new([feature.Count]bool)
	for _, c := range feature.Pipeline() {
		checkFuncs[c] = func(_ request.UserRequest, _ *config.RuleSet, decision *action.Decision, _ *state.Runtime) {
			called[c] = true
			if step := steps[c]; step != nil {
				step(decision)
			}
		}
	}
	return called
}

func requireChallenge(d *action.Decision) { d.RequireChallenge = true }

// A challenge a check asked for is answered by the Challenge check even when that check is
// switched off for the request and a custom rule skips it.
func TestRunChecksRequiredChallengeIgnoresSwitchAndSkip(t *testing.T) {
	srv := NewServer(&config.MainConfig{}, nil, nil, nil)
	on := feature.CustomRules.ControlMask()

	called := stubChecks(t, nil)
	srv.runChecks(request.UserRequest{FeatureControl: on}, nil)
	if called[feature.Challenge] {
		t.Fatal("Challenge ran although it is switched off and nothing asked for it")
	}

	called = stubChecks(t, map[feature.Check]func(*action.Decision){
		feature.CustomRules: func(d *action.Decision) {
			d.SkipMask |= feature.Challenge.SkipMask()
			d.RequireChallenge = true
		},
		feature.Challenge: func(d *action.Decision) { d.SetVerdict(action.Done, action.VerdictChallenge) },
	})
	decision, endedBy := srv.runChecks(request.UserRequest{FeatureControl: on}, nil)
	// The reason given to the connector is the check whose rule asked for the challenge.
	if !called[feature.Challenge] || decision.Verdict != action.VerdictChallenge || endedBy != feature.CustomRules {
		t.Fatalf("Challenge called = %v, decision = %+v, reason %s", called[feature.Challenge], decision, endedBy)
	}

	// A site that challenges every client names the Challenge check itself.
	stubChecks(t, map[feature.Check]func(*action.Decision){
		feature.Challenge: func(d *action.Decision) { d.SetVerdict(action.Done, action.VerdictChallenge) },
	})
	if _, endedBy := srv.runChecks(request.UserRequest{FeatureControl: feature.Challenge.ControlMask()}, nil); endedBy != feature.Challenge {
		t.Fatalf("reason = %s, want Challenge", endedBy)
	}
}

// Between the check that asks for a challenge and the Challenge check, any check can still end
// the pipeline: a stricter answer wins, and so does a pass such as a verified crawler's.
func TestRunChecksLaterCheckWinsOverRequiredChallenge(t *testing.T) {
	srv := NewServer(&config.MainConfig{}, nil, nil, nil)
	on := feature.CustomRules.ControlMask() | feature.VerifyBot.ControlMask() | feature.HTTPFlood.ControlMask()
	for name, tt := range map[string]struct {
		by      feature.Check
		verdict action.Verdict
	}{
		"verified crawler passes": {feature.VerifyBot, action.VerdictAllow},
		"temporary rule blocks":   {feature.ActionRule, action.VerdictBlock},
		"flood is rate limited":   {feature.HTTPFlood, action.VerdictRateLimit},
	} {
		t.Run(name, func(t *testing.T) {
			called := stubChecks(t, map[feature.Check]func(*action.Decision){
				feature.CustomRules: requireChallenge,
				tt.by:               func(d *action.Decision) { d.SetVerdict(action.Done, tt.verdict) },
			})
			decision, endedBy := srv.runChecks(request.UserRequest{FeatureControl: on}, nil)
			if called[feature.Challenge] || decision.Verdict != tt.verdict || endedBy != tt.by {
				t.Fatalf("Challenge called = %v, decision = %+v, ended by %s", called[feature.Challenge], decision, endedBy)
			}
		})
	}
}
