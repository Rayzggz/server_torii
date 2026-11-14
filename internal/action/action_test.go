package action

import "testing"

func TestDecisionTransitions(t *testing.T) {
	d := NewDecision()
	if d.State != Continue || d.Verdict != VerdictAllow {
		t.Fatalf("unexpected default: %+v", d)
	}
	d.Set(Done)
	if d.State != Done || d.Verdict != VerdictAllow {
		t.Fatalf("Set: %+v", d)
	}
	d.SetVerdict(Done, VerdictBlock)
	if d.State != Done || d.Verdict != VerdictBlock {
		t.Fatalf("SetVerdict: %+v", d)
	}
	other := NewDecision()
	if other.State != Continue || other.Verdict != VerdictAllow {
		t.Fatalf("decisions share state: %+v", other)
	}
}

func TestVerdictString(t *testing.T) {
	for v, want := range map[Verdict]string{
		VerdictAllow: "pass", VerdictBlock: "block", VerdictCaptcha: "captcha",
		VerdictRateLimit: "rate_limit", VerdictExternal: "external", Verdict(255): "UNKNOWN",
	} {
		if got := v.String(); got != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", v, got, want)
		}
	}
}
