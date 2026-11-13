package action

import "testing"

func TestDecisionTransitions(t *testing.T) {
	d := NewDecision()
	if d.State != Continue || d.Verdict != VerdictAllow || d.Captcha != CaptchaNone {
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
	d.SetCaptchaResult(Done, VerdictAllow, CaptchaGood)
	if d.State != Done || d.Verdict != VerdictAllow || d.Captcha != CaptchaGood {
		t.Fatalf("SetCaptchaResult: %+v", d)
	}
	other := NewDecision()
	if other.State != Continue || other.Captcha != CaptchaNone {
		t.Fatalf("decisions share state: %+v", other)
	}
}

func TestVerdictString(t *testing.T) {
	for v, want := range map[Verdict]string{
		VerdictAllow: "200", VerdictBlock: "403", VerdictCaptcha: "CAPTCHA",
		VerdictRateLimit: "429", VerdictExternal: "EXTERNAL", VerdictError: "500", Verdict(255): "UNKNOWN",
	} {
		if got := v.String(); got != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", v, got, want)
		}
	}
	for r, want := range map[CaptchaResult]string{
		CaptchaNone: "", CaptchaGood: "good", CaptchaBad: "bad", CaptchaBadSession: "badSession", CaptchaResult(255): "UNKNOWN",
	} {
		if got := r.String(); got != want {
			t.Errorf("CaptchaResult(%d).String() = %q, want %q", r, got, want)
		}
	}
}
