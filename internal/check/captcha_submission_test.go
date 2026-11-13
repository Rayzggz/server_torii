package check

import "testing"

// The script of the CAPTCHA page compares the response body with these strings.
func TestCaptchaSubmissionBodies(t *testing.T) {
	for outcome, want := range map[CaptchaSubmission]string{
		SubmissionRejected: "", SubmissionGood: "good", SubmissionBad: "bad",
		SubmissionBadSession: "badSession", SubmissionUnavailable: "error",
	} {
		if got := outcome.String(); got != want {
			t.Errorf("CaptchaSubmission(%d).String() = %q, want %q", outcome, got, want)
		}
	}
}
