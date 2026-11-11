package action

type checkState int

const (
	Continue checkState = iota
	Done
	Jump
)

// Verdict is the outcome a check assigns to a request.
type Verdict uint8

const (
	VerdictAllow     Verdict = iota // request passes
	VerdictBlock                    // request is forbidden
	VerdictCaptcha                  // request must solve a CAPTCHA
	VerdictRateLimit                // request exceeded a rate limit
	VerdictExternal                 // request is handed to external migration
	VerdictError                    // internal error while deciding
)

var verdictNames = [...]string{
	VerdictAllow:     "200",
	VerdictBlock:     "403",
	VerdictCaptcha:   "CAPTCHA",
	VerdictRateLimit: "429",
	VerdictExternal:  "EXTERNAL",
	VerdictError:     "500",
}

// String returns the wire label of the verdict, as sent in the Torii-Action header.
func (v Verdict) String() string {
	if int(v) < len(verdictNames) {
		return verdictNames[v]
	}
	return "UNKNOWN"
}

// CaptchaResult is the outcome of a CAPTCHA submission.
type CaptchaResult uint8

const (
	CaptchaNone       CaptchaResult = iota // no CAPTCHA submission was evaluated
	CaptchaGood                            // solution accepted
	CaptchaBad                             // solution missing or wrong
	CaptchaBadSession                      // challenge session invalid or mismatched
)

var captchaResultNames = [...]string{
	CaptchaNone:       "",
	CaptchaGood:       "good",
	CaptchaBad:        "bad",
	CaptchaBadSession: "badSession",
}

// String returns the response body sent to the CAPTCHA page for this result.
func (r CaptchaResult) String() string {
	if int(r) < len(captchaResultNames) {
		return captchaResultNames[r]
	}
	return "UNKNOWN"
}

// Decision saves the result of the decision
type Decision struct {
	Verdict   Verdict
	State     checkState
	Captcha   CaptchaResult
	JumpIndex int
	SkipMask  uint32 // checks to skip for the rest of the request, set by custom skip rules
}

func NewDecision() *Decision {
	return &Decision{Verdict: VerdictAllow, State: Continue, Captcha: CaptchaNone, JumpIndex: -1}
}

func (d *Decision) Set(state checkState) {
	d.State = state
}

func (d *Decision) SetVerdict(state checkState, verdict Verdict) {
	d.State = state
	d.Verdict = verdict
}

func (d *Decision) SetCaptchaResult(state checkState, verdict Verdict, result CaptchaResult) {
	d.State = state
	d.Verdict = verdict
	d.Captcha = result
}

func (d *Decision) SetJump(state checkState, verdict Verdict, jumpIndex int) {
	d.State = state
	d.Verdict = verdict
	d.JumpIndex = jumpIndex
}
