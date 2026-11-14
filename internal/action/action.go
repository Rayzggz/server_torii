package action

type checkState int

const (
	Continue checkState = iota
	Done
)

// Verdict is the outcome a check assigns to a request.
type Verdict uint8

const (
	VerdictAllow     Verdict = iota // request passes
	VerdictBlock                    // request is forbidden
	VerdictCaptcha                  // request must solve a CAPTCHA
	VerdictRateLimit                // request exceeded a rate limit
	VerdictExternal                 // request is handed to external migration
)

var verdictNames = [...]string{
	VerdictAllow:     "pass",
	VerdictBlock:     "block",
	VerdictCaptcha:   "captcha",
	VerdictRateLimit: "rate_limit",
	VerdictExternal:  "external",
}

// String returns the wire label of the verdict, as sent in the Torii-Decision header.
func (v Verdict) String() string {
	if int(v) < len(verdictNames) {
		return verdictNames[v]
	}
	return "UNKNOWN"
}

// Decision is what the check pipeline has concluded about a request so far.
type Decision struct {
	Verdict  Verdict
	State    checkState
	SkipMask uint32 // checks to skip for the rest of the request, set by custom skip rules
}

func NewDecision() *Decision {
	return &Decision{Verdict: VerdictAllow, State: Continue}
}

func (d *Decision) Set(state checkState) {
	d.State = state
}

func (d *Decision) SetVerdict(state checkState, verdict Verdict) {
	d.State = state
	d.Verdict = verdict
}
