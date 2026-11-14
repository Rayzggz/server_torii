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
	VerdictChallenge                // client must prove itself: a CAPTCHA, or a visit to the external provider
	VerdictRateLimit                // request exceeded a rate limit
)

var verdictNames = [...]string{
	VerdictAllow:     "pass",
	VerdictBlock:     "block",
	VerdictChallenge: "challenge",
	VerdictRateLimit: "rate_limit",
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
	// RequireChallenge is set by a check whose rule asks for the client to be challenged. The
	// checks that follow still run and may end the pipeline with something stricter; if none
	// does, the Challenge check runs whatever its switch and the skip mask say.
	RequireChallenge bool
	// Detail names what, within the check that is running, decided: a list, a custom rule. The
	// pipeline adds it to the name of the check to form Reason.
	Detail string
	// Reason is the check behind the decision, with its Detail: "Lists:office", "HTTPFlood". The
	// pipeline sets it when it ends.
	Reason string
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
