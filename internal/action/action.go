package action

type checkState int

const (
	Continue checkState = iota
	Done
	Jump
)

// Decision saves the result of the decision
type Decision struct {
	HTTPCode  string
	State     checkState
	JumpIndex int
}

func NewDecision() *Decision {
	return &Decision{HTTPCode: "200", State: Continue, JumpIndex: -1}
}

func (d *Decision) Set(state checkState) {
	d.State = state
}

func (d *Decision) SetCode(state checkState, httpCode string) {
	d.State = state
	d.HTTPCode = httpCode
}

func (d *Decision) SetJump(state checkState, httpCode string, jumpIndex int) {
	d.State = state
	d.HTTPCode = httpCode
	d.JumpIndex = jumpIndex
}
