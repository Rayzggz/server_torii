package action

type checkState int

const (
	Continue checkState = iota
	Done
	Jump
)

// Decision saves the result of the decision
type Decision struct {
	HTTPCode     []byte
	State        checkState
	ResponseData []byte
	JumpIndex    int
}

func NewDecision() *Decision {
	return &Decision{HTTPCode: []byte("200"), State: Continue, ResponseData: nil, JumpIndex: -1}
}

func (d *Decision) Set(state checkState) {
	d.State = state
}

func (d *Decision) SetCode(state checkState, httpCode []byte) {
	d.State = state
	d.HTTPCode = httpCode
}

func (d *Decision) SetResponse(state checkState, httpCode []byte, responseData []byte) {
	d.State = state
	d.HTTPCode = httpCode
	d.ResponseData = responseData
}

func (d *Decision) SetJump(state checkState, httpCode []byte, jumpIndex int) {
	d.State = state
	d.HTTPCode = httpCode
	d.JumpIndex = jumpIndex
}
