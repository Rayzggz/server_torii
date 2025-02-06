package action

type Action int

const (
	Undecided Action = iota // 0：Undecided
	Allow                   // 1：Pass
	Block                   // 2：Deny
)

// Decision saves the result of the decision
type Decision struct {
	result Action
}

func NewDecision() *Decision {
	return &Decision{result: Undecided}
}

func (d *Decision) Get() Action {
	return d.result
}

func (d *Decision) Set(new Action) {
	d.result = new
}
