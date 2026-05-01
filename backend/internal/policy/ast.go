package policy

type Policy struct {
	Name        string
	Rules       []Rule
	Version     string
	Source      string
	SourceBytes []byte
}

type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	ActionLog   Action = "log"
)

type Rule struct {
	Action Action
	Expr   Expr
}

type Expr interface {
	isExpr()
}

type AndExpr struct {
	Left  Expr
	Right Expr
}

func (AndExpr) isExpr() {}

type OrExpr struct {
	Left  Expr
	Right Expr
}

func (OrExpr) isExpr() {}

type NotExpr struct {
	Inner Expr
}

func (NotExpr) isExpr() {}

type CompareExpr struct {
	Field string
	Op    string
	Value Value
}

func (CompareExpr) isExpr() {}

type InExpr struct {
	Field  string
	Negate bool
	Values []Value
}

func (InExpr) isExpr() {}

type Value struct {
	Str   string
	Num   int64
	IsNum bool
	IsStr bool
}
