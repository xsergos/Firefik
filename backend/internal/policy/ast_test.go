package policy

import "testing"

func TestExprMarkers(t *testing.T) {
	AndExpr{}.isExpr()
	OrExpr{}.isExpr()
	NotExpr{}.isExpr()
	CompareExpr{}.isExpr()
	InExpr{}.isExpr()

	var exprs []Expr = []Expr{
		AndExpr{},
		OrExpr{},
		NotExpr{},
		CompareExpr{},
		InExpr{},
	}
	for _, e := range exprs {
		e.isExpr()
	}
}
