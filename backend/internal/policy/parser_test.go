package policy

import (
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	src := `
policy "web-public" {
  allow if proto == "tcp" and port in [80, 443]
  block if geo in ["RU", "CN", "KP"]
  log   if port in [22, 3389]
}
`
	pols, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pols) != 1 || pols[0].Name != "web-public" {
		t.Fatalf("unexpected: %+v", pols)
	}
	p := pols[0]
	if len(p.Rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(p.Rules))
	}
	if p.Rules[0].Action != ActionAllow {
		t.Errorf("want allow, got %q", p.Rules[0].Action)
	}
	if p.Rules[2].Action != ActionLog {
		t.Errorf("want log, got %q", p.Rules[2].Action)
	}
}

func TestParseNotIn(t *testing.T) {
	src := `policy "ok" { allow if geo not in ["RU", "CN"] }`
	pols, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rule := pols[0].Rules[0]
	in, ok := rule.Expr.(InExpr)
	if !ok {
		t.Fatalf("want InExpr, got %T", rule.Expr)
	}
	if !in.Negate {
		t.Errorf("expected negate=true")
	}
}

func TestParseParens(t *testing.T) {
	src := `policy "p" { allow if (port == 80 or port == 443) and proto == "tcp" }`
	pols, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	top, ok := pols[0].Rules[0].Expr.(AndExpr)
	if !ok {
		t.Fatalf("top not AND: %T", pols[0].Rules[0].Expr)
	}
	if _, ok := top.Left.(OrExpr); !ok {
		t.Errorf("left should be OR: %T", top.Left)
	}
}

func TestParseError(t *testing.T) {
	src := `policy "broken" { allow if port == "string" }`

	pols, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := Compile(pols[0]); err == nil {
		t.Errorf("compile should reject port==string")
	}
}

func TestCompileAllowRule(t *testing.T) {
	src := `
policy "web" {
  allow if proto == "tcp" and port in [80, 443]
}
`
	pols, _ := Parse(src)
	c, err := Compile(pols[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(c.RuleSets) != 1 {
		t.Fatalf("want 1 rule-set, got %d", len(c.RuleSets))
	}
	rs := c.RuleSets[0]
	if rs.Protocol != "tcp" {
		t.Errorf("proto = %q", rs.Protocol)
	}
	if len(rs.Ports) != 2 {
		t.Errorf("ports = %v", rs.Ports)
	}
	if !strings.HasPrefix(rs.Name, "pol:web@") {
		t.Errorf("name = %q", rs.Name)
	}
}

func TestCompileBlockGeo(t *testing.T) {
	src := `policy "p" { block if geo in ["RU", "CN"] }`
	pols, _ := Parse(src)
	c, err := Compile(pols[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(c.RuleSets) != 1 {
		t.Fatalf("want 1 rule-set, got %d", len(c.RuleSets))
	}
	rs := c.RuleSets[0]
	if len(rs.GeoBlock) != 2 {
		t.Errorf("geoblock = %v", rs.GeoBlock)
	}
}

func TestCompileOrSplitsRuleSets(t *testing.T) {
	src := `policy "p" { allow if port == 80 or port == 443 }`
	pols, _ := Parse(src)
	c, err := Compile(pols[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(c.RuleSets) != 2 {
		t.Errorf("want 2 rule-sets (OR splits), got %d", len(c.RuleSets))
	}
}

func TestParseNotPrefix(t *testing.T) {
	src := `policy "p" { allow if not (port == 22) }`
	pols, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := pols[0].Rules[0].Expr.(NotExpr); !ok {
		t.Errorf("expected NotExpr, got %T", pols[0].Rules[0].Expr)
	}
}

func TestParseEmptyValueList(t *testing.T) {
	src := `policy "p" { allow if port in [] }`
	pols, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	in, ok := pols[0].Rules[0].Expr.(InExpr)
	if !ok || len(in.Values) != 0 {
		t.Errorf("expected empty InExpr, got %+v", pols[0].Rules[0].Expr)
	}
}

func TestParseAllOps(t *testing.T) {
	src := `policy "p" {
  allow if port == 80
  allow if port != 22
  allow if port < 1000
  allow if port > 1023
  allow if port <= 1024
  allow if port >= 100
}`
	pols, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pols[0].Rules) != 6 {
		t.Errorf("got %d rules", len(pols[0].Rules))
	}
}

func TestParseInvalidOp(t *testing.T) {
	src := `policy "p" { allow if port % 80 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected parse error")
	}
}

func TestParseMissingValue(t *testing.T) {
	src := `policy "p" { allow if port == }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseUnknownAction(t *testing.T) {
	src := `policy "p" { panic if port == 80 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseMissingClose(t *testing.T) {
	src := `policy "p" { allow if port == 80 `
	_, _ = Parse(src)
}

func TestParseBadNumber(t *testing.T) {
	src := `policy "p" { allow if port == 99999999999999999999 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected number parse error")
	}
}

func TestParseValueListMissingClose(t *testing.T) {
	src := `policy "p" { allow if port in [80, 443 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseExpectedFieldIdentifier(t *testing.T) {
	src := `policy "p" { allow if 80 == 80 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseMissingPolicyKeyword(t *testing.T) {
	src := `not_policy "p" { allow if port == 80 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseMissingPolicyName(t *testing.T) {
	src := `policy { allow if port == 80 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseMissingOpenBrace(t *testing.T) {
	src := `policy "p" allow if port == 80 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseMissingIfKeyword(t *testing.T) {
	src := `policy "p" { allow port == 80 }`
	if _, err := Parse(src); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseEmpty(t *testing.T) {
	pols, err := Parse(``)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(pols) != 0 {
		t.Errorf("expected empty, got %+v", pols)
	}
}

func TestParseMultiplePolicies(t *testing.T) {
	src := `policy "p1" { allow if port == 80 }
	policy "p2" { allow if port == 443 }`
	pols, err := Parse(src)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(pols) != 2 {
		t.Errorf("got %d", len(pols))
	}
}
