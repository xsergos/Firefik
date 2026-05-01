package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

func Parse(src string) ([]*Policy, error) {
	lex := newLexer(src)
	var toks []token
	for {
		t, err := lex.next()
		if err != nil {
			return nil, err
		}
		toks = append(toks, t)
		if t.Kind == tkEOF {
			break
		}
	}
	p := &parser{toks: toks, srcBytes: []byte(src)}
	return p.parseAll()
}

type parser struct {
	toks     []token
	pos      int
	srcBytes []byte
}

func (p *parser) peek() token {
	if p.pos >= len(p.toks) {
		return token{Kind: tkEOF}
	}
	return p.toks[p.pos]
}

func (p *parser) advance() token {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) expect(kind tokenKind, value string) (token, error) {
	t := p.peek()
	if t.Kind != kind || (value != "" && t.Value != value) {
		return token{}, fmt.Errorf("line %d col %d: expected %q, got %q", t.Line, t.Col, value, t.Value)
	}
	p.advance()
	return t, nil
}

func (p *parser) parseAll() ([]*Policy, error) {
	var out []*Policy
	for p.peek().Kind != tkEOF {
		pol, err := p.parsePolicy()
		if err != nil {
			return nil, err
		}
		out = append(out, pol)
	}
	return out, nil
}

func (p *parser) parsePolicy() (*Policy, error) {
	if _, err := p.expect(tkKeyword, "policy"); err != nil {
		return nil, err
	}
	name, err := p.expect(tkString, "")
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkPunct, "{"); err != nil {
		return nil, err
	}

	pol := &Policy{Name: name.Value}
	for p.peek().Kind != tkEOF {
		t := p.peek()
		if t.Kind == tkPunct && t.Value == "}" {
			p.advance()
			break
		}
		rule, err := p.parseRule()
		if err != nil {
			return nil, err
		}
		pol.Rules = append(pol.Rules, rule)
	}
	pol.Version = versionOf(name.Value, pol.Rules)
	pol.SourceBytes = p.srcBytes
	return pol, nil
}

func (p *parser) parseRule() (Rule, error) {
	t := p.advance()
	if t.Kind != tkKeyword {
		return Rule{}, fmt.Errorf("line %d: expected rule keyword (allow/block/log), got %q", t.Line, t.Value)
	}
	var action Action
	switch t.Value {
	case "allow":
		action = ActionAllow
	case "block":
		action = ActionBlock
	case "log":
		action = ActionLog
	default:
		return Rule{}, fmt.Errorf("line %d: unknown rule keyword %q", t.Line, t.Value)
	}
	if _, err := p.expect(tkKeyword, "if"); err != nil {
		return Rule{}, err
	}
	expr, err := p.parseExprOr()
	if err != nil {
		return Rule{}, err
	}
	return Rule{Action: action, Expr: expr}, nil
}

func (p *parser) parseExprOr() (Expr, error) {
	left, err := p.parseExprAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().Kind == tkKeyword && p.peek().Value == "or" {
		p.advance()
		right, err := p.parseExprAnd()
		if err != nil {
			return nil, err
		}
		left = OrExpr{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseExprAnd() (Expr, error) {
	left, err := p.parseExprUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().Kind == tkKeyword && p.peek().Value == "and" {
		p.advance()
		right, err := p.parseExprUnary()
		if err != nil {
			return nil, err
		}
		left = AndExpr{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseExprUnary() (Expr, error) {
	if p.peek().Kind == tkKeyword && p.peek().Value == "not" {
		p.advance()
		inner, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		return NotExpr{Inner: inner}, nil
	}
	return p.parseAtom()
}

func (p *parser) parseAtom() (Expr, error) {
	t := p.peek()
	if t.Kind == tkPunct && t.Value == "(" {
		p.advance()
		inner, err := p.parseExprOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkPunct, ")"); err != nil {
			return nil, err
		}
		return inner, nil
	}
	if t.Kind != tkIdent {
		return nil, fmt.Errorf("line %d col %d: expected field identifier, got %q", t.Line, t.Col, t.Value)
	}
	field := p.advance().Value

	if p.peek().Kind == tkKeyword && p.peek().Value == "in" {
		p.advance()
		values, err := p.parseValueList()
		if err != nil {
			return nil, err
		}
		return InExpr{Field: field, Values: values}, nil
	}
	if p.peek().Kind == tkKeyword && p.peek().Value == "not" {
		save := p.pos
		p.advance()
		if p.peek().Kind == tkKeyword && p.peek().Value == "in" {
			p.advance()
			values, err := p.parseValueList()
			if err != nil {
				return nil, err
			}
			return InExpr{Field: field, Negate: true, Values: values}, nil
		}
		p.pos = save
	}

	opTok := p.advance()
	if opTok.Kind != tkPunct {
		return nil, fmt.Errorf("line %d: expected comparison op, got %q", opTok.Line, opTok.Value)
	}
	switch opTok.Value {
	case "==", "!=", "<", ">", "<=", ">=":
	default:
		return nil, fmt.Errorf("line %d: unknown comparison op %q", opTok.Line, opTok.Value)
	}
	val, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	return CompareExpr{Field: field, Op: opTok.Value, Value: val}, nil
}

func (p *parser) parseValueList() ([]Value, error) {
	if _, err := p.expect(tkPunct, "["); err != nil {
		return nil, err
	}
	var out []Value
	for {
		if p.peek().Kind == tkPunct && p.peek().Value == "]" {
			p.advance()
			return out, nil
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if p.peek().Kind == tkPunct && p.peek().Value == "," {
			p.advance()
			continue
		}
		if _, err := p.expect(tkPunct, "]"); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func (p *parser) parseValue() (Value, error) {
	t := p.advance()
	switch t.Kind {
	case tkString:
		return Value{IsStr: true, Str: t.Value}, nil
	case tkNumber:
		n, err := strconv.ParseInt(t.Value, 10, 64)
		if err != nil {
			return Value{}, fmt.Errorf("line %d: bad number %q", t.Line, t.Value)
		}
		return Value{IsNum: true, Num: n}, nil
	}
	return Value{}, fmt.Errorf("line %d: expected literal value, got %q", t.Line, t.Value)
}

func versionOf(name string, rules []Rule) string {
	b := fmt.Sprintf("name=%s\nrules=%d", name, len(rules))
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])[:16]
}
