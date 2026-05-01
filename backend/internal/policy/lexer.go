package policy

import (
	"fmt"
	"strings"
	"unicode"
)

type tokenKind int

const (
	tkEOF tokenKind = iota
	tkIdent
	tkString
	tkNumber
	tkPunct
	tkKeyword
)

type token struct {
	Kind  tokenKind
	Value string
	Line  int
	Col   int
}

var keywords = map[string]bool{
	"policy": true,
	"allow":  true,
	"block":  true,
	"log":    true,
	"if":     true,
	"and":    true,
	"or":     true,
	"not":    true,
	"in":     true,
}

type lexer struct {
	src  []rune
	pos  int
	line int
	col  int
}

func newLexer(s string) *lexer {
	return &lexer{src: []rune(s), line: 1, col: 1}
}

func (l *lexer) peek() rune {
	if l.pos >= len(l.src) {
		return 0
	}
	return l.src[l.pos]
}

func (l *lexer) advance() rune {
	if l.pos >= len(l.src) {
		return 0
	}
	r := l.src[l.pos]
	l.pos++
	if r == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return r
}

func (l *lexer) skipWhitespaceAndComments() {
	for l.pos < len(l.src) {
		r := l.peek()
		if unicode.IsSpace(r) {
			l.advance()
			continue
		}
		if r == '#' {
			for l.pos < len(l.src) && l.peek() != '\n' {
				l.advance()
			}
			continue
		}
		if r == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
			for l.pos < len(l.src) && l.peek() != '\n' {
				l.advance()
			}
			continue
		}
		break
	}
}

func (l *lexer) next() (token, error) {
	l.skipWhitespaceAndComments()
	if l.pos >= len(l.src) {
		return token{Kind: tkEOF, Line: l.line, Col: l.col}, nil
	}
	startLine, startCol := l.line, l.col
	r := l.peek()
	switch {
	case r == '"':
		return l.lexString(startLine, startCol)
	case unicode.IsLetter(r) || r == '_':
		return l.lexIdent(startLine, startCol)
	case unicode.IsDigit(r):
		return l.lexNumber(startLine, startCol)
	case isPunctStart(r):
		return l.lexPunct(startLine, startCol)
	}
	return token{}, fmt.Errorf("line %d col %d: unexpected character %q", startLine, startCol, r)
}

func (l *lexer) lexString(line, col int) (token, error) {
	l.advance()
	var b strings.Builder
	for l.pos < len(l.src) {
		r := l.advance()
		if r == '"' {
			return token{Kind: tkString, Value: b.String(), Line: line, Col: col}, nil
		}
		if r == '\\' {
			if l.pos >= len(l.src) {
				return token{}, fmt.Errorf("line %d col %d: trailing backslash", line, col)
			}
			next := l.advance()
			switch next {
			case '"', '\\':
				b.WriteRune(next)
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				return token{}, fmt.Errorf("line %d: unknown escape \\%c", line, next)
			}
			continue
		}
		b.WriteRune(r)
	}
	return token{}, fmt.Errorf("line %d col %d: unterminated string", line, col)
}

func (l *lexer) lexIdent(line, col int) (token, error) {
	var b strings.Builder
	for l.pos < len(l.src) {
		r := l.peek()
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(l.advance())
			continue
		}
		break
	}
	val := b.String()
	if keywords[val] {
		return token{Kind: tkKeyword, Value: val, Line: line, Col: col}, nil
	}
	return token{Kind: tkIdent, Value: val, Line: line, Col: col}, nil
}

func (l *lexer) lexNumber(line, col int) (token, error) {
	var b strings.Builder
	for l.pos < len(l.src) {
		r := l.peek()
		if unicode.IsDigit(r) {
			b.WriteRune(l.advance())
			continue
		}
		break
	}
	return token{Kind: tkNumber, Value: b.String(), Line: line, Col: col}, nil
}

func isPunctStart(r rune) bool {
	switch r {
	case '{', '}', '[', ']', '(', ')', ',', '=', '!', '<', '>':
		return true
	}
	return false
}

func (l *lexer) lexPunct(line, col int) (token, error) {
	r := l.advance()

	if l.pos < len(l.src) {
		r2 := l.peek()
		two := string([]rune{r, r2})
		switch two {
		case "==", "!=", "<=", ">=":
			l.advance()
			return token{Kind: tkPunct, Value: two, Line: line, Col: col}, nil
		}
	}
	return token{Kind: tkPunct, Value: string(r), Line: line, Col: col}, nil
}
