package policy

import "testing"

func TestLexerEscapes(t *testing.T) {
	cases := map[string]string{
		`"\""`: `"`,
		`"\\"`: `\`,
		`"\n"`: "\n",
		`"\t"`: "\t",
	}
	for in, want := range cases {
		l := newLexer(in)
		tok, err := l.next()
		if err != nil {
			t.Errorf("lex(%q): err %v", in, err)
			continue
		}
		if tok.Value != want {
			t.Errorf("lex(%q) = %q, want %q", in, tok.Value, want)
		}
	}
}

func TestLexerUnterminatedString(t *testing.T) {
	l := newLexer(`"unterminated`)
	if _, err := l.next(); err == nil {
		t.Errorf("expected error")
	}
}

func TestLexerUnknownEscape(t *testing.T) {
	l := newLexer(`"\x"`)
	if _, err := l.next(); err == nil {
		t.Errorf("expected error")
	}
}

func TestLexerTrailingBackslash(t *testing.T) {
	l := newLexer(`"\`)
	if _, err := l.next(); err == nil {
		t.Errorf("expected error")
	}
}

func TestLexerComments(t *testing.T) {
	l := newLexer("# comment\nallow")
	tok, err := l.next()
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "allow" {
		t.Errorf("got %q", tok.Value)
	}
}

func TestLexerSlashComments(t *testing.T) {
	l := newLexer("// comment\nallow")
	tok, err := l.next()
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "allow" {
		t.Errorf("got %q", tok.Value)
	}
}

func TestLexerNumbers(t *testing.T) {
	l := newLexer("123")
	tok, err := l.next()
	if err != nil {
		t.Fatal(err)
	}
	if tok.Kind != tkNumber || tok.Value != "123" {
		t.Errorf("got %+v", tok)
	}
}

func TestLexerCompareOps(t *testing.T) {
	l := newLexer("== != <= >=")
	want := []string{"==", "!=", "<=", ">="}
	for _, w := range want {
		tok, err := l.next()
		if err != nil {
			t.Fatal(err)
		}
		if tok.Value != w {
			t.Errorf("got %q want %q", tok.Value, w)
		}
	}
}

func TestLexerSinglePunct(t *testing.T) {
	l := newLexer("{}[],()=<>!")
	for i := 0; i < 11; i++ {
		_, err := l.next()
		if err != nil {
			t.Errorf("err: %v", err)
		}
	}
}

func TestLexerUnexpectedChar(t *testing.T) {
	l := newLexer("@")
	if _, err := l.next(); err == nil {
		t.Errorf("expected error")
	}
}

func TestLexerEOF(t *testing.T) {
	l := newLexer("")
	tok, err := l.next()
	if err != nil {
		t.Fatal(err)
	}
	if tok.Kind != tkEOF {
		t.Errorf("got %+v", tok)
	}
}
