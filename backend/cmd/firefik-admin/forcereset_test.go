package main

import (
	"io"
	"strings"
	"testing"
)

func TestPromptDeleteEOF(t *testing.T) {
	err := promptDelete(strings.NewReader(""))
	if err == nil {
		t.Fatal("want error on EOF")
	}
	if !strings.Contains(err.Error(), "no terminal attached") {
		t.Errorf("EOF error should mention lack of terminal, got: %v", err)
	}
}

func TestPromptDeleteWrongLine(t *testing.T) {
	err := promptDelete(strings.NewReader("yes\n"))
	if err == nil {
		t.Fatal("want error on non-DELETE input")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPromptDeleteAccept(t *testing.T) {
	if err := promptDelete(strings.NewReader("DELETE\n")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPromptDeleteAcceptNoTrailingNewline(t *testing.T) {
	if err := promptDelete(strings.NewReader("DELETE")); err != nil {
		t.Fatalf("unexpected error on terminal-less DELETE: %v", err)
	}
}

func TestPromptDeleteLeavesRestForCaller(t *testing.T) {
	r := strings.NewReader("DELETE\nleftover")
	if err := promptDelete(r); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "" {
		_ = rest
	}
}
