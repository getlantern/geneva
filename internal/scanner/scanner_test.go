package scanner_test

import (
	"testing"

	"github.com/getlantern/geneva/internal/scanner"
)

func TestLexer(t *testing.T) {
	source := "abcde"
	l := scanner.NewScanner(source)
	if l == nil {
		t.Fatal("nil scanner")
	}

	r, err := l.Peek()
	if err != nil {
		t.Fatalf("Peek() returned error: %v", err)
	}
	if r != 'a' {
		t.Fatalf("Peek(): expected %c, got %c", source[0], r)
	}

	r, err = l.Pop()
	if err != nil {
		t.Fatalf("Pop() returned error: %v", err)
	}
	if r != 'a' {
		t.Fatalf("Pop(): expected %c, got %c", source[0], r)
	}

	str, err := l.Expect("bcd")
	if err != nil {
		t.Fatalf("Expect returned error: %v", err)
	}
	if str != "bcd" {
		t.Fatalf("Expect(): expected %s, got %s", "bcd", str)
	}

	rSource := []rune(source)

	last, err := l.Peek()
	if err != nil {
		t.Fatalf("Peek() of last char returned error: %v", err)
	}
	if last != rSource[len(rSource)-1] {
		t.Fatalf("Peek() of last char: expected %c, got %c", rSource[len(rSource)-1], last)
	}

	last, err = l.Pop()
	if err != nil {
		t.Fatalf("Pop() of last char returned error: %v", err)
	}
	if last != rSource[len(rSource)-1] {
		t.Fatalf("Pop() of last char: expected %c, got %c", rSource[len(rSource)-1], last)
	}

	if _, err = l.Peek(); err == nil {
		t.Fatalf("Peek() past end of text should have failed")
	}

	if _, err = l.Pop(); err == nil {
		t.Fatalf("Pop() past end of text should have failed")
	}
}

func TestExpectPastEnd(t *testing.T) {
	l := scanner.NewScanner("abc")
	if _, err := l.Expect("abcde"); err == nil {
		t.Fatalf("Expect() past end of text should have failed")
	}
}

func TestFindToken(t *testing.T) {
	l := scanner.NewScanner("abcde")
	if !l.FindToken("a", true) {
		t.Fatal("FindToken(): case-sensitive search for 'a' failed when it should not have")
	}
	if !l.FindToken("A", false) {
		t.Fatal("FindToken(): case-INsensitive search for 'a' failed when it should not have")
	}

	if l.FindToken("A", true) {
		t.Fatal("FindToken(): case-sensitive search for 'A' suceeded when it should not have")
	}
}

func TestAdvance(t *testing.T) {
	l := scanner.NewScanner("abcde")
	if err := l.Advance(1); err != nil {
		t.Fatalf("Advance() returned error: %v", err)
	}

	// right up to the end
	if err := l.Advance(4); err != nil {
		t.Fatalf("Advance() returned error: %v", err)
	}

	if err := l.Advance(1); err == nil {
		t.Fatalf("Advance() past end of text should have failed")
	}
}

func TestUntil(t *testing.T) {
	l := scanner.NewScanner("abcde")
	token, err := l.Until('c')
	if err != nil {
		t.Fatal("Until() failed to find 'c'")
	}
	if token != "ab" {
		t.Fatalf("Until(): expected token %s, got %s", "ab", token)
	}

	if r, err := l.Peek(); err != nil {
		t.Fatalf("Peek() after Advance() got error: %v", err)
	} else if r != 'c' {
		t.Fatalf("Peek() after Advance(): expected %c, got %c", 'c', r)
	}
}
