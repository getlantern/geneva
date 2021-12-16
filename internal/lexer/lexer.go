package lexer

import (
	"fmt"
	"io"
	"unicode"
)

type Lexer struct {
	rest            []rune
	currentPosition int
}

func NewLexer(source string) *Lexer {
	return &Lexer{[]rune(source), 0}
}

func (l *Lexer) tokenNotFound() error {
	r, err := l.Peek()
	if err != nil {
		return err
	}

	return fmt.Errorf(`token "%c" not recognized at char %d`, r, l.currentPosition)
}

func (l *Lexer) Rest() []rune {
	return l.rest[l.currentPosition:]
}

func (l *Lexer) Peek() (rune, error) {
	if l.currentPosition >= len(l.rest) {
		return 0, io.EOF
	}
	return l.rest[l.currentPosition], nil
}

func (l *Lexer) Pop() (rune, error) {
	b, err := l.Peek()
	if err != nil {
		return 0, err
	}

	l.currentPosition++
	return b, nil
}

func (l *Lexer) Expect(token string) (string, error) {
	if len(token) > len(l.rest)-l.currentPosition {
		return "", io.EOF
	}

	for i, c := range token {
		if l.rest[l.currentPosition+i] != c {
			return "", fmt.Errorf(`expected token "%s" not found at position %d`, token, l.currentPosition)
		}
	}
	l.currentPosition += len(token)
	return token, nil
}

func (l *Lexer) FindToken(token string, caseSensitive bool) bool {
	if len(token) > len(l.rest)-l.currentPosition {
		return false
	}

	for i, c := range token {
		t := c
		cur := l.rest[l.currentPosition+i]
		if !caseSensitive {
			t = unicode.ToLower(c)
			cur = unicode.ToLower(cur)
		}
		if cur != t {
			return false
		}
	}
	return true
}

func (l *Lexer) Until(r rune) (string, error) {
	start := l.currentPosition
	for _, c := range l.rest[start:] {
		if r == c {
			return string(l.rest[start:l.currentPosition]), nil
		}
		l.currentPosition++
	}

	return "", io.EOF
}

func (l *Lexer) Advance(count int) error {
	if count > len(l.rest)-l.currentPosition {
		return io.EOF
	}

	l.currentPosition += count
	return nil
}

func (l *Lexer) Chomp() {
	for {
		c, err := l.Peek()
		if err != nil {
			return
		}
		if !unicode.IsSpace(c) {
			return
		}
		_ = l.Advance(1)
	}
}
