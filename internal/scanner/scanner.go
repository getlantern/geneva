package scanner

import (
	"fmt"
	"io"
	"unicode"
)

type Scanner struct {
	rest            []rune
	currentPosition int
}

func NewScanner(source string) *Scanner {
	return &Scanner{[]rune(source), 0}
}

func (l *Scanner) tokenNotFound() error {
	r, err := l.Peek()
	if err != nil {
		return err
	}

	return fmt.Errorf(`token "%c" not recognized at char %d`, r, l.currentPosition)
}

func (l *Scanner) Rest() []rune {
	return l.rest[l.currentPosition:]
}

func (l *Scanner) Peek() (rune, error) {
	if l.currentPosition >= len(l.rest) {
		return 0, io.EOF
	}
	return l.rest[l.currentPosition], nil
}

func (l *Scanner) Pop() (rune, error) {
	b, err := l.Peek()
	if err != nil {
		return 0, err
	}

	l.currentPosition++
	return b, nil
}

func (l *Scanner) Expect(token string) (string, error) {
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

func (l *Scanner) FindToken(token string, caseSensitive bool) bool {
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

func (l *Scanner) Until(r rune) (string, error) {
	start := l.currentPosition
	for _, c := range l.rest[start:] {
		if r == c {
			return string(l.rest[start:l.currentPosition]), nil
		}
		l.currentPosition++
	}

	return "", io.EOF
}

func (l *Scanner) Advance(count int) error {
	if count > len(l.rest)-l.currentPosition {
		return io.EOF
	}

	l.currentPosition += count
	return nil
}

func (l *Scanner) Chomp() {
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
