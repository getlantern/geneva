//nolint:godox
package scanner

import (
	"io"
	"unicode"

	"github.com/getlantern/errors"
)

// Scanner is a token scanner tailored to this library.
//
// BUG(sw) this could probably be almost completely replaced with stdlib's text/scanner.
type Scanner struct {
	rest            []rune
	currentPosition int
}

// NewScanner creates a new scanner with the given source.
func NewScanner(source string) *Scanner {
	return &Scanner{[]rune(source), 0}
}

func (l *Scanner) Pos() int {
	return l.currentPosition
}

// Peek returns the next rune without consuming it. It returns io.EOF if the scanner is at the end of the source.
func (l *Scanner) Peek() (rune, error) {
	if l.currentPosition >= len(l.rest) {
		return 0, io.EOF
	}

	return l.rest[l.currentPosition], nil
}

// Pop returns the next rune and consumes it. It returns io.EOF if the scanner is at the end of the source.
func (l *Scanner) Pop() (rune, error) {
	b, err := l.Peek()
	if err != nil {
		return 0, errors.Wrap(err)
	}

	l.currentPosition++

	return b, nil
}

// Expect tells the scanner that the given token must be found at the current position, and consumes it.
//
// If it is not found, it will return an error and the scanner position will not change.
func (l *Scanner) Expect(token string) (string, error) {
	if len(token) > len(l.rest)-l.currentPosition {
		return "", io.EOF
	}

	for i, c := range token {
		if l.rest[l.currentPosition+i] != c {
			return "", errors.New("expected token %q not found at position %d", token, l.currentPosition)
		}
	}

	l.currentPosition += len(token)

	return token, nil
}

// FindToken returns true if it finds the at the current position, and false otherwise. It does not consume the token.
//
// FindToken will perform a case-insensitive match if caseSensitive = false.
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

// Until searches for the next occurrence of r and returns the string from the starting position to right before r.
//
// All runes from the starting position to r are consumed. r is not consumed.
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

// Advance consumes count runes but does not return them.
func (l *Scanner) Advance(count int) error {
	if count > len(l.rest)-l.currentPosition {
		return io.EOF
	}

	l.currentPosition += count

	return nil
}

// Chomp advances past any whitespace.
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
