package actions

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
)

// ErrInvalidSleepRule is returned when a "sleep" action cannot be parsed.
var ErrInvalidSleepRule = errors.New("invalid sleep rule")

// SleepAction is a Geneva action that pauses for a fixed duration before applying its child
// action (and therefore before the resulting packets are emitted).
//
// It mirrors canonical Geneva's "sleep" action, whose duration is expressed in (fractional)
// seconds: "sleep{1}" sleeps one second, "sleep{0.5}" half a second. As in canonical Geneva,
// a sleep may carry a single child action; "sleep{d}" is shorthand for "sleep{d}(send)".
//
// The pause is synchronous: Apply blocks the calling goroutine for the duration. In a
// per-packet processing model (such as an nfqueue worker) this delays only the packet being
// processed, matching canonical Geneva's "delay before sending this packet" semantics.
type SleepAction struct {
	// Duration is how long to sleep before applying the child action.
	Duration time.Duration
	// Action is the action to apply after sleeping.
	Action Action
}

// Apply sleeps for the configured duration and then applies the child action.
func (a *SleepAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	if a.Duration > 0 {
		time.Sleep(a.Duration)
	}

	return a.Action.Apply(packet)
}

// String returns a string representation of this action. The duration is rendered in seconds
// to match canonical Geneva's "sleep{<seconds>}" syntax. A plain "send" child is elided, just
// as canonical Geneva serializes a childless sleep.
func (a *SleepAction) String() string {
	seconds := strconv.FormatFloat(a.Duration.Seconds(), 'g', -1, 64)

	if _, ok := a.Action.(*SendAction); ok || a.Action == nil {
		return fmt.Sprintf("sleep{%s}", seconds)
	}

	return fmt.Sprintf("sleep{%s}(%s)", seconds, a.Action)
}

// ParseSleepAction parses a string representation of a "sleep" action.
//
// If the string is malformed, an error will be returned instead.
//
//nolint:errorlint
func ParseSleepAction(s *scanner.Scanner) (Action, error) {
	if _, err := s.Expect("sleep{"); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrInvalidSleepRule, err)
	}

	str, err := s.Until('}')
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrInvalidSleepRule, err)
	}

	_, _ = s.Pop()

	seconds, err := strconv.ParseFloat(strings.TrimSpace(str), 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a valid duration", ErrInvalidSleepRule, str)
	}
	if seconds < 0 {
		return nil, fmt.Errorf("%w: duration must not be negative", ErrInvalidSleepRule)
	}

	action := &SleepAction{
		Duration: time.Duration(seconds * float64(time.Second)),
		Action:   &SendAction{},
	}

	// A child action is optional: "sleep{d}" is equivalent to "sleep{d}(send)".
	if _, err = s.Expect("("); err != nil {
		return action, nil //nolint:nilerr
	}

	if action.Action, err = ParseAction(s); err != nil {
		if !errors.Is(err, ErrInvalidAction) {
			return nil, err
		}

		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			action.Action = &SendAction{}
		} else {
			return nil, fmt.Errorf("%s: invalid action, %w", ErrInvalidSleepRule, err)
		}
	}

	// Sleep is not a branching action, so it accepts at most one child.
	if _, err = s.Expect(","); err == nil {
		if !s.FindToken(")", true) {
			return nil, fmt.Errorf("%w: only one action is allowed", ErrInvalidSleepRule)
		}
	}

	if _, err = s.Expect(")"); err != nil {
		return nil, fmt.Errorf("%s: unexpected token: %w", ErrInvalidSleepRule, internal.EOFUnexpected(err))
	}

	return action, nil
}
