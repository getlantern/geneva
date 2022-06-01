// Package actions describes the actions that can be applied to a given packet.
//
// See the top-level documentation for more details.
package actions

import (
	"fmt"

	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/getlantern/geneva/triggers"
	"github.com/google/gopacket"

	// gopacket best practice says import this, too.
	_ "github.com/google/gopacket/layers"
)

// ActionTree represents a Geneva (trigger, action) pair.
//
// Technically, Geneva uses the term "action tree" to refer to the tree of actions in the tuple
// (trigger, action tree). In other words, RootAction here is what they call the "action tree". They
// have no name for the (trigger, action tree) tuple, which this type actually represents.
type ActionTree struct {
	// Trigger is the trigger that will fire this action tree if matched.
	Trigger triggers.Trigger
	// RootAction is the root action of the tree and may have subordinate actions that it calls.
	RootAction Action
}

// String returns a string representation of this ActionTree.
func (at *ActionTree) String() string {
	return fmt.Sprintf("%s-%s-|", at.Trigger, at.RootAction)
}

// Matches returns whether this action tree's trigger matches the packet.
func (at *ActionTree) Matches(packet gopacket.Packet) (bool, error) {
	r, err := at.Trigger.Matches(packet)
	return r, fmt.Errorf("match failed: %w", err)
}

// Apply applies this action tree to the packet, returning zero or more potentially-modified
// packets.
func (at *ActionTree) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	r, err := at.RootAction.Apply(packet)
	return r, fmt.Errorf("apply failed: %w", err)
}

// ParseActionTree attempts to parse an action tree from its input.
func ParseActionTree(s *scanner.Scanner) (*ActionTree, error) {
	trigger, err := triggers.ParseTrigger(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse action tree: %w", err)
	}

	at := &ActionTree{trigger, nil}

	if _, err := s.Expect("-"); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in action tree: %w",
			internal.EOFUnexpected(err),
		)
	}

	at.RootAction, err = ParseAction(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse action: %w", err)
	}

	if _, err := s.Expect("-|"); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in action tree: %w",
			internal.EOFUnexpected(err),
		)
	}

	return at, nil
}

// Action is implemented by any value that describes a Geneva action.
type Action interface {
	// Apply applies the action to the packet, returning zero or more potentially-modified
	// packets.
	Apply(gopacket.Packet) ([]gopacket.Packet, error)
	fmt.Stringer
}

// ParseAction parses a string representation of an action into the actual Action object.
//
// If the string is malformed, an error will be returned instead.
func ParseAction(s *scanner.Scanner) (Action, error) {
	if s.FindToken("duplicate", true) {
		return ParseDuplicateAction(s)
	}

	if s.FindToken("fragment", true) {
		return ParseFragmentAction(s)
	}

	if s.FindToken("tamper", true) {
		return ParseTamperAction(s)
	}

	if s.FindToken("drop", true) {
		if err := s.Advance(4); err != nil {
			return nil, fmt.Errorf(
				"failed to parse action: %w",
				internal.EOFUnexpected(err),
			)
		}

		return DefaultDropAction, nil
	}

	if s.FindToken("send", true) {
		if err := s.Advance(4); err != nil {
			return nil, fmt.Errorf(
				"failed to parse action: %w",
				internal.EOFUnexpected(err),
			)
		}

		return DefaultSendAction, nil
	}

	return nil, fmt.Errorf("invalid action at %d", s.Pos())
}
