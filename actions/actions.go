package actions

import (
	"fmt"

	"github.com/getlantern/errors"
	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/getlantern/geneva/triggers"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers" // gopacket best practice
)

// ActionTree represents a Geneva (trigger, action) pair.
//
// Technically, Geneva uses the term "action tree" to refer to the tree of actions in the tuple (trigger, action
// tree). In other words, RootAction here is what they call the "action tree". They have no name for the (trigger,
// action tree) tuple, which this type actually represents.
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
	return r, errors.Wrap(err)
}

// Apply applies this action tree to the packet, returning zero or more potentially-modified packets.
func (at *ActionTree) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	return at.RootAction.Apply(packet)
}

// ParseActionTree attempts to parse an action tree from its input.
func ParseActionTree(s *scanner.Scanner) (*ActionTree, error) {
	trigger, err := triggers.ParseTrigger(s)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	at := &ActionTree{trigger, nil}

	if _, err := s.Expect("-"); err != nil {
		return nil, errors.Wrap(internal.EOFUnexpected(err))
	}

	at.RootAction, err = ParseAction(s)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	if _, err := s.Expect("-|"); err != nil {
		return nil, errors.Wrap(internal.EOFUnexpected(err))
	}

	return at, nil
}

// Action is implemented by any value that describes a Geneva action.
type Action interface {
	// Apply applies the action to the packet, returning zero or more potentially-modified packets.
	Apply(gopacket.Packet) ([]gopacket.Packet, error)
	fmt.Stringer
}

// ParseAction parses a string representation of an action into the actual Action object.
// If the string is malformed, and error will be returned instead.
func ParseAction(s *scanner.Scanner) (Action, error) {
	if s.FindToken("duplicate", true) {
		return ParseDuplicateAction(s)
	}
	if s.FindToken("fragment", true) {
		return ParseFragmentAction(s)
	}
	if s.FindToken("tamper", true) {
		return nil, fmt.Errorf("tamper action not yet implemented")
	}
	if s.FindToken("drop", true) {
		s.Advance(4)
		return DefaultDropAction, nil
	}
	if s.FindToken("send", true) {
		s.Advance(4)
		return DefaultSendAction, nil
	}

	return nil, errors.New("invalid action at %d", s.Pos())
}
