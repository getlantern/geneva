package actions

import (
	"fmt"

	"github.com/Crosse/geneva/internal/scanner"
	"github.com/Crosse/geneva/triggers"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
)

type ActionTree struct {
	Trigger    triggers.Trigger
	RootAction Action
}

func ParseActionTree(s *scanner.Scanner) (*ActionTree, error) {
	trigger, err := triggers.ParseTrigger(s)
	if err != nil {
		return nil, err
	}

	at := &ActionTree{trigger, nil}

	if _, err := s.Expect("-"); err != nil {
		return nil, err
	}

	at.RootAction, err = ParseAction(s)
	if err != nil {
		return nil, err
	}

	if _, err := s.Expect("-|"); err != nil {
	}

	return at, nil
}

func (at *ActionTree) String() string {
	return fmt.Sprintf("%s-%s-|", at.Trigger, at.RootAction)
}

type Action interface {
	Apply(gopacket.Packet) []gopacket.Packet
	fmt.Stringer
}

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

	return nil, fmt.Errorf("invalid action")
}
