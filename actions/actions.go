package actions

import (
	"fmt"

	"github.com/Crosse/geneva/internal/lexer"
	"github.com/Crosse/geneva/triggers"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
)

type ActionTree struct {
	Trigger    triggers.Trigger
	RootAction Action
}

func ParseActionTree(l *lexer.Lexer) (*ActionTree, error) {
	trigger, err := triggers.ParseTrigger(l)
	if err != nil {
		return nil, err
	}

	at := &ActionTree{trigger, nil}

	if _, err := l.Expect("-"); err != nil {
		return nil, err
	}

	at.RootAction, err = ParseAction(l)
	if err != nil {
		return nil, err
	}

	if _, err := l.Expect("-|"); err != nil {
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

func ParseAction(l *lexer.Lexer) (Action, error) {
	if l.FindToken("duplicate", true) {
		return ParseDuplicateAction(l)
	}
	if l.FindToken("fragment", true) {
		return ParseFragmentAction(l)
	}
	if l.FindToken("tamper", true) {
		return nil, fmt.Errorf("tamper action not yet implemented")
	}
	if l.FindToken("drop", true) {
		l.Advance(4)
		return DefaultDropAction, nil
	}
	if l.FindToken("send", true) {
		l.Advance(4)
		return DefaultSendAction, nil
	}

	return nil, fmt.Errorf("invalid action")
}
