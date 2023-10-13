package actions

import (
	"errors"
	"fmt"

	"github.com/google/gopacket"

	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
)

// DuplicateAction is a Geneva action that duplicates a packet and applies separate action trees to
// each.
type DuplicateAction struct {
	Left  Action
	Right Action
}

func duplicate(packet gopacket.Packet) ([]gopacket.Packet, error) {
	pData := packet.Data()
	buf := make([]byte, len(pData))
	copy(buf, pData)

	var firstLayer gopacket.Layer

	for _, l := range packet.Layers() {
		if l != nil {
			firstLayer = l

			break
		}
	}

	if firstLayer == nil {
		return nil, errors.New("duplicate: packet has no parseable layers")
	}

	p2 := gopacket.NewPacket(buf, firstLayer.LayerType(), gopacket.Default)

	return []gopacket.Packet{packet, p2}, nil
}

// Apply duplicates packet, returning zero or more potentially-modified packets.
//
// The number of returned packets depends on this action's sub-actions.
func (a *DuplicateAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	var (
		err                error
		duped              []gopacket.Packet
		lpackets, rpackets []gopacket.Packet
	)

	if duped, err = duplicate(packet); err != nil {
		return nil, fmt.Errorf("failed to duplciate packet: %w", err)
	}

	if lpackets, err = a.Left.Apply(duped[0]); err != nil {
		return nil, fmt.Errorf(
			"failed to apply action tree to first duplicate packet: %w",
			err,
		)
	}

	if rpackets, err = a.Right.Apply(duped[1]); err != nil {
		return nil, fmt.Errorf(
			"failed to apply action tree to second duplicate packet: %w",
			err,
		)
	}

	return append(lpackets, rpackets...), nil
}

// String returns a string representation of this Action.
func (a *DuplicateAction) String() string {
	actions := [2]string{"", ""}
	if _, ok := a.Left.(*SendAction); !ok {
		actions[0] = a.Left.String()
	}

	if _, ok := a.Right.(*SendAction); !ok {
		actions[1] = a.Right.String()
	}

	var actStr string
	if len(actions[0])+len(actions[1]) > 0 {
		actStr = fmt.Sprintf("(%s,%s)", actions[0], actions[1])
	}

	return fmt.Sprintf("duplicate%s", actStr)
}

// ParseDuplicateAction parses a string representation of a "duplicate" action.
//
// If the string is malformed, an error will be returned instead.
func ParseDuplicateAction(s *scanner.Scanner) (Action, error) {
	var err error

	action := &DuplicateAction{}

	if _, err = s.Expect("duplicate"); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in duplicate rule: %w",
			internal.EOFUnexpected(err),
		)
	}

	// rules can omit all arguments, in which case all actions are assumed to be 'send' actions
	if _, err = s.Expect("("); err != nil {
		action.Left = &SendAction{}
		action.Right = &SendAction{}

		return action, nil //nolint:nilerr
	}

	if action.Left, err = ParseAction(s); err != nil {
		if !errors.Is(err, ErrInvalidAction) {
			return nil, err
		}

		if c, err2 := s.Peek(); err2 == nil && c == ',' {
			action.Left = &SendAction{}
		} else {
			return nil, fmt.Errorf(
				"error parsing first action of duplicate rule: %v",
				err)
		}
	}

	if _, err = s.Expect(","); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in duplicate rule: %v",
			internal.EOFUnexpected(err),
		)
	}

	if action.Right, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			action.Right = &SendAction{}
		} else {
			return nil, fmt.Errorf(
				"error parsing second action of duplicate rule: %v",
				err)
		}
	}

	if _, err = s.Expect(")"); err != nil {
		return nil, fmt.Errorf(
			"unexpected token in duplicate rule: %v",
			internal.EOFUnexpected(err),
		)
	}

	return action, nil
}
