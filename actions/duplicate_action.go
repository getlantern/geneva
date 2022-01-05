package actions

import (
	"fmt"

	"github.com/getlantern/errors"
	"github.com/getlantern/geneva/internal"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/google/gopacket"
)

// DuplicateAction is a Geneva action that duplicates a packet and applies separate action trees to each.
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
	var err error
	var duped, lpackets, rpackets []gopacket.Packet

	if duped, err = duplicate(packet); err != nil {
		return nil, errors.Wrap(err)
	}

	if lpackets, err = a.Left.Apply(duped[0]); err != nil {
		return nil, errors.Wrap(err)
	}

	if rpackets, err = a.Right.Apply(duped[1]); err != nil {
		return nil, errors.Wrap(err)
	}

	return append(lpackets, rpackets...), nil
}

// String returns a string representation of this Action.
func (a *DuplicateAction) String() string {
	return fmt.Sprintf("duplicate(%s,%s)", a.Left, a.Right)
}

// ParseDuplicateAction parses a string representation of a "duplicate" action.
// If the string is malformed, and error will be returned instead.
func ParseDuplicateAction(s *scanner.Scanner) (Action, error) {
	var err error

	if _, err = s.Expect("duplicate("); err != nil {
		return nil, fmt.Errorf("invalid duplicate() rule: %v", err)
	}

	action := &DuplicateAction{}
	if action.Left, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ',' {
			action.Left = &SendAction{}
		} else {
			return nil, errors.New(
				"invalid duplicate rule: error parsing first action: %v",
				err)
		}
	}

	if _, err = s.Expect(","); err != nil {
		return nil, errors.New("invalid duplicate rule: %v", internal.EOFUnexpected(err))
	}

	if action.Right, err = ParseAction(s); err != nil {
		if c, err2 := s.Peek(); err2 == nil && c == ')' {
			action.Right = &SendAction{}
		} else {
			return nil, errors.New("invalid duplicate rule: %v", err)
		}
	}

	if _, err = s.Expect(")"); err != nil {
		return nil, errors.New("invalid duplicate rule: %v", internal.EOFUnexpected(err))
	}

	return action, nil
}
