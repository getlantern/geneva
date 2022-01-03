// Package strategy provides types and functions for creating Geneva strategies.
//
// A Geneva strategy consists of zero or more action trees that can be applied to inbound or outbound packets. The
// actions trees encode what actions to take on a packet. A strategy, conceptually, looks like this:
//
//  inbound \/ outbound
//
// "inbound" and "outbound" are ordered lists of (trigger, action tree) pairs. The Geneva paper calls these ordered
// lists "forests". The inbound and outbound forests are separated by the "\/" characters; if the strategy omits one or
// the other, then that side of the "\/" is left empty. For example, a strategy that only includes an inbound forest
// would take the form "inbound \/", whereas an outbound-only strategy would be "\/ outbound".
//
// A real example, taken from https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf (pg 2202), would look like this:
//
//  [TCP:flags:S]-
//     duplicate(
//        tamper{TCP:flags:replace:SA}(
//           send),
//         send)-| \/
//  [TCP:flags:R]-drop-|
//
// In this example, the inbound forest would trigger on TCP packets that have just the SYN flag set, and would
// perform a few different actions on those packets. The outbound forest would only apply to TCP packets with the
// RST flag set, and would simply drop them. Each of the forests in the example are made up of a single (trigger, action
// tree) pair.
package strategy

import (
	"fmt"
	"io"
	"strings"

	"github.com/Crosse/geneva/actions"
	"github.com/Crosse/geneva/internal/scanner"
	"github.com/google/gopacket"
)

// Forest refers to an ordered list of (trigger, action tree) pairs.
type Forest []*actions.ActionTree

// Strategy is the top-level Geneva construct that describes potential inbound and outbound changes to packets.
type Strategy struct {
	Inbound  Forest
	Outbound Forest
}

// Direction is the direction of a packet: either inbound (ingress) or outbound (egress).
type Direction int

const (
	// DirectionInbound indicates a packet received from a remote host (i.e., inbound or ingress traffic).
	DirectionInbound Direction = iota
	// DirectionOutbound indicates a packet to be sent to a remote host (i.e., outbound or egress traffic).
	DirectionOutbound
)

// Apply applies the strategy to a given packet.
func (s *Strategy) Apply(packet gopacket.Packet, dir Direction) ([]gopacket.Packet, error) {
	if dir == DirectionInbound && s.Inbound == nil {
		return []gopacket.Packet{packet}, nil
	} else if dir == DirectionOutbound && s.Outbound == nil {
		return []gopacket.Packet{packet}, nil
	}

	var forest Forest
	if dir == DirectionInbound {
		forest = s.Inbound
	} else {
		forest = s.Outbound
	}

	if len(forest) == 0 {
		return []gopacket.Packet{packet}, nil
	}

	packets := make([]gopacket.Packet, 0, 2)

	// XXX: here's the thing: the paper mentions that each action tree in a forest gets "its own fresh copy of the
	// original packet", so we should either copy it here before giving it to each action tree, or ensure that any
	// action that modifies the packet makes a copy first. The former would be easier to implement, while the latter
	// could potentially keep the number of memcpy() operations down by lazily copying only when required.
	for i, at := range forest {
		if m, err := at.Matches(packet); err != nil {
			return nil, fmt.Errorf("error matching action tree %d: %v", i, err)
		} else if m {
			result, err := at.Apply(packet)
			if err != nil {
				return nil, err
			}
			packets = append(packets, result...)
		} else {
			// When the action tree doesn't match, return the packet unharmed
			packets = append(packets, packet)
		}
	}

	return packets, nil
}

// ParseStrategy parses a string representation of a strategy into the actual Strategy object.
// If the string is malformed, and error will be returned instead.
func ParseStrategy(strategy string) (*Strategy, error) {
	// inbound-tree \/ outbound-tree
	l := scanner.NewScanner(strings.TrimSpace(strategy))

	st := &Strategy{
		make([]*actions.ActionTree, 0, 1),
		make([]*actions.ActionTree, 0, 1),
	}

	for {
		if l.FindToken(`\/`, true) {
			break
		}

		inbound, err := actions.ParseActionTree(l)
		if err != nil {
			return nil, err
		}
		st.Inbound = append(st.Inbound, inbound)
		l.Chomp()
	}

	l.Chomp()
	if _, err := l.Expect(`\/`); err != nil {
		// okay fine, you've already used your free pass above, so now we'll fail hard.
		return nil, err
	}
	l.Chomp()

	for {
		// before we try to parse the outbound strategy, let's first make sure there's one there at all.
		if _, err := l.Peek(); err != nil && err == io.EOF {
			// looks like we don't have an outbound strategy, so we're done!
			break
		}

		outbound, err := actions.ParseActionTree(l)
		if err != nil {
			return nil, err
		}
		st.Outbound = append(st.Outbound, outbound)
	}

	return st, nil
}

// String returns a string representation of this strategy.
func (s *Strategy) String() string {
	var inbound, outbound []string
	for _, st := range s.Inbound {
		inbound = append(inbound, st.String())
	}
	i := strings.Join(inbound, " ")

	for _, st := range s.Outbound {
		outbound = append(outbound, st.String())
	}
	o := strings.Join(outbound, " ")
	return strings.TrimSpace(fmt.Sprintf(`%s \/ %s`, i, o))
}
