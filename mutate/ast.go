package mutate

import (
	"fmt"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/getlantern/geneva/strategy"
	"github.com/getlantern/geneva/triggers"
)

type actionSlot struct {
	get    func() actions.Action
	set    func(actions.Action)
	isRoot bool
}

func collectActionSlots(tree *actions.ActionTree) []actionSlot {
	slots := make([]actionSlot, 0, 8)
	root := actionSlot{
		get:    func() actions.Action { return tree.RootAction },
		set:    func(action actions.Action) { tree.RootAction = action },
		isRoot: true,
	}
	collectActionSlot(root, &slots)
	return slots
}

func geneticActionSlots(tree *actions.ActionTree) []actionSlot {
	all := collectActionSlots(tree)
	slots := make([]actionSlot, 0, len(all))
	for _, slot := range all {
		if _, implicit := slot.get().(*actions.SendAction); !implicit {
			slots = append(slots, slot)
		}
	}
	if len(slots) == 0 {
		return all
	}
	return slots
}

func collectActionSlot(slot actionSlot, slots *[]actionSlot) {
	// Nil slots (an action-less passthrough tree's root) are still valid mutation and
	// crossover points.
	*slots = append(*slots, slot)

	action := slot.get()
	if action == nil {
		return
	}

	switch typed := action.(type) {
	case *actions.DuplicateAction:
		left := actionSlot{
			get: func() actions.Action { return typed.Left },
			set: func(action actions.Action) { typed.Left = action },
		}
		right := actionSlot{
			get: func() actions.Action { return typed.Right },
			set: func(action actions.Action) { typed.Right = action },
		}
		collectActionSlot(left, slots)
		collectActionSlot(right, slots)
	case *actions.FragmentAction:
		first := actionSlot{
			get: func() actions.Action { return typed.FirstFragmentAction },
			set: func(action actions.Action) { typed.FirstFragmentAction = action },
		}
		second := actionSlot{
			get: func() actions.Action { return typed.SecondFragmentAction },
			set: func(action actions.Action) { typed.SecondFragmentAction = action },
		}
		collectActionSlot(first, slots)
		collectActionSlot(second, slots)
	case *actions.TCPTamperAction:
		child := actionSlot{
			get: func() actions.Action { return typed.Action },
			set: func(action actions.Action) { typed.Action = action },
		}
		collectActionSlot(child, slots)
	case *actions.IPv4TamperAction:
		child := actionSlot{
			get: func() actions.Action { return typed.Action },
			set: func(action actions.Action) { typed.Action = action },
		}
		collectActionSlot(child, slots)
	}
}

func cloneStrategy(parent *strategy.Strategy) (*strategy.Strategy, error) {
	if err := strategy.Validate(parent); err != nil {
		return nil, err
	}

	clone, err := strategy.ParseStrategy(parent.String())
	if err != nil {
		return nil, fmt.Errorf("clone strategy: %w", err)
	}
	return clone, nil
}

func parseAction(dna string) (actions.Action, error) {
	action, err := actions.ParseAction(scanner.NewScanner(dna))
	if err != nil {
		return nil, fmt.Errorf("parse generated action %q: %w", dna, err)
	}
	return action, nil
}

func (g *Generator) randomTree(direction strategy.Direction) (*actions.ActionTree, error) {
	trigger, err := g.randomTrigger()
	if err != nil {
		return nil, err
	}
	action, err := g.randomAction(direction)
	if err != nil {
		return nil, err
	}

	return &actions.ActionTree{Trigger: trigger, RootAction: action}, nil
}

func (g *Generator) randomTrigger() (triggers.Trigger, error) {
	values := []string{
		"TCP:flags:S",
		"TCP:flags:SA",
		"TCP:flags:A*",
		"TCP:flags:R",
		"TCP:dport:80",
		"TCP:dport:443",
		"TCP:sport:80",
		"TCP:window:65535",
		"IP:ttl:64",
		"IP:ttl:128",
		"IP:proto:6",
		"IP:tos:0",
	}
	dna := values[g.random.IntN(len(values))]
	if g.random.Float64() < 0.20 {
		// Gas 0 would produce a trigger that can never fire; generate 1 through 5.
		dna += fmt.Sprintf(":%d", 1+g.random.IntN(5))
	}

	trigger, err := triggers.ParseTrigger(scanner.NewScanner("[" + dna + "]"))
	if err != nil {
		return nil, fmt.Errorf("parse generated trigger %q: %w", dna, err)
	}
	return trigger, nil
}

func (g *Generator) randomAction(direction strategy.Direction) (actions.Action, error) {
	// These are the canonical action weights: tamper 5, duplicate 3,
	// fragment 2, and drop 1. Inbound excludes both branching actions.
	if direction == strategy.DirectionInbound {
		if g.random.IntN(6) < 5 {
			return g.randomTamper()
		}
		return &actions.DropAction{}, nil
	}

	switch pick := g.random.IntN(11); {
	case pick < 5:
		return g.randomTamper()
	case pick < 8:
		return &actions.DuplicateAction{
			Left:  &actions.SendAction{},
			Right: &actions.SendAction{},
		}, nil
	case pick < 10:
		return g.randomFragment(nil, nil)
	default:
		return &actions.DropAction{}, nil
	}
}

func (g *Generator) randomTamper() (actions.Action, error) {
	templates := []string{
		"tamper{TCP:flags:replace:S}",
		"tamper{TCP:flags:replace:R}",
		"tamper{TCP:flags:corrupt}",
		"tamper{TCP:seq:corrupt}",
		"tamper{TCP:ack:corrupt}",
		"tamper{TCP:window:replace:0}",
		"tamper{TCP:options-timestamp:corrupt}",
		"tamper{IP:ttl:replace:64}",
		"tamper{IP:id:corrupt}",
		"tamper{IP:tos:replace:0}",
	}
	return parseAction(templates[g.random.IntN(len(templates))])
}

func (g *Generator) randomFragment(first, second actions.Action) (*actions.FragmentAction, error) {
	if first == nil {
		first = &actions.SendAction{}
	}
	if second == nil {
		second = &actions.SendAction{}
	}

	proto := "TCP"
	fragSize := -1
	if g.random.Float64() >= 0.75 {
		proto = "IP"
		if g.random.Float64() < 0.20 {
			fragSize = 1 + g.random.IntN(49)
		}
	} else if g.random.Float64() < 0.50 {
		fragSize = 1 + g.random.IntN(59)
	}

	// Overlap is only honored for TCP segmentation; FragmentIPPacket (like canonical Geneva's
	// ip_fragment, which uses scapy fragmentation) ignores it. Don't emit a dead gene that
	// serializes differently but behaves identically.
	overlap := 0
	if proto == "TCP" && g.random.Float64() < 0.50 {
		if g.random.Float64() < 0.50 {
			if fragSize == -1 {
				overlap = 5
			} else {
				overlap = fragSize / 2
			}
		} else {
			overlap = 1 + g.random.IntN(49)
		}
	}

	return actions.NewFragmentAction(proto, fragSize, g.random.IntN(2) == 0, overlap, first, second)
}

func setTamperChild(action actions.Action, child actions.Action) error {
	switch typed := action.(type) {
	case *actions.TCPTamperAction:
		typed.Action = child
	case *actions.IPv4TamperAction:
		typed.Action = child
	default:
		return fmt.Errorf("action %T is not a tamper action", action)
	}
	return nil
}
