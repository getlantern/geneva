package mutate

import (
	"errors"
	"fmt"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/strategy"
)

// ErrNoValidMutation is returned when repeated mutations cannot produce a
// changed strategy that passes validation.
var ErrNoValidMutation = errors.New("no valid mutation produced")

// Validate checks strategy DNA before it is proposed or deployed.
func Validate(s *strategy.Strategy) error {
	return strategy.Validate(s)
}

// Mutate clones parent, applies the canonical Geneva mutation mix, validates
// the result, and returns it. Parent is never modified.
func Mutate(parent *strategy.Strategy) (*strategy.Strategy, error) {
	return defaultGenerator().Mutate(parent)
}

// Mutate clones parent, mutates it with this generator, and validates the
// result. Parent is never modified.
func (g *Generator) Mutate(parent *strategy.Strategy) (*strategy.Strategy, error) {
	if g == nil || g.random == nil {
		return nil, errors.New("mutation generator is nil")
	}

	for attempt := 0; attempt < 32; attempt++ {
		child, err := cloneStrategy(parent)
		if err != nil {
			return nil, fmt.Errorf("mutate parent: %w", err)
		}
		before := child.String()

		switch {
		case len(child.Outbound) == 0 && len(child.Inbound) == 0:
			if err := g.mutateForest(&child.Outbound, strategy.DirectionOutbound); err != nil {
				return nil, err
			}
		default:
			if len(child.Outbound) > 0 {
				if err := g.mutateForest(&child.Outbound, strategy.DirectionOutbound); err != nil {
					return nil, err
				}
			}
			if len(child.Inbound) > 0 {
				if err := g.mutateForest(&child.Inbound, strategy.DirectionInbound); err != nil {
					return nil, err
				}
			}
		}

		if err := strategy.Validate(child); err != nil {
			continue
		}
		if child.String() != before {
			return child, nil
		}
	}

	return nil, ErrNoValidMutation
}

func (g *Generator) mutateForest(forest *strategy.Forest, direction strategy.Direction) error {
	pick := g.random.Float64()
	switch {
	case len(*forest) == 0 || pick < 0.10:
		tree, err := g.randomTree(direction)
		if err != nil {
			return err
		}
		*forest = append(*forest, tree)
	case pick < 0.20:
		idx := g.random.IntN(len(*forest))
		*forest = append((*forest)[:idx], (*forest)[idx+1:]...)
	case pick < 0.25 && len(*forest) > 1:
		g.shuffle(len(*forest), func(i, j int) {
			(*forest)[i], (*forest)[j] = (*forest)[j], (*forest)[i]
		})
	default:
		for _, tree := range *forest {
			if err := g.mutateTree(tree, direction); err != nil {
				return err
			}
		}
	}

	return nil
}

func (g *Generator) mutateTree(tree *actions.ActionTree, direction strategy.Direction) error {
	pick := g.random.Float64()
	switch {
	case pick < 0.20:
		return g.addAction(tree, direction)
	case pick < 0.65:
		return g.mutateAction(tree, direction)
	case pick < 0.80:
		trigger, err := g.randomTrigger()
		if err != nil {
			return err
		}
		tree.Trigger = trigger
		return nil
	default:
		return g.removeAction(tree, direction)
	}
}

func (g *Generator) addAction(tree *actions.ActionTree, direction strategy.Direction) error {
	slots := collectActionSlots(tree)
	open := make([]actionSlot, 0, len(slots))
	for _, slot := range slots {
		if _, ok := slot.get().(*actions.SendAction); ok {
			open = append(open, slot)
		}
	}
	if len(open) == 0 {
		return g.mutateAction(tree, direction)
	}

	action, err := g.randomAction(direction)
	if err != nil {
		return err
	}
	open[g.random.IntN(len(open))].set(action)
	return nil
}

func (g *Generator) mutateAction(tree *actions.ActionTree, direction strategy.Direction) error {
	slots := geneticActionSlots(tree)
	if len(slots) == 0 {
		return errors.New("cannot mutate an empty action tree")
	}

	slot := slots[g.random.IntN(len(slots))]
	switch typed := slot.get().(type) {
	case *actions.DuplicateAction:
		typed.Left, typed.Right = typed.Right, typed.Left
	case *actions.FragmentAction:
		replacement, err := g.randomFragment(typed.FirstFragmentAction, typed.SecondFragmentAction)
		if err != nil {
			return err
		}
		slot.set(replacement)
	case *actions.TCPTamperAction:
		replacement, err := g.randomTamper()
		if err != nil {
			return err
		}
		if err := setTamperChild(replacement, typed.Action); err != nil {
			return err
		}
		slot.set(replacement)
	case *actions.IPv4TamperAction:
		replacement, err := g.randomTamper()
		if err != nil {
			return err
		}
		if err := setTamperChild(replacement, typed.Action); err != nil {
			return err
		}
		slot.set(replacement)
	default:
		replacement, err := g.randomAction(direction)
		if err != nil {
			return err
		}
		slot.set(replacement)
	}

	return nil
}

func (g *Generator) removeAction(tree *actions.ActionTree, direction strategy.Direction) error {
	slots := geneticActionSlots(tree)
	candidates := make([]actionSlot, 0, len(slots))
	for _, slot := range slots {
		if !slot.isRoot {
			candidates = append(candidates, slot)
			continue
		}
		switch slot.get().(type) {
		case *actions.DuplicateAction, *actions.FragmentAction,
			*actions.TCPTamperAction, *actions.IPv4TamperAction:
			candidates = append(candidates, slot)
		}
	}
	if len(candidates) == 0 {
		return g.mutateAction(tree, direction)
	}

	slot := candidates[g.random.IntN(len(candidates))]
	replacement := actions.Action(&actions.SendAction{})
	switch typed := slot.get().(type) {
	case *actions.DuplicateAction:
		replacement = typed.Left
	case *actions.FragmentAction:
		replacement = typed.FirstFragmentAction
	case *actions.TCPTamperAction:
		replacement = typed.Action
	case *actions.IPv4TamperAction:
		replacement = typed.Action
	}
	slot.set(replacement)
	return nil
}
