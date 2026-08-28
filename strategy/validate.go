package strategy

import (
	"errors"
	"fmt"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/triggers"
)

const (
	// MaxTreesPerForest bounds the work performed for each packet direction.
	MaxTreesPerForest = 64
	// MaxActions bounds the total number of action nodes in a strategy.
	MaxActions = 256
	// MaxActionDepth bounds recursive action evaluation.
	MaxActionDepth = 64
)

// ErrInvalidStrategy is returned when strategy DNA is structurally invalid or
// uses behavior outside the supported IPv4/TCP engine.
var ErrInvalidStrategy = errors.New("invalid strategy")

// Validate checks a strategy before it is proposed or deployed. Validation is
// side-effect free and does not consume trigger gas.
func Validate(s *Strategy) error {
	if s == nil {
		return fmt.Errorf("%w: strategy is nil", ErrInvalidStrategy)
	}

	count := 0
	if err := validateForest(s.Outbound, DirectionOutbound, &count); err != nil {
		return err
	}
	if err := validateForest(s.Inbound, DirectionInbound, &count); err != nil {
		return err
	}

	return nil
}

func validateForest(forest Forest, direction Direction, count *int) error {
	if len(forest) > MaxTreesPerForest {
		return fmt.Errorf("%w: %s forest has %d trees; maximum is %d",
			ErrInvalidStrategy, direction, len(forest), MaxTreesPerForest)
	}

	for i, tree := range forest {
		if tree == nil {
			return fmt.Errorf("%w: %s tree %d is nil", ErrInvalidStrategy, direction, i)
		}
		if err := triggers.Validate(tree.Trigger); err != nil {
			return fmt.Errorf("%w: %s tree %d: %w", ErrInvalidStrategy, direction, i, err)
		}

		// A tree without a root action is a valid canonical passthrough tree.
		if tree.RootAction == nil {
			continue
		}

		active := make(map[actions.Action]bool)
		if err := validateAction(tree.RootAction, direction, 1, count, active); err != nil {
			return fmt.Errorf("%w: %s tree %d: %w", ErrInvalidStrategy, direction, i, err)
		}
	}

	return nil
}

func validateAction(action actions.Action, direction Direction, depth int, count *int, active map[actions.Action]bool) error {
	if action == nil {
		return errors.New("action is nil")
	}
	if depth > MaxActionDepth {
		return fmt.Errorf("action depth exceeds %d", MaxActionDepth)
	}

	*count++
	if *count > MaxActions {
		return fmt.Errorf("strategy has more than %d actions", MaxActions)
	}

	switch typed := action.(type) {
	case *actions.SendAction:
		if typed == nil {
			return errors.New("send action is nil")
		}
		return nil
	case *actions.DropAction:
		if typed == nil {
			return errors.New("drop action is nil")
		}
		return nil
	}

	// Reject unsupported implementations before the cycle-detection map, which uses the
	// action as a key: a non-comparable Action implementation would panic ("hash of
	// unhashable type") instead of returning the intended invalid-strategy error.
	if !isSupportedBranchingAction(action) {
		return fmt.Errorf("unsupported action type %T", action)
	}

	if active[action] {
		return errors.New("action graph contains a cycle")
	}
	active[action] = true
	defer delete(active, action)

	switch typed := action.(type) {
	case *actions.DuplicateAction:
		if typed == nil {
			return errors.New("duplicate action is nil")
		}
		if direction == DirectionInbound {
			return errors.New("duplicate is a branching action and cannot be used inbound")
		}
		if err := validateAction(typed.Left, direction, depth+1, count, active); err != nil {
			return fmt.Errorf("duplicate left child: %w", err)
		}
		if err := validateAction(typed.Right, direction, depth+1, count, active); err != nil {
			return fmt.Errorf("duplicate right child: %w", err)
		}
	case *actions.FragmentAction:
		if typed == nil {
			return errors.New("fragment action is nil")
		}
		if direction == DirectionInbound {
			return errors.New("fragment is a branching action and cannot be used inbound")
		}
		if typed.Proto() != "IP" && typed.Proto() != "TCP" {
			return fmt.Errorf("fragment protocol %q is unsupported; only IPv4 and TCP are supported", typed.Proto())
		}
		if typed.FragSize < -1 {
			return fmt.Errorf("fragment size %d is invalid", typed.FragSize)
		}
		if typed.Overlap() < 0 {
			return fmt.Errorf("fragment overlap %d is invalid", typed.Overlap())
		}
		if err := validateAction(typed.FirstFragmentAction, direction, depth+1, count, active); err != nil {
			return fmt.Errorf("fragment first child: %w", err)
		}
		if err := validateAction(typed.SecondFragmentAction, direction, depth+1, count, active); err != nil {
			return fmt.Errorf("fragment second child: %w", err)
		}
	case *actions.TCPTamperAction:
		if typed == nil {
			return errors.New("TCP tamper action is nil")
		}
		definition := typed.TamperAction
		child := definition.Action
		definition.Action = actions.DefaultSendAction
		if _, err := actions.NewTCPTamperAction(definition); err != nil {
			return fmt.Errorf("invalid TCP tamper action: %w", err)
		}
		if err := validateAction(child, direction, depth+1, count, active); err != nil {
			return fmt.Errorf("TCP tamper child: %w", err)
		}
	case *actions.IPv4TamperAction:
		if typed == nil {
			return errors.New("IPv4 tamper action is nil")
		}
		definition := typed.TamperAction
		child := definition.Action
		definition.Action = actions.DefaultSendAction
		if _, err := actions.NewIPv4TamperAction(definition); err != nil {
			return fmt.Errorf("invalid IPv4 tamper action: %w", err)
		}
		if err := validateAction(child, direction, depth+1, count, active); err != nil {
			return fmt.Errorf("IPv4 tamper child: %w", err)
		}
	case *actions.SleepAction:
		if typed == nil {
			return errors.New("sleep action is nil")
		}
		// Sleep is not a branching action, so — like tamper — it is valid in either
		// direction.
		if typed.Duration < 0 {
			return fmt.Errorf("sleep duration %s is invalid", typed.Duration)
		}
		// A nil child is an elided send (see SleepAction.Apply and String), so there is
		// nothing to recurse into; validate only a child that is actually present. This
		// also keeps mutation/crossover, which can swap in nil passthrough subtrees,
		// from producing a strategy that validation rejects but Apply accepts.
		if typed.Action != nil {
			if err := validateAction(typed.Action, direction, depth+1, count, active); err != nil {
				return fmt.Errorf("sleep child: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported action type %T", action)
	}

	return nil
}

// isSupportedBranchingAction reports whether action is a composite implementation that the
// validator knows how to recurse into. Terminal types (send, drop) are handled above.
func isSupportedBranchingAction(action actions.Action) bool {
	switch action.(type) {
	case *actions.DuplicateAction, *actions.FragmentAction,
		*actions.TCPTamperAction, *actions.IPv4TamperAction,
		*actions.SleepAction:
		return true
	}
	return false
}
