package mutate

import (
	"errors"
	"fmt"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/strategy"
)

// Crossover clones both parents, crosses their action ASTs using the canonical
// 80% subtree / 20% whole-tree operation mix, validates both children, and
// returns them. The parents are never modified.
func Crossover(first, second *strategy.Strategy) (*strategy.Strategy, *strategy.Strategy, error) {
	return defaultGenerator().Crossover(first, second)
}

// Crossover crosses two cloned parents using this generator.
func (g *Generator) Crossover(first, second *strategy.Strategy) (*strategy.Strategy, *strategy.Strategy, error) {
	if g == nil || g.random == nil {
		return nil, nil, errors.New("mutation generator is nil")
	}

	for attempt := 0; attempt < 32; attempt++ {
		left, err := cloneStrategy(first)
		if err != nil {
			return nil, nil, fmt.Errorf("crossover first parent: %w", err)
		}
		right, err := cloneStrategy(second)
		if err != nil {
			return nil, nil, fmt.Errorf("crossover second parent: %w", err)
		}

		g.crossForest(&left.Outbound, &right.Outbound)
		g.crossForest(&left.Inbound, &right.Inbound)

		// Crossing two parents that differ in no crossable way (e.g. both empty) yields
		// clones of the parents, not novel offspring. Retry like Mutate does.
		if left.String() == first.String() && right.String() == second.String() {
			continue
		}

		if err := strategy.Validate(left); err != nil {
			continue
		}
		if err := strategy.Validate(right); err != nil {
			continue
		}
		return left, right, nil
	}

	return nil, nil, ErrNoValidMutation
}

func (g *Generator) crossForest(first, second *strategy.Forest) bool {
	if len(*first) == 0 && len(*second) == 0 {
		return false
	}

	if len(*first) > 0 && len(*second) > 0 &&
		(g.random.Float64() < 0.80 || len(*first) == 1 && len(*second) == 1) {
		leftTree := (*first)[g.random.IntN(len(*first))]
		rightTree := (*second)[g.random.IntN(len(*second))]
		leftSlots := geneticActionSlots(leftTree)
		rightSlots := geneticActionSlots(rightTree)
		if len(leftSlots) == 0 || len(rightSlots) == 0 {
			// Defensive: a valid tree always has at least one action slot.
			return false
		}
		leftSlot := leftSlots[g.random.IntN(len(leftSlots))]
		rightSlot := rightSlots[g.random.IntN(len(rightSlots))]
		leftAction, rightAction := leftSlot.get(), rightSlot.get()
		leftSlot.set(rightAction)
		rightSlot.set(leftAction)
		return true
	}

	var leftDonation, rightDonation *actions.ActionTree
	if len(*first) > 0 {
		idx := g.random.IntN(len(*first))
		leftDonation = (*first)[idx]
		*first = append((*first)[:idx], (*first)[idx+1:]...)
	}
	if len(*second) > 0 {
		idx := g.random.IntN(len(*second))
		rightDonation = (*second)[idx]
		*second = append((*second)[:idx], (*second)[idx+1:]...)
	}
	if rightDonation != nil {
		idx := g.random.IntN(len(*first) + 1)
		*first = insertTree(*first, idx, rightDonation)
	}
	if leftDonation != nil {
		idx := g.random.IntN(len(*second) + 1)
		*second = insertTree(*second, idx, leftDonation)
	}
	return true
}

func insertTree(forest strategy.Forest, idx int, tree *actions.ActionTree) strategy.Forest {
	forest = append(forest, nil)
	copy(forest[idx+1:], forest[idx:])
	forest[idx] = tree
	return forest
}
