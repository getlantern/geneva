package mutate_test

import (
	"errors"
	rand "math/rand/v2"
	"testing"

	"github.com/getlantern/geneva/mutate"
	"github.com/getlantern/geneva/strategy"
)

func TestMutateProducesValidIndependentStrategies(t *testing.T) {
	t.Parallel()

	parents := []string{
		`\/`,
		`[TCP:flags:S]-duplicate(drop,)-| \/`,
		`\/ [TCP:flags:R]-tamper{IP:ttl:replace:32}-|`,
		`[TCP:dport:443]-fragment{TCP:-1:false:5}-| \/ [TCP:flags:R]-drop-|`,
	}

	for i, dna := range parents {
		t.Run(dna, func(t *testing.T) {
			t.Parallel()
			parent, err := strategy.ParseStrategy(dna)
			if err != nil {
				t.Fatal(err)
			}
			generator := mutate.New(rand.NewPCG(uint64(i+1), uint64(i+101)))

			for range 100 {
				before := parent.String()
				child, err := generator.Mutate(parent)
				if err != nil {
					t.Fatalf("Mutate() got an error: %v", err)
				}
				if parent.String() != before {
					t.Fatal("Mutate() modified its parent")
				}
				if child.String() == before {
					t.Fatal("Mutate() returned unchanged DNA")
				}
				assertValidRoundTrip(t, child)
				parent = child
			}
		})
	}
}

func TestMutationIsDeterministicWithSeededSource(t *testing.T) {
	t.Parallel()

	parent, err := strategy.ParseStrategy(`[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:R},drop)-| \/`)
	if err != nil {
		t.Fatal(err)
	}
	first := mutate.New(rand.NewPCG(7, 11))
	second := mutate.New(rand.NewPCG(7, 11))

	left, err := first.Mutate(parent)
	if err != nil {
		t.Fatal(err)
	}
	right, err := second.Mutate(parent)
	if err != nil {
		t.Fatal(err)
	}
	if left.String() != right.String() {
		t.Errorf("seeded mutations differ:\n%s\n%s", left, right)
	}
}

func TestCrossoverProducesValidIndependentStrategies(t *testing.T) {
	t.Parallel()

	first, err := strategy.ParseStrategy(
		`[TCP:flags:R]-duplicate(tamper{TCP:flags:replace:S},drop)-| \/ [TCP:flags:A]-drop-|`,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := strategy.ParseStrategy(
		`[TCP:flags:S]-fragment{TCP:4:true}(drop,tamper{IP:ttl:replace:32})-| \/ [TCP:flags:R]-tamper{TCP:window:replace:0}-|`,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstDNA, secondDNA := first.String(), second.String()
	generator := mutate.New(rand.NewPCG(17, 23))

	for range 100 {
		left, right, crossErr := generator.Crossover(first, second)
		if crossErr != nil {
			t.Fatalf("Crossover() got an error: %v", crossErr)
		}
		if first.String() != firstDNA || second.String() != secondDNA {
			t.Fatal("Crossover() modified a parent")
		}
		assertValidRoundTrip(t, left)
		assertValidRoundTrip(t, right)
		first, second = left, right
		firstDNA, secondDNA = first.String(), second.String()
	}
}

func TestCrossoverEmptyStrategies(t *testing.T) {
	t.Parallel()

	empty, err := strategy.ParseStrategy(`\/`)
	if err != nil {
		t.Fatal(err)
	}

	// Crossing two parents that offer no crossable material reports failure instead of
	// returning unmodified clones as novel offspring.
	if _, _, err := mutate.Crossover(empty, empty); !errors.Is(err, mutate.ErrNoValidMutation) {
		t.Fatalf("Crossover(empty, empty) error = %v, expected ErrNoValidMutation", err)
	}

	// Crossing an empty parent with a non-empty one still produces novel children.
	populated, err := strategy.ParseStrategy(`[TCP:flags:S]-drop-| \/`)
	if err != nil {
		t.Fatal(err)
	}
	left, right, err := mutate.Crossover(empty, populated)
	if err != nil {
		t.Fatalf("Crossover(empty, populated) got an error: %v", err)
	}
	if left.String() == empty.String() && right.String() == populated.String() {
		t.Fatal("Crossover(empty, populated) produced no novel children")
	}
	assertValidRoundTrip(t, left)
	assertValidRoundTrip(t, right)
}

func TestGeneticOperationsRejectInvalidParents(t *testing.T) {
	t.Parallel()

	if _, err := mutate.Mutate(nil); !errors.Is(err, strategy.ErrInvalidStrategy) {
		t.Errorf("Mutate(nil) error = %v, expected ErrInvalidStrategy", err)
	}
	valid, err := strategy.ParseStrategy(`[TCP:flags:S]-drop-| \/`)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mutate.Crossover(nil, valid); !errors.Is(err, strategy.ErrInvalidStrategy) {
		t.Errorf("Crossover(nil, valid) error = %v, expected ErrInvalidStrategy", err)
	}
}

func assertValidRoundTrip(t *testing.T, candidate *strategy.Strategy) {
	t.Helper()
	if err := mutate.Validate(candidate); err != nil {
		t.Fatalf("generated invalid strategy %q: %v", candidate, err)
	}
	dna := candidate.String()
	roundTripped, err := strategy.ParseStrategy(dna)
	if err != nil {
		t.Fatalf("generated strategy did not parse %q: %v", dna, err)
	}
	if roundTripped.String() != dna {
		t.Errorf("generated strategy did not serialize canonically: %q != %q", roundTripped, dna)
	}
}

// TestMutationHandlesActionlessTrees exercises mutation and crossover over trigger-only
// passthrough trees ("[trigger]-|"), which have a nil root action slot.
func TestMutationHandlesActionlessTrees(t *testing.T) {
	t.Parallel()

	parent, err := strategy.ParseStrategy(`[TCP:flags:S]-|`)
	if err != nil {
		t.Fatal(err)
	}

	generator := mutate.New(rand.NewPCG(7, 17))

	child, err := generator.Mutate(parent)
	if err != nil {
		t.Fatalf("Mutate() got an error: %v", err)
	}
	if err := strategy.Validate(child); err != nil {
		t.Fatalf("mutated child is invalid: %v", err)
	}

	// Crossing a strategy with itself that offers no crossable material reports failure
	// rather than returning unmodified clones as novel offspring.
	_, _, err = generator.Crossover(parent, parent)
	if !errors.Is(err, mutate.ErrNoValidMutation) {
		t.Fatalf("Crossover(identical actionless parents) error = %v, expected ErrNoValidMutation", err)
	}

	// Crossing two distinct parents, at least one with an actionless tree, must succeed.
	other, err := strategy.ParseStrategy(`\/ [TCP:flags:R]-drop-|`)
	if err != nil {
		t.Fatal(err)
	}

	left, right, err := generator.Crossover(parent, other)
	if err != nil {
		t.Fatalf("Crossover() got an error: %v", err)
	}
	for i, childDNA := range []string{left.String(), right.String()} {
		parsed, parseErr := strategy.ParseStrategy(childDNA)
		if parseErr != nil || strategy.Validate(parsed) != nil {
			t.Fatalf("crossover child %d is invalid: %q (%v)", i, childDNA, parseErr)
		}
	}
}
