// Package mutate provides dependency-free genetic operations for Geneva
// strategy ASTs.
package mutate

import rand "math/rand/v2"

type randomSource interface {
	Float64() float64
	IntN(int) int
}

type globalRandom struct{}

func (globalRandom) Float64() float64 { return rand.Float64() }
func (globalRandom) IntN(n int) int   { return rand.IntN(n) }

// Generator performs deterministic mutations when constructed with a seeded
// source. A Generator must not be used concurrently.
type Generator struct {
	random randomSource
}

// New returns a mutation generator backed by source. A nil source uses Go's
// concurrency-safe package-level random generator.
func New(source rand.Source) *Generator {
	if source == nil {
		return &Generator{random: globalRandom{}}
	}

	return &Generator{random: rand.New(source)}
}

func (g *Generator) shuffle(n int, swap func(int, int)) {
	for i := n - 1; i > 0; i-- {
		j := g.random.IntN(i + 1)
		swap(i, j)
	}
}

func defaultGenerator() *Generator {
	return &Generator{random: globalRandom{}}
}
