package triggers

import "sync"

// triggerGas keeps the configured gas separate from the runtime counter. A
// strategy's serialized DNA must remain stable while it is being evaluated.
type triggerGas struct {
	mu         sync.Mutex
	enabled    bool
	bomb       bool
	configured int
	remaining  int
}

func newTriggerGas(gas *int) *triggerGas {
	if gas == nil {
		return &triggerGas{}
	}

	return &triggerGas{
		enabled:    true,
		bomb:       *gas < 0,
		configured: *gas,
		remaining:  *gas,
	}
}

func (g *triggerGas) value() (int, bool) {
	if g == nil || !g.enabled {
		return 0, false
	}

	return g.configured, true
}

// allow applies the canonical Geneva gas rules to a successful field match.
// Positive gas allows that many matches. Zero allows none. Negative gas is a
// bomb: it suppresses -gas matches and allows every matching packet after that.
func (g *triggerGas) allow(matched bool) bool {
	if !matched || g == nil || !g.enabled {
		return matched
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.bomb {
		if g.remaining < 0 {
			g.remaining++
			return false
		}

		return true
	}

	if g.remaining <= 0 {
		return false
	}

	g.remaining--
	return true
}
