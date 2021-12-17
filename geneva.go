package geneva

import (
	"github.com/Crosse/geneva/strategy"
)

// NewStrategy parses st into a Geneva strategy.
//
// This is a convenience wrapper for strategy.ParseStrategy().
func NewStrategy(st string) (*strategy.Strategy, error) {
	return strategy.ParseStrategy(st)
}
