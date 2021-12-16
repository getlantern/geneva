package geneva

import (
	"github.com/Crosse/geneva/strategy"
)

func NewStrategy(st string) (*strategy.Strategy, error) {
	return strategy.ParseStrategy(st)
}
