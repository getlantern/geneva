//go:build !windows

package main

import (
	"fmt"
	"runtime"

	"github.com/getlantern/geneva/strategy"
	"github.com/urfave/cli/v2"
)

func doIntercept(strat *strategy.Strategy, iface string) error {
	return cli.Exit(fmt.Sprintf("intercept not supported on %s", runtime.GOOS), 1)
}
