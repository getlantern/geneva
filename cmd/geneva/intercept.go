package main

import (
	"fmt"
	"os"

	"github.com/getlantern/geneva"
	"github.com/urfave/cli/v2"
)

func intercept(c *cli.Context) error {
	inputFile := c.String("input")
	iface := c.String("interface")

	if inputFile == "" {
		return cli.Exit("no strategy given", 1)
	}

	if iface == "" {
		return cli.Exit("no interface specified", 1)
	}

	input, err := os.ReadFile(inputFile)
	if err != nil {
		return cli.Exit(fmt.Sprintf("cannot open %s: %v", inputFile, err), 1)
	}

	strat, err := geneva.NewStrategy(string(input))
	if err != nil {
		return cli.Exit(err, 1)
	}

	fmt.Println("outbound strategy:")

	for _, s := range strat.Outbound {
		fmt.Printf("\t%s\n", s)
	}

	fmt.Println("inbound strategy:")

	for _, s := range strat.Inbound {
		fmt.Printf("\t%s\n", s)
	}

	return doIntercept(strat, iface)
}
