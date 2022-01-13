package main

import (
	"fmt"
	"os"

	"github.com/getlantern/geneva"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:                   "geneva",
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			{
				Name:  "dot",
				Usage: "output the strategy graph as an SVG",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Value:   "output.svg",
					},
				},
				ArgsUsage: "STRATEGY",
				Action:    dot,
			},
			{
				Name:  "intercept",
				Usage: "Run a strategy on live network traffic",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "input",
						Aliases: []string{"i"},
						Value:   "strategy.txt",
					},
					&cli.StringFlag{
						Name:    "interface",
						Aliases: []string{"iface"},
					},
				},
				Action: intercept,
			},
			{
				Name:  "run-pcap",
				Usage: "Run a PCAP file through a strategy and output the resulting packets in a new PCAP",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "force",
						Usage:   "Overwrite destination file if it exists",
						Aliases: []string{"f"},
					},
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Value:    "input.pcap",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "output",
						Aliases:  []string{"o"},
						Value:    "output.pcap",
						Required: true,
					},
				},
				Action: runPcap,
			},
			{
				Name:  "validate",
				Usage: "validate that a strategy is well-formed",
				Action: func(c *cli.Context) error {
					return validate(c.Args().First())
				},
			},
		},
	}

	_ = app.Run(os.Args)
}

func validate(s string) error {
	strategy, err := geneva.NewStrategy(s)
	if err != nil {
		return cli.Exit(fmt.Sprintf("invalid strategy: %v\n", err), 1)
	}

	fmt.Println(strategy)

	return nil
}
