package main

import (
	"fmt"
	"os"

	"github.com/Crosse/geneva"
)

func fatal(m interface{}) {
	fmt.Fprintln(os.Stderr, m)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "not enough arguments\n")
		os.Exit(1)
	}

	input := os.Args[1]
	strategy, err := geneva.NewStrategy(input)
	if err != nil {
		fatal(fmt.Sprintf("invalid strategy: %v\n", err))
	}

	fmt.Println("strategy is well-formed!")
	fmt.Println(strategy)
}
