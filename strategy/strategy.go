package strategy

import (
	"fmt"
	"io"
	"strings"

	"github.com/Crosse/geneva/actions"
	"github.com/Crosse/geneva/internal/scanner"
)

type Strategy struct {
	Inbound  []*actions.ActionTree
	Outbound []*actions.ActionTree
}

func ParseStrategy(strategy string) (*Strategy, error) {
	// inbound-tree \/ outbound-tree
	l := scanner.NewScanner(strings.TrimSpace(strategy))

	st := &Strategy{
		make([]*actions.ActionTree, 0, 1),
		make([]*actions.ActionTree, 0, 1),
	}

	for {
		if l.FindToken(`\/`, true) {
			break
		}

		inbound, err := actions.ParseActionTree(l)
		if err != nil {
			return nil, err
		}
		st.Inbound = append(st.Inbound, inbound)
		l.Chomp()
	}

	l.Chomp()
	if _, err := l.Expect(`\/`); err != nil {
		// okay fine, you've already used your free pass above, so now we'll fail hard.
		return nil, err
	}
	l.Chomp()

	for {
		// before we try to parse the outbound strategy, let's first make sure there's one there at all.
		if _, err := l.Peek(); err != nil && err == io.EOF {
			// looks like we don't have an outbound strategy, so we're done!
			break
		}

		outbound, err := actions.ParseActionTree(l)
		if err != nil {
			return nil, err
		}
		st.Outbound = append(st.Outbound, outbound)
	}

	return st, nil
}

func (s *Strategy) String() string {
	var inbound, outbound []string
	for _, st := range s.Inbound {
		inbound = append(inbound, st.String())
	}
	i := strings.Join(inbound, " ")

	for _, st := range s.Outbound {
		outbound = append(outbound, st.String())
	}
	o := strings.Join(outbound, " ")
	return strings.TrimSpace(fmt.Sprintf(`%s \/ %s`, i, o))
}
