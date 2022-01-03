package main

import (
	"bytes"
	"fmt"

	"github.com/Crosse/geneva"
	"github.com/Crosse/geneva/actions"
	"github.com/Crosse/geneva/strategy"
	"github.com/goccy/go-graphviz"
	"github.com/goccy/go-graphviz/cgraph"
	"github.com/urfave/cli/v2"
)

func dot(c *cli.Context) error {
	input := c.Args().First()

	if input == "" {
		return cli.Exit("no strategy given", 1)
	}

	output := c.String("output")
	if output == "" {
		return cli.Exit(fmt.Sprintf("invalid output filename: `%s`", output), 1)
	}

	strategy, err := geneva.NewStrategy(input)
	if err != nil {
		return cli.Exit(fmt.Sprintf("invalid strategy: %v", err), 1)
	}

	g := graphviz.New()

	graph, err := g.Graph()
	if err != nil {
		return cli.Exit(err, 1)
	}

	defer func() {
		if err := graph.Close(); err != nil {
			fmt.Fprintf(cli.ErrWriter, "error closing graph: %v\n", err)
		}
		g.Close()
	}()

	err = parse(graph, strategy)
	if err != nil {
		cli.Exit(fmt.Sprintf("failed to graph strategy: %v\n", err), 1)
	}

	if c.Bool("verbose") {
		var buf2 bytes.Buffer
		if err := g.Render(graph, "dot", &buf2); err != nil {
			cli.Exit(err, 1)
		}
		fmt.Println(buf2.String())
	}

	var buf bytes.Buffer
	if err = g.Render(graph, graphviz.SVG, &buf); err != nil {
		cli.Exit(err, 1)
	}

	fmt.Printf("writing SVG to %s", output)
	if err := g.RenderFilename(graph, graphviz.SVG, output); err != nil {
		cli.Exit(err, 1)
	}

	return nil
}

func parse(graph *cgraph.Graph, st *strategy.Strategy) error {
	inbound, err := graph.CreateNode("inbound")
	if err != nil {
		return err
	}

	for _, at := range st.Inbound {
		node, err := parseActionTree(graph, at)
		if err != nil {
			return err
		}
		_, err = graph.CreateEdge(name("e"), inbound, node)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseActionTree(graph *cgraph.Graph, at *actions.ActionTree) (*cgraph.Node, error) {
	trigger, err := graph.CreateNode(name("trigger"))
	if err != nil {
		return nil, err
	}
	trigger.SetShape("Mrecord")
	trigger.SetLabel(fmt.Sprintf("trigger|{%s}", at.Trigger.String()))

	node, err := parseAction(graph, at.RootAction)
	if err != nil {
		return nil, err
	}

	if _, err := graph.CreateEdge("e", trigger, node); err != nil {
		return nil, err
	}

	return trigger, nil
}

func parseAction(graph *cgraph.Graph, action actions.Action) (*cgraph.Node, error) {
	switch t := action.(type) {
	case *actions.SendAction:
		node, err := graph.CreateNode(name("send"))
		if err != nil {
			return nil, err
		}
		node.SetLabel("send")
		return node, nil
	case *actions.DropAction:
		node, err := graph.CreateNode(name("drop"))
		if err != nil {
			return nil, err
		}
		node.SetLabel("drop")
		return node, nil
	case *actions.DuplicateAction:
		return parseDuplicateAction(graph, t)
	case *actions.FragmentAction:
		return parseFragmentAction(graph, t)
	default:
		return nil, fmt.Errorf("unhandled action \"%T\"", action)
	}
}

func parseDuplicateAction(graph *cgraph.Graph, action *actions.DuplicateAction) (*cgraph.Node, error) {
	node, err := graph.CreateNode(name("duplicate"))
	if err != nil {
		return nil, err
	}
	node.SetLabel("duplicate")

	lnode, err := parseAction(graph, action.Left)
	if err != nil {
		return nil, err
	}
	rnode, err := parseAction(graph, action.Right)
	if err != nil {
		return nil, err
	}

	_, err = graph.CreateEdge(name("e"), node, lnode)
	if err != nil {
		return nil, err
	}

	_, err = graph.CreateEdge(name("e"), node, rnode)
	if err != nil {
		return nil, err
	}

	return node, nil
}

func parseFragmentAction(graph *cgraph.Graph, action *actions.FragmentAction) (*cgraph.Node, error) {
	node, err := graph.CreateNode(name("fragment"))
	if err != nil {
		return nil, err
	}
	node.SetShape("record")
	node.SetLabel(
		fmt.Sprintf("fragment|{proto:%s|offset:%d|inOrder:%v}",
			action.Proto, action.FragSize, action.InOrder))

	lnode, err := parseAction(graph, action.FirstFragmentAction)
	if err != nil {
		return nil, err
	}

	rnode, err := parseAction(graph, action.SecondFragmentAction)
	if err != nil {
		return nil, err
	}

	_, err = graph.CreateEdge(name("e"), node, lnode)
	if err != nil {
		return nil, err
	}

	_, err = graph.CreateEdge(name("e"), node, rnode)
	if err != nil {
		return nil, err
	}

	return node, nil
}

var counter int = 0

func name(base string) string {
	counter++
	return fmt.Sprintf("%s_%d", base, counter)
}
