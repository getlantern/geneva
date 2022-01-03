package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/goccy/go-graphviz"
	"github.com/goccy/go-graphviz/cgraph"

	"github.com/getlantern/geneva"
	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/strategy"
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

	g := graphviz.New()

	graph, err := g.Graph()
	if err != nil {
		fatal(err)
	}

	defer func() {
		if err := graph.Close(); err != nil {
			fatal(err)
		}
		g.Close()
	}()

	err = parse(graph, strategy)
	if err != nil {
		fatal(fmt.Sprintf("failed to graph strategy: %v\n", err))
	}

	fmt.Println("printing DOT")
	var buf2 bytes.Buffer
	if err := g.Render(graph, "dot", &buf2); err != nil {
		fatal(err)
	}
	fmt.Println(buf2.String())

	fmt.Println("rendering SVG in memory")
	var buf bytes.Buffer
	if err = g.Render(graph, graphviz.SVG, &buf); err != nil {
		fatal(err)
	}

	fmt.Println("writing SVG to out.svg")
	if err := g.RenderFilename(graph, graphviz.SVG, "out.svg"); err != nil {
		fatal(err)
	}

}

func parse(graph *cgraph.Graph, st *strategy.Strategy) error {
	inbound, err := graph.CreateNode("inbound")
	if err != nil {
		return err
	}

	for i, at := range st.Inbound {
		node, err := parseActionTree(graph, at)
		if err != nil {
			return err
		}
		_, err = graph.CreateEdge(name("e"), inbound, node)
		if err != nil {
			return err
		}
		fmt.Printf("action tree %d sucessful\n", i)
	}

	return nil
}

func parseActionTree(graph *cgraph.Graph, at *actions.ActionTree) (*cgraph.Node, error) {
	fmt.Printf("trigger: %s\n", at.Trigger.String())

	trigger, err := graph.CreateNode(name("trigger"))
	if err != nil {
		return nil, err
	}
	trigger.SetShape("Mrecord")
	trigger.SetLabel(fmt.Sprintf("trigger|{%s}", at.Trigger.String()))

	fmt.Printf("root action: %s\n", at.RootAction.String())
	node, err := parseAction(graph, at.RootAction)
	if err != nil {
		return nil, err
	}

	fmt.Println("parsed action tree!")

	if _, err := graph.CreateEdge("e", trigger, node); err != nil {
		return nil, err
	}

	return trigger, nil
}

func parseAction(graph *cgraph.Graph, action actions.Action) (*cgraph.Node, error) {
	switch t := action.(type) {
	case *actions.SendAction:
		fmt.Println("send action")
		node, err := graph.CreateNode(name("send"))
		if err != nil {
			return nil, err
		}
		node.SetLabel("send")
		return node, nil
	case *actions.DropAction:
		fmt.Println("drop action")
		node, err := graph.CreateNode(name("drop"))
		if err != nil {
			return nil, err
		}
		node.SetLabel("drop")
		return node, nil
	case *actions.DuplicateAction:
		fmt.Printf("duplicate action: %s\n", t.String())
		return parseDuplicateAction(graph, t)
	case *actions.FragmentAction:
		fmt.Printf("fragment action: %s\n", t.String())
		return parseFragmentAction(graph, t)
	default:
		fmt.Println("wtf did you do")
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
