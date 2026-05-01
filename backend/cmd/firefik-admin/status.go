package main

import (
	"flag"
	"fmt"
	"os"
)

type statusReport struct {
	Backend         string `json:"backend"`
	Chain           string `json:"chain"`
	Parent          string `json:"parent"`
	ContainerChains int    `json:"container_chains"`
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	g := parseGlobals(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	backend, kind, err := resolveBackendFn(g, false)
	if err != nil {
		return err
	}
	ids, err := backend.ListAppliedContainerIDs()
	if err != nil {
		return fmt.Errorf("enumerate chains: %w", err)
	}
	rep := statusReport{
		Backend:         kind,
		Chain:           g.chain,
		Parent:          g.parent,
		ContainerChains: len(ids),
	}
	if g.output == "json" {
		return writeJSON(os.Stdout, rep)
	}
	fmt.Printf("backend:           %s\n", rep.Backend)
	fmt.Printf("chain:             %s\n", rep.Chain)
	fmt.Printf("parent chain:      %s\n", rep.Parent)
	fmt.Printf("container chains:  %d\n", rep.ContainerChains)
	return nil
}
