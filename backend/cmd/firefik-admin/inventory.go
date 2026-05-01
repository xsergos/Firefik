package main

import (
	"flag"
	"fmt"
	"os"
)

type inventoryReport struct {
	Backend           string   `json:"backend"`
	Chain             string   `json:"chain"`
	Parent            string   `json:"parent"`
	TrackedContainers int      `json:"tracked_containers"`
	ContainerShortIDs []string `json:"container_short_ids"`
}

func cmdInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
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
	rep := inventoryReport{
		Backend:           kind,
		Chain:             g.chain,
		Parent:            g.parent,
		TrackedContainers: len(ids),
		ContainerShortIDs: ids,
	}
	if g.output == "json" {
		return writeJSON(os.Stdout, rep)
	}
	fmt.Printf("backend: %s\nchain:   %s\ntracked containers: %d\n", rep.Backend, rep.Chain, rep.TrackedContainers)
	for _, id := range ids {
		fmt.Println("  -", id)
	}
	return nil
}
