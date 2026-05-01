package main

import (
	"flag"
	"fmt"
	"os"
)

type checkReport struct {
	Backend             string   `json:"backend"`
	Chain               string   `json:"chain"`
	Parent              string   `json:"parent"`
	BaseChainPresent    bool     `json:"base_chain_present"`
	ParentJumpPresent   bool     `json:"parent_jump_present"`
	ContainerChainCount int      `json:"container_chain_count"`
	Drift               bool     `json:"drift"`
	Notes               []string `json:"notes,omitempty"`
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	g := parseGlobals(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	backend, kind, err := resolveBackendFn(g, false)
	if err != nil {
		return err
	}

	health, err := backend.Healthy()
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	rep := checkReport{
		Backend:             kind,
		Chain:               g.chain,
		Parent:              g.parent,
		BaseChainPresent:    health.BaseChainPresent,
		ParentJumpPresent:   health.ParentJumpPresent,
		ContainerChainCount: health.ContainerChainCount,
		Notes:               health.Notes,
	}
	rep.Drift = !health.BaseChainPresent || !health.ParentJumpPresent

	if g.output == "json" {
		if err := writeJSON(os.Stdout, rep); err != nil {
			return err
		}
	} else {
		fmt.Printf("backend:              %s\n", rep.Backend)
		fmt.Printf("chain:                %s\n", rep.Chain)
		fmt.Printf("base chain present:   %v\n", rep.BaseChainPresent)
		fmt.Printf("parent jump present:  %v\n", rep.ParentJumpPresent)
		fmt.Printf("container chains:     %d\n", rep.ContainerChainCount)
		fmt.Printf("drift:                %v\n", rep.Drift)
		for _, n := range rep.Notes {
			fmt.Println("  note:", n)
		}
	}
	if rep.Drift {
		os.Exit(2)
	}
	return nil
}
