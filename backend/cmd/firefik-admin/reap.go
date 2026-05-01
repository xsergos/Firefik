package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"firefik/internal/config"
	"firefik/internal/rules"
)

type reapReport struct {
	Backend       string   `json:"backend"`
	Chain         string   `json:"chain"`
	Suffix        string   `json:"suffix"`
	LegacyChain   string   `json:"legacy_chain"`
	DryRun        bool     `json:"dry_run"`
	ContainerIDs  []string `json:"container_ids"`
	ChainsRemoved int      `json:"chains_removed"`
	WouldRemove   int      `json:"would_remove,omitempty"`
}

func cmdReap(args []string) error {
	fs := flag.NewFlagSet("reap", flag.ContinueOnError)
	g := parseGlobals(fs)
	suffix := fs.String("suffix", "", "legacy chain suffix to reap (required)")
	dryRun := fs.Bool("dry-run", false, "list chains that would be removed, do not touch them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *suffix == "" {
		return fmt.Errorf("--suffix is required")
	}
	if err := config.ValidateSuffix(*suffix); err != nil {
		return err
	}
	if isSystemChain(g.chain) || isSystemChain(g.chain+"-"+*suffix) {
		return fmt.Errorf("refusing to reap system chain")
	}

	legacy := config.DeriveLegacyChains(g.chain, g.chain, []string{*suffix})
	if len(legacy) == 0 {
		return fmt.Errorf("no legacy chain derived from suffix %q", *suffix)
	}
	legacyChain := legacy[0]

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	backend, kind, err := newBackendForChainFn(g, legacyChain, logger)
	if err != nil {
		return err
	}

	ids, err := backend.ListAppliedContainerIDs()
	if err != nil {
		return fmt.Errorf("enumerate chains for %s: %w", legacyChain, err)
	}

	rep := reapReport{
		Backend:      kind,
		Chain:        g.chain,
		Suffix:       *suffix,
		LegacyChain:  legacyChain,
		DryRun:       *dryRun,
		ContainerIDs: ids,
	}

	if *dryRun {
		rep.WouldRemove = len(ids)
	} else {
		if err := backend.Cleanup(); err != nil {
			return fmt.Errorf("reap %s: %w", legacyChain, err)
		}
		rep.ChainsRemoved = len(ids)
	}

	if g.output == "json" {
		return writeJSON(os.Stdout, rep)
	}
	if *dryRun {
		fmt.Printf("dry-run: would remove %d container chain(s) under %s (backend %s)\n",
			len(ids), legacyChain, kind)
		for _, id := range ids {
			fmt.Println("  -", id)
		}
		return nil
	}
	fmt.Printf("reaped %d container chain(s) under %s (backend %s)\n", len(ids), legacyChain, kind)
	return nil
}

var newBackendForChainFn = newBackendForChain

func newBackendForChain(g *globalFlags, chain string, logger *slog.Logger) (rules.Backend, string, error) {
	backend := g.backend
	if backend == "auto" {
		backend = rules.DetectBackendType()
	}
	switch strings.ToLower(backend) {
	case "nftables":
		b, err := rules.NewNFTablesBackend(chain, logger)
		if err != nil {
			return nil, backend, fmt.Errorf("init nftables: %w", err)
		}
		if err := b.SetupChains(); err != nil {
			return nil, backend, fmt.Errorf("nftables setup: %w", err)
		}
		return b, backend, nil
	default:
		b, err := rules.NewIPTablesBackend(chain, g.parent)
		if err != nil {
			return nil, backend, fmt.Errorf("init iptables: %w", err)
		}
		return b, backend, nil
	}
}
