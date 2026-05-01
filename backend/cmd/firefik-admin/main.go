package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"firefik/internal/rules"
)

const (
	defaultChain  = "FIREFIK"
	defaultParent = "DOCKER-USER"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "firefik-admin:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command specified")
	}
	switch args[0] {
	case "inventory":
		return cmdInventory(args[1:])
	case "force-reset":
		return cmdForceReset(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "check":
		return cmdCheck(args[1:])
	case "drain":
		return cmdDrain(args[1:])
	case "reconcile":
		return cmdReconcile(args[1:])
	case "reap":
		return cmdReap(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "diff":
		return cmdDiff(args[1:])
	case "explain":
		return cmdExplain(args[1:])
	case "enroll":
		return cmdEnroll(args[1:])
	case "metrics-audit":
		return cmdMetricsAudit(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: firefik-admin <command> [flags]")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  inventory     list tracked container chains")
	fmt.Fprintln(os.Stderr, "  status        summarise backend + chain count")
	fmt.Fprintln(os.Stderr, "  check         report kernel-side drift (exit != 0 on drift)")
	fmt.Fprintln(os.Stderr, "  drain         remove every firefik container chain (honours --keep-parent-jump)")
	fmt.Fprintln(os.Stderr, "  reconcile     run engine.Reconcile locally against the docker daemon")
	fmt.Fprintln(os.Stderr, "  reap          remove legacy blue/green chains by --suffix (supports --dry-run)")
	fmt.Fprintln(os.Stderr, "  doctor        run environmental pre-flight checks (kernel modules, caps, docker socket, GeoIP age)")
	fmt.Fprintln(os.Stderr, "  diff          compare /api/rules in-memory state vs kernel chains; exit 1 on drift")
	fmt.Fprintln(os.Stderr, "  explain       show compiled policy rule-sets for a container (optional --packet trace)")
	fmt.Fprintln(os.Stderr, "  enroll        request/renew mTLS client cert from firefik-server /v1/enroll")
	fmt.Fprintln(os.Stderr, "  metrics-audit report per-metric cardinality from a /metrics endpoint or file")
	fmt.Fprintln(os.Stderr, "  force-reset   remove all firefik chains (requires --confirm)")
	fmt.Fprintln(os.Stderr, "global flags:")
	fmt.Fprintln(os.Stderr, "  --chain        chain name (default FIREFIK)")
	fmt.Fprintln(os.Stderr, "  --parent       parent iptables chain (default DOCKER-USER)")
	fmt.Fprintln(os.Stderr, "  --backend      iptables|nftables|auto (default auto)")
	fmt.Fprintln(os.Stderr, "  --output       text (default) | json  (inventory/status/check)")
}

type globalFlags struct {
	chain   string
	parent  string
	backend string
	output  string
}

func parseGlobals(fs *flag.FlagSet) *globalFlags {
	g := &globalFlags{}
	fs.StringVar(&g.chain, "chain", defaultChain, "firefik chain name")
	fs.StringVar(&g.parent, "parent", defaultParent, "parent iptables chain")
	fs.StringVar(&g.backend, "backend", "auto", "iptables|nftables|auto")
	fs.StringVar(&g.output, "output", "text", "text|json")
	return g
}

var resolveBackendFn = resolveBackend

func resolveBackend(g *globalFlags, setup bool) (rules.Backend, string, error) {
	backend := g.backend
	if backend == "auto" {
		backend = rules.DetectBackendType()
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	switch backend {
	case "nftables":
		b, err := rules.NewNFTablesBackend(g.chain, logger)
		if err != nil {
			return nil, backend, fmt.Errorf("init nftables: %w", err)
		}
		if setup {
			if err := b.SetupChains(); err != nil {
				return nil, backend, fmt.Errorf("nftables setup: %w", err)
			}
		}
		return b, backend, nil
	default:
		b, err := rules.NewIPTablesBackend(g.chain, g.parent)
		if err != nil {
			return nil, backend, fmt.Errorf("init iptables: %w", err)
		}
		if setup {
			if err := b.SetupChains(); err != nil {
				return nil, backend, fmt.Errorf("iptables setup: %w", err)
			}
		}
		return b, backend, nil
	}
}

func isSystemChain(chain string) bool {
	upper := strings.ToUpper(chain)
	switch upper {
	case "INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING",
		"DOCKER-USER", "DOCKER", "DOCKER-ISOLATION-STAGE-1", "DOCKER-ISOLATION-STAGE-2":
		return true
	}
	return strings.HasPrefix(upper, "DOCKER-") && !strings.HasPrefix(upper, "FIREFIK")
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
