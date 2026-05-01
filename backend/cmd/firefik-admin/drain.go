package main

import (
	"flag"
	"fmt"
	"os"

	"firefik/internal/rules"
)

func cmdDrain(args []string) error {
	fs := flag.NewFlagSet("drain", flag.ContinueOnError)
	g := parseGlobals(fs)
	confirm := fs.Bool("confirm", false, "skip interactive confirmation")
	yes := fs.Bool("yes", false, "alias for --confirm")
	keepParent := fs.Bool("keep-parent-jump", false, "leave the DOCKER-USER jump rule in place (blue/green rollback mode)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if isSystemChain(g.chain) {
		return fmt.Errorf("refusing to drain system chain %q", g.chain)
	}
	backend, kind, err := resolveBackendFn(g, true)
	if err != nil {
		return err
	}

	ids, err := backend.ListAppliedContainerIDs()
	if err != nil {
		return fmt.Errorf("enumerate chains: %w", err)
	}
	if len(ids) == 0 && *keepParent {
		fmt.Println("no container chains present")
		return nil
	}

	if !*confirm && !*yes {
		fmt.Printf("drain will remove %d container chain(s) from backend %s (chain %q).\n", len(ids), kind, g.chain)
		if !*keepParent {
			fmt.Printf("will ALSO drop the parent-chain jump and delete the base chain %q.\n", g.chain)
		}
		if err := promptDelete(os.Stdin); err != nil {
			return err
		}
	}

	var removeErrs int
	for i, id := range ids {
		fmt.Printf("  [%d/%d] removing container chain %s …\n", i+1, len(ids), id)
		if err := backend.RemoveContainerChains(id); err != nil {
			fmt.Fprintf(os.Stderr, "    error: %v\n", err)
			removeErrs++
		}
	}

	if !*keepParent {
		fmt.Printf("  tearing down base chain %q …\n", g.chain)
		if err := backend.Cleanup(); err != nil {
			return fmt.Errorf("base chain teardown: %w", err)
		}
	}

	if removeErrs > 0 {
		return fmt.Errorf("drain completed with %d error(s)", removeErrs)
	}
	fmt.Printf("drained %d chain(s); parent jump %s\n",
		len(ids), keepParentSummary(*keepParent))
	return nil
}

func keepParentSummary(keep bool) string {
	if keep {
		return "retained"
	}
	return "removed"
}

var _ = rules.Backend(nil)
