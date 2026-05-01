package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func cmdForceReset(args []string) error {
	fs := flag.NewFlagSet("force-reset", flag.ContinueOnError)
	g := parseGlobals(fs)
	confirm := fs.Bool("confirm", false, "confirm destruction without stdin prompt")
	yes := fs.Bool("yes", false, "alias for --confirm")
	dangerousOK := fs.Bool("allow-system-chain", false, "required when --chain names a system chain (DOCKER-*, INPUT, OUTPUT, FORWARD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if isSystemChain(g.chain) && !*dangerousOK {
		return fmt.Errorf("refusing to reset system chain %q without --allow-system-chain", g.chain)
	}
	backend, kind, err := resolveBackendFn(g, true)
	if err != nil {
		return err
	}
	ids, err := backend.ListAppliedContainerIDs()
	if err != nil {
		return fmt.Errorf("enumerate chains: %w", err)
	}
	if len(ids) == 0 {
		fmt.Println("no firefik chains present, nothing to do")
		return nil
	}
	fmt.Printf("WARNING: this will REMOVE %d firefik container chain(s) on backend %s (chain prefix %q).\n",
		len(ids), kind, g.chain)
	for _, id := range ids {
		fmt.Println("  -", id)
	}
	if !(*confirm || *yes) {
		if err := promptDelete(os.Stdin); err != nil {
			return err
		}
	}
	for _, id := range ids {
		if err := backend.RemoveContainerChains(id); err != nil {
			fmt.Fprintf(os.Stderr, "remove %s: %v\n", id, err)
		}
	}
	fmt.Printf("removed %d container chains\n", len(ids))
	return nil
}

func promptDelete(r io.Reader) error {
	fmt.Print("Type 'DELETE' to proceed, anything else aborts: ")
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if errors.Is(err, io.EOF) && strings.TrimSpace(line) == "" {
		return fmt.Errorf("no terminal attached for confirmation prompt; pass --confirm or --yes in automation")
	}
	if strings.TrimSpace(line) != "DELETE" {
		return fmt.Errorf("aborted by user")
	}
	return nil
}
