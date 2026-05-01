package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

func cmdReconcile(args []string) error {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	g := parseGlobals(fs)
	configFile := fs.String("rules-file", "", "path to rules file (defaults to FIREFIK_CONFIG if set)")
	timeout := fs.Duration("timeout", 60*time.Second, "overall reconcile timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	backend, _, err := resolveBackendFn(g, true)
	if err != nil {
		return err
	}

	dockerClient, err := docker.NewClient()
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer dockerClient.Close()

	cfg := config.Load()
	cfg.ChainName = g.chain
	cfg.ParentChain = g.parent
	cfg.EffectiveChain = g.chain
	if *configFile != "" {
		cfg.ConfigFile = config.SafePath(*configFile)
		if cfg.ConfigFile == "" {
			return fmt.Errorf("rules-file %q rejected by SafePath", *configFile)
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	engine := rules.NewEngine(backend, dockerClient, cfg, logger)
	defer engine.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := engine.Rehydrate(ctx); err != nil {
		logger.Warn("rehydrate failed (continuing with empty state)", "error", err)
	}

	start := time.Now()
	if err := engine.Reconcile(ctx, audit.SourceManual); err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	fmt.Printf("reconcile ok in %s\n", time.Since(start).Round(time.Millisecond))
	return nil
}
