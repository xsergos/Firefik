package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type diffReport struct {
	Backend    string   `json:"backend"`
	Chain      string   `json:"chain"`
	ApiURL     string   `json:"api_url"`
	OrphanIDs  []string `json:"orphan_ids"`
	MissingIDs []string `json:"missing_ids"`
	Drift      bool     `json:"drift"`
}

type apiRuleEntry struct {
	ContainerID string `json:"containerID"`
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	g := parseGlobals(fs)
	apiURL := fs.String("api", "http://127.0.0.1/api/rules", "URL of the /api/rules endpoint on the running firefik")
	token := fs.String("token", "", "bearer token (overrides $FIREFIK_API_TOKEN)")
	timeout := fs.Duration("timeout", 5*time.Second, "HTTP timeout for the API call")
	if err := fs.Parse(args); err != nil {
		return err
	}

	authToken := *token
	if authToken == "" {
		authToken = os.Getenv("FIREFIK_API_TOKEN")
	}

	memIDs, err := fetchAPIContainerIDs(*apiURL, authToken, *timeout)
	if err != nil {
		return fmt.Errorf("fetch in-memory state: %w", err)
	}

	backend, kind, err := resolveBackendFn(g, false)
	if err != nil {
		return err
	}
	kernelIDs, err := backend.ListAppliedContainerIDs()
	if err != nil {
		return fmt.Errorf("enumerate kernel chains: %w", err)
	}

	memSet := map[string]struct{}{}
	for _, id := range memIDs {
		memSet[id] = struct{}{}
	}
	kernelSet := map[string]struct{}{}
	for _, id := range kernelIDs {
		kernelSet[id] = struct{}{}
	}

	rep := diffReport{
		Backend: kind,
		Chain:   g.chain,
		ApiURL:  *apiURL,
	}
	for id := range kernelSet {
		if _, ok := memSet[id]; !ok {
			rep.OrphanIDs = append(rep.OrphanIDs, id)
		}
	}
	for id := range memSet {
		if _, ok := kernelSet[id]; !ok {
			rep.MissingIDs = append(rep.MissingIDs, id)
		}
	}
	sort.Strings(rep.OrphanIDs)
	sort.Strings(rep.MissingIDs)
	rep.Drift = len(rep.OrphanIDs) > 0 || len(rep.MissingIDs) > 0

	if g.output == "json" {
		if err := writeJSON(os.Stdout, rep); err != nil {
			return err
		}
	} else {
		fmt.Printf("backend:  %s\n", rep.Backend)
		fmt.Printf("chain:    %s\n", rep.Chain)
		fmt.Printf("api:      %s\n", rep.ApiURL)
		fmt.Printf("drift:    %v\n", rep.Drift)
		fmt.Printf("orphan (in kernel, not in API memory): %d\n", len(rep.OrphanIDs))
		for _, id := range rep.OrphanIDs {
			fmt.Println("  -", id)
		}
		fmt.Printf("missing (in API memory, not in kernel): %d\n", len(rep.MissingIDs))
		for _, id := range rep.MissingIDs {
			fmt.Println("  -", id)
		}
	}
	if rep.Drift {
		return fmt.Errorf("drift detected")
	}
	return nil
}

func fetchAPIContainerIDs(url, token string, timeout time.Duration) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: timeout}
	if strings.HasPrefix(url, "unix://") {
		return nil, fmt.Errorf("unix:// API URLs not supported yet; use http://host/api/rules or TCP listener")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var entries []apiRuleEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.ContainerID != "" {
			ids = append(ids, e.ContainerID)
		}
	}
	return ids, nil
}
