package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	g := parseGlobals(fs)
	apiURL := fs.String("api", "http://127.0.0.1", "firefik base URL (no trailing slash)")
	token := fs.String("token", "", "bearer token (overrides $FIREFIK_API_TOKEN)")
	timeout := fs.Duration("timeout", 5*time.Second, "HTTP timeout")
	policyName := fs.String("policy", "", "policy name to explain (required unless --policy-file)")
	policyFile := fs.String("policy-file", "", "explain a DSL file that is not yet saved (dry-run)")
	containerID := fs.String("container", "", "container id or unambiguous prefix")
	packet := fs.String("packet", "", "optional synthetic packet in the form 'proto src-ip:src-port -> :dst-port'")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *containerID == "" {
		return fmt.Errorf("--container is required")
	}
	if *policyName == "" && *policyFile == "" {
		return fmt.Errorf("either --policy or --policy-file is required")
	}

	authToken := *token
	if authToken == "" {
		authToken = os.Getenv("FIREFIK_API_TOKEN")
	}

	reqBody := map[string]any{"containerID": *containerID}
	if *policyFile != "" {
		dsl, err := os.ReadFile(*policyFile)
		if err != nil {
			return fmt.Errorf("read policy file: %w", err)
		}
		reqBody["dsl"] = string(dsl)
	}
	name := *policyName
	if name == "" {
		name = "inline"
	}
	body, _ := json.Marshal(reqBody)

	url := strings.TrimSuffix(*apiURL, "/") + "/api/policies/" + name + "/simulate"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call simulate: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("simulate returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out simulateResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("decode simulate response: %w", err)
	}

	if g.output == "json" {
		type tracedOut struct {
			simulateResponse
			Trace *firstMatch `json:"firstMatch,omitempty"`
		}
		wrapped := tracedOut{simulateResponse: out}
		if *packet != "" {
			if trace, err := firstMatchFromPacket(*packet, out.RuleSets); err != nil {
				fmt.Fprintln(os.Stderr, "trace warning:", err)
			} else {
				wrapped.Trace = trace
			}
		}
		return writeJSON(os.Stdout, wrapped)
	}

	fmt.Printf("policy:        %s\n", out.Policy)
	if out.Container != "" {
		fmt.Printf("container:     %s\n", out.Container)
	}
	if out.DefaultPolicy != "" {
		fmt.Printf("default-policy: %s\n", out.DefaultPolicy)
	}
	fmt.Printf("rule-sets:     %d\n", len(out.RuleSets))
	for i, rs := range out.RuleSets {
		fmt.Printf("\n  [%d] %s (%s)\n", i, rs.Name, rs.Protocol)
		if len(rs.Ports) > 0 {
			fmt.Printf("      ports:     %v\n", rs.Ports)
		}
		if len(rs.Allowlist) > 0 {
			fmt.Printf("      allowlist: %s\n", strings.Join(rs.Allowlist, ", "))
		}
		if len(rs.Blocklist) > 0 {
			fmt.Printf("      blocklist: %s\n", strings.Join(rs.Blocklist, ", "))
		}
		if len(rs.GeoAllow) > 0 {
			fmt.Printf("      geoallow:  %v\n", rs.GeoAllow)
		}
		if len(rs.GeoBlock) > 0 {
			fmt.Printf("      geoblock:  %v\n", rs.GeoBlock)
		}
		if rs.Log {
			fmt.Printf("      log:       yes (prefix=%q)\n", rs.LogPrefix)
		}
	}
	for _, w := range out.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	for _, e := range out.Errors {
		fmt.Fprintln(os.Stderr, "error:  ", e)
	}

	if *packet != "" {
		trace, err := firstMatchFromPacket(*packet, out.RuleSets)
		if err != nil {
			fmt.Fprintln(os.Stderr, "trace warning:", err)
		} else if trace == nil {
			fmt.Printf("\ntrace:\n  no rule-set matched — packet would hit default policy (%s)\n",
				out.DefaultPolicy,
			)
		} else {
			fmt.Printf("\ntrace:\n  matched rule-set %d (%s) via %s\n",
				trace.Index, trace.Name, trace.Reason,
			)
		}
	}
	return nil
}

type simulateRuleSet struct {
	Name      string   `json:"name"`
	Ports     []int    `json:"ports"`
	Protocol  string   `json:"protocol,omitempty"`
	Allowlist []string `json:"allowlist"`
	Blocklist []string `json:"blocklist"`
	GeoAllow  []string `json:"geoAllow,omitempty"`
	GeoBlock  []string `json:"geoBlock,omitempty"`
	Log       bool     `json:"log,omitempty"`
	LogPrefix string   `json:"logPrefix,omitempty"`
}

type simulateResponse struct {
	Policy        string            `json:"policy"`
	Container     string            `json:"container,omitempty"`
	DefaultPolicy string            `json:"defaultPolicy,omitempty"`
	RuleSets      []simulateRuleSet `json:"ruleSets"`
	Warnings      []string          `json:"warnings,omitempty"`
	Errors        []string          `json:"errors,omitempty"`
	LabelsSeen    map[string]string `json:"labelsSeen,omitempty"`
}

type firstMatch struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func firstMatchFromPacket(pkt string, sets []simulateRuleSet) (*firstMatch, error) {

	parts := strings.Fields(pkt)
	if len(parts) < 4 {
		return nil, fmt.Errorf("packet must look like: tcp 1.2.3.4:33221 -> :443")
	}
	proto := strings.ToLower(parts[0])

	dst := parts[3]
	if !strings.HasPrefix(dst, ":") {
		return nil, fmt.Errorf("destination must be :PORT (src-host is implicit)")
	}
	dstPort := 0
	if _, err := fmt.Sscanf(strings.TrimPrefix(dst, ":"), "%d", &dstPort); err != nil {
		return nil, fmt.Errorf("bad dst port: %w", err)
	}
	for i, rs := range sets {
		if rs.Protocol != "" && strings.ToLower(rs.Protocol) != proto {
			continue
		}
		portOK := len(rs.Ports) == 0
		for _, p := range rs.Ports {
			if p == dstPort {
				portOK = true
				break
			}
		}
		if !portOK {
			continue
		}
		return &firstMatch{
			Index:  i,
			Name:   rs.Name,
			Reason: fmt.Sprintf("proto=%s port=%d", proto, dstPort),
		}, nil
	}
	return nil, nil
}
