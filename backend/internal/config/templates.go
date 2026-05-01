package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type RuleTemplate struct {
	Name              string   `yaml:"name"              json:"name"`
	Description       string   `yaml:"description"       json:"description,omitempty"`
	Ports             []uint16 `yaml:"ports"             json:"ports,omitempty"`
	Protocol          string   `yaml:"protocol"          json:"protocol,omitempty"`
	Allowlist         []string `yaml:"allowlist"         json:"allowlist,omitempty"`
	Blocklist         []string `yaml:"blocklist"         json:"blocklist,omitempty"`
	AllowlistNetworks []string `yaml:"allowlistNetworks" json:"allowlistNetworks,omitempty"`
	BlocklistNetworks []string `yaml:"blocklistNetworks" json:"blocklistNetworks,omitempty"`
	GeoBlock          []string `yaml:"geoblock"          json:"geoblock,omitempty"`
	GeoAllow          []string `yaml:"geoallow"          json:"geoallow,omitempty"`
	Ratelimit         string   `yaml:"ratelimit"         json:"ratelimit,omitempty"`
	Profile           string   `yaml:"profile"           json:"profile,omitempty"`
	Log               bool     `yaml:"log"               json:"log,omitempty"`
	LogPrefix         string   `yaml:"logPrefix"         json:"logPrefix,omitempty"`
	Version           string   `yaml:"-"                 json:"version"`
}

type TemplateBundle struct {
	Templates []RuleTemplate `yaml:"templates"`
}

func LoadTemplates(path string) (map[string]RuleTemplate, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read templates %s: %w", path, err)
	}
	return parseTemplateBytes(data)
}

func parseTemplateBytes(data []byte) (map[string]RuleTemplate, error) {
	var bundle TemplateBundle
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	out := make(map[string]RuleTemplate, len(bundle.Templates))
	for i, t := range bundle.Templates {
		if t.Name == "" {
			return nil, fmt.Errorf("template #%d has no name", i)
		}
		if _, dup := out[t.Name]; dup {
			return nil, fmt.Errorf("duplicate template name %q", t.Name)
		}
		t.Version = canonicalVersion(t)
		out[t.Name] = t
	}
	return out, nil
}

func canonicalVersion(t RuleTemplate) string {

	b := &strings.Builder{}
	write := func(k string, vs []string) {
		if len(vs) == 0 {
			return
		}
		cp := make([]string, len(vs))
		copy(cp, vs)
		sort.Strings(cp)
		fmt.Fprintf(b, "%s=%s\n", k, strings.Join(cp, ","))
	}
	writePorts := func(k string, vs []uint16) {
		if len(vs) == 0 {
			return
		}
		cp := make([]int, 0, len(vs))
		for _, v := range vs {
			cp = append(cp, int(v))
		}
		sort.Ints(cp)
		parts := make([]string, len(cp))
		for i, v := range cp {
			parts[i] = fmt.Sprintf("%d", v)
		}
		fmt.Fprintf(b, "%s=%s\n", k, strings.Join(parts, ","))
	}
	fmt.Fprintf(b, "name=%s\nproto=%s\nprofile=%s\nratelimit=%s\nlog=%v\nlog_prefix=%s\n",
		t.Name, t.Protocol, t.Profile, t.Ratelimit, t.Log, t.LogPrefix)
	writePorts("ports", t.Ports)
	write("allow", t.Allowlist)
	write("block", t.Blocklist)
	write("allow_nets", t.AllowlistNetworks)
	write("block_nets", t.BlocklistNetworks)
	write("geoblock", t.GeoBlock)
	write("geoallow", t.GeoAllow)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:16]
}

const TemplateLabel = "firefik.template"

func ResolveTemplateNames(labelValue string) []string {
	if labelValue == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, p := range strings.Split(labelValue, ",") {
		name := strings.TrimSpace(p)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
