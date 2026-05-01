package policy

import (
	"fmt"
	"os"
	"path/filepath"
)

func LoadDir(path string) (map[string]*Policy, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return LoadFile(path)
	}
	out := map[string]*Policy{}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".policy" {
			continue
		}
		full := filepath.Join(path, e.Name())
		parsed, err := LoadFile(full)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", full, err)
		}
		for name, pol := range parsed {
			if _, dup := out[name]; dup {
				return nil, fmt.Errorf("duplicate policy name %q (seen again in %s)", name, full)
			}
			pol.Source = full
			out[name] = pol
		}
	}
	return out, nil
}

func LoadFile(path string) (map[string]*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pols, err := Parse(string(data))
	if err != nil {
		return nil, err
	}
	out := make(map[string]*Policy, len(pols))
	for _, p := range pols {
		if _, dup := out[p.Name]; dup {
			return nil, fmt.Errorf("duplicate policy name %q in %s", p.Name, path)
		}
		p.Source = path
		out[p.Name] = p
	}
	return out, nil
}
