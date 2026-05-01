//go:build !linux

package metrics

func NewIPTablesCollector(chainName string) (*IPTablesCollector, error) {
	return nil, nil
}

type IPTablesCollector struct{}
