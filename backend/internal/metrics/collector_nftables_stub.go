//go:build !linux

package metrics

func NewNFTablesCollector(chainName string) (*NFTablesCollector, error) {
	return nil, nil
}

type NFTablesCollector struct{}
