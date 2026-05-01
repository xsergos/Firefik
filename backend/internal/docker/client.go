package docker

import (
	"context"
	"fmt"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

const ContainerIDShortLen = 12

type Client struct {
	sdk *client.Client
}

type NetworkEndpoint struct {
	IP        string
	PrefixLen int
}

type ContainerInfo struct {
	ID       string
	Name     string
	Status   string
	Labels   map[string]string
	Networks map[string]NetworkEndpoint
}

func NewClient() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation()) //nolint:govet
	if err != nil {
		return nil, fmt.Errorf("create docker client: %w", err)
	}
	return &Client{sdk: cli}, nil
}

func (c *Client) Close() error {
	return c.sdk.Close()
}

func (c *Client) Inspect(ctx context.Context, id string) (ContainerInfo, bool, error) {
	res, err := c.sdk.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return ContainerInfo{}, false, nil
		}
		return ContainerInfo{}, false, fmt.Errorf("inspect %s: %w", id, err)
	}
	return inspectResponseToInfo(res.Container), true, nil
}

func inspectResponseToInfo(ins container.InspectResponse) ContainerInfo {
	name := strings.TrimPrefix(ins.Name, "/")

	networks := make(map[string]NetworkEndpoint)
	if ins.NetworkSettings != nil {
		for netName, ep := range ins.NetworkSettings.Networks {
			if ep == nil || !ep.IPAddress.IsValid() {
				continue
			}
			networks[netName] = NetworkEndpoint{
				IP:        ep.IPAddress.String(),
				PrefixLen: ep.IPPrefixLen,
			}
		}
	}

	shortID := ins.ID
	if len(shortID) > ContainerIDShortLen {
		shortID = shortID[:ContainerIDShortLen]
	}

	status := ""
	if ins.State != nil {
		status = string(ins.State.Status)
	}

	var labels map[string]string
	if ins.Config != nil {
		labels = ins.Config.Labels
	}

	return ContainerInfo{
		ID:       shortID,
		Name:     name,
		Status:   status,
		Labels:   labels,
		Networks: networks,
	}
}

func (c *Client) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	ctrs, err := c.sdk.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	return summariesToInfos(ctrs.Items), nil
}

func summariesToInfos(items []container.Summary) []ContainerInfo {
	result := make([]ContainerInfo, 0, len(items))
	for _, ctr := range items {
		result = append(result, summaryToInfo(ctr))
	}
	return result
}

func summaryToInfo(ctr container.Summary) ContainerInfo {
	name := ""
	if len(ctr.Names) > 0 {
		name = strings.TrimPrefix(ctr.Names[0], "/")
	}

	networks := make(map[string]NetworkEndpoint)
	if ctr.NetworkSettings != nil {
		for netName, ep := range ctr.NetworkSettings.Networks {
			if ep != nil && ep.IPAddress.IsValid() {
				networks[netName] = NetworkEndpoint{
					IP:        ep.IPAddress.String(),
					PrefixLen: ep.IPPrefixLen,
				}
			}
		}
	}

	id := ctr.ID
	if len(id) > ContainerIDShortLen {
		id = id[:ContainerIDShortLen]
	}

	return ContainerInfo{
		ID:       id,
		Name:     name,
		Status:   string(ctr.State),
		Labels:   ctr.Labels,
		Networks: networks,
	}
}
