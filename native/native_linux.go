// Package native selects the host's native firewall backend.
package native

import (
	"context"
	fw "github.com/yuhaiin/firewall"
	"github.com/yuhaiin/firewall/backend/linux"
)

// Config configures the Linux owner and private lock directory.
type Config = linux.Config

// Open probes native state without installing a policy.
func Open(ctx context.Context, c Config) (*fw.Client, error) {
	d, err := linux.New(c)
	if err != nil {
		return nil, err
	}
	client, err := fw.New(ctx, d)
	if err != nil {
		_ = d.Release()
	}
	return client, err
}
