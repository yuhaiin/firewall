package native

import (
	"context"
	fw "github.com/yuhaiin/firewall"
	"github.com/yuhaiin/firewall/backend/darwin"
)

// Config selects the signed Network Extension host executable and private lock.
type Config = darwin.Config

// Open probes native state without installing a policy.
func Open(ctx context.Context, c Config) (*fw.Client, error) {
	d, err := darwin.New(c)
	if err != nil {
		return nil, err
	}
	client, err := fw.New(ctx, d)
	if err != nil {
		_ = d.Close()
	}
	return client, err
}
