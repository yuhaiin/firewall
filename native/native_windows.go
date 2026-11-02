//go:build windows && (amd64 || arm64)

package native

import (
	"context"
	fw "github.com/yuhaiin/firewall"
	"github.com/yuhaiin/firewall/backend/windows"
)

// Config configures the WFP owner, lifetime and optional automatic-start service.
type Config = windows.Config

// Open probes native state without installing a policy.
func Open(ctx context.Context, c Config) (*fw.Client, error) {
	d, err := windows.New(c)
	if err != nil {
		return nil, err
	}
	client, err := fw.New(ctx, d)
	if err != nil {
		_ = d.Close()
	}
	return client, err
}
