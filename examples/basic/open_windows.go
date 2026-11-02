//go:build windows && (amd64 || arm64)

package main

import (
	"context"
	fw "github.com/yuhaiin/firewall"
	"github.com/yuhaiin/firewall/native"
	"os"
)

func open(ctx context.Context) (*fw.Client, error) {
	return native.Open(ctx, native.Config{Owner: "firewall-example", Lifetime: fw.Persistent, PersistentService: os.Getenv("FIREWALL_WINDOWS_SERVICE")})
}
