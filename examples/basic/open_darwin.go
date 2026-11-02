package main

import (
	"context"
	fw "github.com/yuhaiin/firewall"
	"github.com/yuhaiin/firewall/native"
	"os"
)

func open(ctx context.Context) (*fw.Client, error) {
	return native.Open(ctx, native.Config{Owner: "firewall-example", HostExecutable: os.Getenv("FIREWALL_HOST_EXECUTABLE"), LockDir: os.Getenv("FIREWALL_LOCK_DIR")})
}
