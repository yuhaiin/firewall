// Command benchmark-linux is the policy loader for scripts/bench-linux.sh.
// It deliberately refuses to run in the invoking host network namespace.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"

	fw "github.com/yuhaiin/firewall"
	"github.com/yuhaiin/firewall/native"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	n := flag.Int("rules", 100, "number of unmatched native forwarding rules")
	lock := flag.String("lock-dir", "", "private directory")
	ready := flag.String("ready", "", "new readiness file")
	flag.Parse()
	parent := os.Getenv("FIREWALL_BENCH_PARENT_NS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	if parent == "" || parent == current {
		return fmt.Errorf("refusing benchmark policy in invoking namespace; use scripts/bench-linux.sh")
	}
	if *n < 1 || *n > 10000 || *ready == "" {
		return fw.ErrInvalid
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	c, err := native.Open(ctx, native.Config{Owner: "native-throughput-benchmark", LockDir: *lock})
	if err != nil {
		return err
	}
	defer c.Close()
	p := fw.Policy{Lifetime: fw.Temporary, Defaults: map[fw.Direction]fw.Action{fw.Forward: fw.Allow}}
	for i := range *n {
		family := fw.IPv4
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 32)
		if i%2 == 1 {
			family = fw.IPv6
			prefix = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", i))
		}
		p.Rules = append(p.Rules, fw.Rule{ID: fmt.Sprintf("unmatched-%05d", i), Direction: fw.Forward, Family: family, Action: fw.Drop, When: fw.Is(fw.Match{Field: fw.DestinationPrefix, Prefix: prefix})})
	}
	if _, err = c.Apply(ctx, p); err != nil {
		return err
	}
	f, err := os.OpenFile(*ready, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
