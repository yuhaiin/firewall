package linux

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/unix"
)

func TestKernelLargePolicies(t *testing.T) {
	isolated(t)
	b := openTestBackend(t, t.TempDir())
	c, err := fw.New(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, n := range []int{100, 1000, 10000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			p := policy()
			p.Lifetime = fw.Temporary
			for i := range n {
				p.Rules = append(p.Rules, fw.Rule{ID: fmt.Sprintf("prefix-%05d", i), Family: fw.IPv4, Direction: fw.Outbound, Action: fw.Drop, When: fw.Is(fw.Match{Field: fw.DestinationPrefix, Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)})})
			}
			if _, err := c.Apply(t.Context(), p); err != nil {
				if errors.Is(err, unix.EMSGSIZE) || errors.Is(err, unix.ENOBUFS) {
					t.Skipf("kernel Netlink buffer limit (old policy preserved): %v", err)
				}
				t.Fatal(err)
			}
			state, err := c.Current(t.Context())
			if err != nil || !state.Active {
				t.Fatalf("large native policy state: %+v %v", state, err)
			}
		})
	}
}
