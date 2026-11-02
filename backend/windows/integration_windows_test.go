//go:build windows && (amd64 || arm64)

package windows

import (
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	fw "github.com/yuhaiin/firewall"
)

func TestNativeWFP(t *testing.T) {
	if os.Getenv("FIREWALL_WFP_TEST") != "1" {
		t.Skip("set FIREWALL_WFP_TEST=1 only in a disposable elevated Windows runner")
	}
	cfg := Config{Owner: "integration-test", Lifetime: fw.Temporary}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c, err := fw.New(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if other, err := New(cfg); !errors.Is(err, fw.ErrOwnership) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("ownership: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// This test only blocks this test executable's loopback port. It never
	// installs a machine-wide default-deny or touches another provider.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	p := fw.Policy{Lifetime: fw.Temporary, Defaults: map[fw.Direction]fw.Action{fw.Outbound: fw.Allow}, Rules: []fw.Rule{{ID: "app-block", Direction: fw.Outbound, Family: fw.IPv4, Action: fw.Drop, When: fw.All(fw.Is(fw.Match{Field: fw.Application, Text: executable}), fw.Is(fw.Match{Field: fw.Protocol, Number: 6}), fw.Is(fw.Match{Field: fw.DestinationPort, Ports: fw.PortRange{First: port, Last: port}}))}}}
	r, err := c.Apply(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp4", l.Addr().String(), 500*time.Millisecond)
	if err == nil {
		conn.Close()
		key := guid(cfg.Owner, "app-block/ipv4/0")
		var installed *filter
		if e := call(filterGet, uintptr(b.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&installed))); e == nil {
			t.Logf("native filter: layer=%s flags=%x action=%x count=%d weight type=%d", installed.Layer, installed.Flags, installed.Action.Type, installed.Count, installed.Weight.Type)
			for _, c := range unsafe.Slice(installed.Conditions, installed.Count) {
				t.Logf("native condition: field=%s op=%d type=%d data=%x", c.Field, c.Op, c.Value.Type, c.Value.Data)
			}
			t.Logf("executable=%s", executable)
			release(&installed)
		} else {
			t.Logf("get installed filter: %v", e)
		}
		// Separate application-identity mismatch from loopback arbitration.
		p.Rules[0].When = fw.All(fw.Is(fw.Match{Field: fw.Protocol, Number: 6}), fw.Is(fw.Match{Field: fw.DestinationPort, Ports: fw.PortRange{First: port, Last: port}}))
		if _, e := c.Apply(t.Context(), p); e != nil {
			t.Logf("port-only installation: %v", e)
		} else {
			x, e := net.DialTimeout("tcp4", l.Addr().String(), 500*time.Millisecond)
			if x != nil {
				x.Close()
			}
			t.Logf("port-only loopback verdict: %v", e)
		}
		p.Rules[0].When = fw.All(fw.Is(fw.Match{Field: fw.Application, Text: executable}), fw.Is(fw.Match{Field: fw.Protocol, Number: 6}), fw.Is(fw.Match{Field: fw.DestinationPrefix, Prefix: netip.MustParsePrefix("192.0.2.123/32")}))
		if _, e := c.Apply(t.Context(), p); e != nil {
			t.Logf("remote installation: %v", e)
		} else {
			x, e := net.DialTimeout("tcp4", "192.0.2.123:54321", 500*time.Millisecond)
			if x != nil {
				x.Close()
			}
			t.Logf("application remote verdict: %v (access denied=%t)", e, errors.Is(e, windows.WSAEACCES))
		}
		t.Fatal("application WFP drop did not enforce")
	}
	state, err := c.Current(t.Context())
	if err != nil || !state.Active || state.Revision != r {
		t.Fatalf("native state %+v %v", state, err)
	}
	// Reject during a real native transaction must preserve the old provider.
	err = b.transaction(t.Context(), func() error {
		if err := b.deleteOwned(); err != nil {
			return err
		}
		return errors.New("injected transaction abort")
	})
	if err == nil {
		t.Fatal("expected abort")
	}
	state, err = c.Current(t.Context())
	if err != nil || state.Revision != r {
		t.Fatalf("transaction rollback %+v %v", state, err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	b2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	s, err := b2.Inspect(t.Context())
	if err != nil || s.Active {
		t.Fatalf("dynamic cleanup %+v %v", s, err)
	}
}
