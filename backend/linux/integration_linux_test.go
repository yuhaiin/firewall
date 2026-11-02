package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/unix"
)

func isolated(t *testing.T) {
	t.Helper()
	if os.Getenv("FIREWALL_ISOLATED_TEST") != "1" {
		t.Skip("use scripts/test-linux.sh to create an isolated network namespace")
	}
	a, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	b := os.Getenv("FIREWALL_PARENT_NETNS")
	if b == "" || a == b {
		t.Fatal("refusing enforcement tests in the host network namespace")
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("bring up isolated loopback: %s: %v", out, err)
	}
}
func openTestBackend(t *testing.T, dir string) *Backend {
	t.Helper()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Owner: "integration", LockDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	return b
}
func policy() fw.Policy {
	return fw.Policy{Lifetime: fw.Persistent, Defaults: map[fw.Direction]fw.Action{fw.Inbound: fw.Allow, fw.Outbound: fw.Allow, fw.Forward: fw.Allow}}
}
func portRule(id string, d fw.Direction, proto uint32, port uint16) fw.Rule {
	return fw.Rule{ID: id, Direction: d, Family: fw.Dual, Action: fw.Drop, When: fw.All(fw.Is(fw.Match{Field: fw.DestinationPort, Ports: fw.PortRange{First: port, Last: port}}), fw.Is(fw.Match{Field: fw.Protocol, Number: proto}))}
}

func tcpListener(t *testing.T, network, address string) net.Listener {
	t.Helper()
	l, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l
}
func tcpReachable(address string, mark bool) bool {
	d := net.Dialer{Timeout: 150 * time.Millisecond}
	if mark {
		d.Control = func(_, _ string, raw syscall.RawConn) error {
			return SetSocketMark(raw, MarkReservation{Mask: 0xff, Value: 0x80})
		}
	}
	c, err := d.Dial("tcp", address)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
func udpListener(t *testing.T, address string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(address)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		var data [16]byte
		for {
			n, from, err := c.ReadFromUDPAddrPort(data[:])
			if err != nil {
				return
			}
			c.WriteToUDPAddrPort(data[:n], from)
		}
	}()
	return c
}
func udpReachable(address string) bool {
	c, err := net.Dial("udp", address)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err = c.Write([]byte("test")); err != nil {
		return false
	}
	var b [8]byte
	_, err = c.Read(b[:])
	return err == nil
}

func TestKernelPolicies(t *testing.T) {
	isolated(t)
	dir := t.TempDir()
	b := openTestBackend(t, dir)
	c, err := fw.New(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	p := policy()
	r, err := c.Apply(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	// A second cooperating writer cannot acquire this owner's namespace lock.
	if other, err := New(Config{Owner: "integration", LockDir: dir}); !errors.Is(err, fw.ErrOwnership) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("second owner: %v", err)
	}
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		l := tcpListener(t, "tcp", address)
		dst := l.Addr().String()
		port := uint16(l.Addr().(*net.TCPAddr).Port)
		if !tcpReachable(dst, false) {
			t.Fatalf("baseline TCP %s failed", dst)
		}
		for _, d := range []fw.Direction{fw.Outbound, fw.Inbound} {
			p.Rules = []fw.Rule{portRule("block-tcp", d, 6, port)}
			if _, err = c.Apply(t.Context(), p); err != nil {
				t.Fatal(err)
			}
			if tcpReachable(dst, false) {
				t.Fatalf("%s TCP not blocked for %s", d, dst)
			}
			// Capture mark exemptions must never bypass a security decision.
			if tcpReachable(dst, true) {
				t.Fatal("marked proxy socket bypassed drop")
			}
			counts, err := b.Counters(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if counts["block-tcp"].Packets == 0 {
				t.Fatal("missing native counter")
			}
		}
		p.Rules = nil
		if _, err = c.Apply(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		if !tcpReachable(dst, false) {
			t.Fatal("TCP did not recover after atomic replacement")
		}
		u := udpListener(t, address)
		udp := u.LocalAddr().String()
		up := uint16(u.LocalAddr().(*net.UDPAddr).Port)
		if !udpReachable(udp) {
			t.Fatal("baseline UDP failed")
		}
		p.Rules = []fw.Rule{portRule("block-udp", fw.Outbound, 17, up)}
		if _, err = c.Apply(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		if udpReachable(udp) {
			t.Fatal("UDP not blocked")
		}
		p.Rules = nil
	}
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	// The native batch must roll back even after queued deletion of our table.
	before, err := c.Current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	batch := &nftables.Conn{}
	batch.DelTable(b.table)
	batch.AddChain(&nftables.Chain{Name: "must-fail", Table: &nftables.Table{Name: "nonexistent", Family: nftables.TableFamilyINet}})
	if err = batch.Flush(); err == nil {
		t.Fatal("expected kernel transaction rejection")
	}
	after, err := c.Current(t.Context())
	if err != nil || after.Revision != before.Revision {
		t.Fatalf("failed batch lost old rules: %+v %v", after, err)
	}
	// Independent firewall base-chain Drop wins over our Allow.
	external := &nftables.Table{Name: "unrelated_firewall", Family: nftables.TableFamilyINet}
	nc := &nftables.Conn{}
	nc.AddTable(external)
	drop := nftables.ChainPolicyDrop
	nc.AddChain(&nftables.Chain{Name: "input", Table: external, Hooknum: nftables.ChainHookInput, Type: nftables.ChainTypeFilter, Priority: new(nftables.ChainPriority(10)), Policy: &drop})
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	l := tcpListener(t, "tcp4", "127.0.0.1:0")
	if tcpReachable(l.Addr().String(), false) {
		t.Fatal("our Allow overrode external Drop")
	}
	p.Rules = []fw.Rule{portRule("test", fw.Outbound, 6, 1)}
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if _, err = nc.ListTableOfFamily(external.Name, external.Family); err != nil {
		t.Fatal("unrelated table removed")
	}
	nc.DelTable(external)
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	b2 := openTestBackend(t, dir)
	c2, err := fw.New(t.Context(), b2)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	state, err := c2.Current(t.Context())
	if err != nil || !state.Active || state.Policy != nil || state.Revision.Generation <= r.Generation {
		t.Fatalf("persistent recovery: %+v %v", state, err)
	}
	if err = c2.Remove(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = c2.Remove(t.Context()); err != nil {
		t.Fatal(err)
	}
	p.Lifetime = fw.Temporary
	if _, err = c2.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if err = c2.Close(); err != nil {
		t.Fatal(err)
	}
	b3 := openTestBackend(t, dir)
	state3, err := b3.Inspect(t.Context())
	if err != nil || state3.Active {
		t.Fatalf("temporary cleanup: %+v %v", state3, err)
	}
}

func TestKernelConditions(t *testing.T) {
	isolated(t)
	b := openTestBackend(t, t.TempDir())
	c, err := fw.New(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := policy()
	p.Lifetime = fw.Temporary
	l := tcpListener(t, "tcp4", "127.0.0.1:0")
	dst := l.Addr().String()
	for _, condition := range []fw.Condition{
		fw.Is(fw.Match{Field: fw.OutputInterface, Text: "lo"}),
		fw.Is(fw.Match{Field: fw.DestinationPrefix, Prefix: netip.MustParsePrefix("127.0.0.0/8")}),
		fw.Not(fw.Is(fw.Match{Field: fw.DestinationPrefix, Prefix: netip.MustParsePrefix("10.0.0.0/8")})),
		fw.Is(fw.Match{Field: fw.ConnectionState, Number: fw.StateNew}),
		fw.Is(fw.Match{Field: fw.User, Text: fmt.Sprint(os.Getuid())}),
		fw.All(fw.Is(fw.Match{Field: fw.Protocol, Number: 6}), fw.Is(fw.Match{Field: fw.DestinationPort, Ports: fw.PortRange{First: 1, Last: 65535}})),
	} {
		p.Rules = []fw.Rule{{ID: "condition", Direction: fw.Outbound, Family: fw.IPv4, Action: fw.Drop, When: condition}}
		if _, err = c.Apply(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		if tcpReachable(dst, false) {
			t.Fatalf("predicate did not block: %+v", condition)
		}
	}
	p.Rules = []fw.Rule{{ID: "marked", Direction: fw.Outbound, Family: fw.Dual, Action: fw.Drop, When: fw.Is(fw.Match{Field: fw.PacketMark, Mask: 0xff, Number: 0x80})}}
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if !tcpReachable(dst, false) || tcpReachable(dst, true) {
		t.Fatal("mark predicate failed")
	}
	var addresses []fw.Condition
	for _, address := range []string{"127.0.0.1/32", "192.0.2.1/32", "198.51.100.1/32", "::1/128"} {
		addresses = append(addresses, fw.Is(fw.Match{Field: fw.DestinationPrefix, Prefix: netip.MustParsePrefix(address)}))
	}
	p.Rules = []fw.Rule{{ID: "set-block", Direction: fw.Outbound, Family: fw.Dual, Action: fw.Drop, When: fw.Any(addresses...)}}
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if tcpReachable(dst, false) {
		t.Fatal("native address set did not block")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = c.Apply(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Persisted marks are never rewritten by rule installation itself.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 0x4000); err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "socket")
	defer file.Close()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err = SetSocketMark(raw, MarkReservation{Mask: 0xff, Value: 0x80}); err != nil {
		t.Fatal(err)
	}
	mark, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
	if err != nil || mark != 0x4080 {
		t.Fatalf("mark=%x err=%v", mark, err)
	}
}

func TestRuleExpressions(t *testing.T) {
	if err := (MarkReservation{Mask: 0xff, Value: 1, OtherMasks: []uint32{0x10}}).Validate(); !errors.Is(err, fw.ErrOwnership) {
		t.Fatal(err)
	}
	// Compiling an IPv4 prefix under NOT must match IPv6, not discard it.
	es, possible, err := expressions([]fw.Literal{{Match: fw.Match{Field: fw.DestinationPrefix, Prefix: netip.MustParsePrefix("10.0.0.0/8")}, Not: true}}, fw.IPv6, fw.Outbound)
	if err != nil || !possible || len(es) != 2 {
		t.Fatalf("negated cross-family prefix: %+v %v", es, err)
	}
	if _, ok := verdict(fw.Reject)[0].(*expr.Reject); !ok {
		t.Fatal("missing native reject")
	}
}
