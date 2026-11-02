package linux

import (
	"net"
	"testing"
	"time"

	fw "github.com/yuhaiin/firewall"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func icmpReachable(t *testing.T, ipv6Family bool) bool {
	t.Helper()
	network, address, proto := "ip4:icmp", "127.0.0.1", 1
	var request, reply icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if ipv6Family {
		network, address, proto = "ip6:ipv6-icmp", "::1", 58
		request, reply = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	c, err := icmp.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(200 * time.Millisecond))
	data, err := (&icmp.Message{Type: request, Body: &icmp.Echo{ID: 1234, Seq: 1, Data: []byte("firewall")}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.WriteTo(data, &net.IPAddr{IP: net.ParseIP(address)}); err != nil {
		return false
	}
	var buffer [1500]byte
	for {
		n, _, err := c.ReadFrom(buffer[:])
		if err != nil {
			return false
		}
		message, err := icmp.ParseMessage(proto, buffer[:n])
		if err == nil && message.Type == reply {
			return true
		}
	}
}
func TestKernelICMPAndReject(t *testing.T) {
	isolated(t)
	b := openTestBackend(t, t.TempDir())
	c, err := fw.New(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := policy()
	p.Lifetime = fw.Temporary
	for _, v6 := range []bool{false, true} {
		p.Rules = nil
		if _, err = c.Apply(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		if !icmpReachable(t, v6) {
			t.Fatal("baseline ICMP echo failed")
		}
		family, protocol := fw.IPv4, uint32(1)
		address := "127.0.0.1:0"
		if v6 {
			family, protocol, address = fw.IPv6, 58, "[::1]:0"
		}
		p.Rules = []fw.Rule{{ID: "icmp", Direction: fw.Outbound, Family: family, Action: fw.Drop, When: fw.Is(fw.Match{Field: fw.Protocol, Number: protocol})}}
		if _, err = c.Apply(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		if icmpReachable(t, v6) {
			t.Fatal("native ICMP escaped drop")
		}
		l := tcpListener(t, "tcp", address)
		r := portRule("reject", fw.Outbound, 6, uint16(l.Addr().(*net.TCPAddr).Port))
		r.Action = fw.Reject
		p.Rules = []fw.Rule{r}
		if _, err = c.Apply(t.Context(), p); err != nil {
			t.Fatal(err)
		}
		if tcpReachable(l.Addr().String(), false) {
			t.Fatal("native Reject allowed connection")
		}
	}
}
