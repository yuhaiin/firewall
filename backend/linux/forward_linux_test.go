package linux

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	fw "github.com/yuhaiin/firewall"
)

type peer struct {
	dir     string
	command int
}
type peerCommand struct {
	Sequence           int
	Address, Operation string
}
type peerResult struct {
	Sequence  int
	Reachable bool
	Error     string
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %s: %v", args, out, err)
	}
}
func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("peer readiness timed out: %s", path)
}
func startPeer(t *testing.T, role string, subnet int) *peer {
	t.Helper()
	p := &peer{dir: t.TempDir()}
	var log bytes.Buffer
	cmd := exec.Command("unshare", "--net", "--", os.Args[0], "-test.run=^TestKernelPeer$", "-test.v")
	cmd.Env = append(os.Environ(), "FIREWALL_PEER_ROLE="+role, "FIREWALL_PEER_DIR="+p.dir, fmt.Sprintf("FIREWALL_PEER_SUBNET=%d", subnet))
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(log.String())
		}
	})
	waitFile(t, filepath.Join(p.dir, "namespace"))
	iface, other := role+"0", role+"peer"
	runIP(t, "link", "add", iface, "type", "veth", "peer", "name", other)
	runIP(t, "link", "set", other, "netns", fmt.Sprint(cmd.Process.Pid))
	runIP(t, "link", "set", iface, "up")
	runIP(t, "addr", "add", fmt.Sprintf("10.80.%d.1/24", subnet), "dev", iface)
	runIP(t, "-6", "addr", "add", fmt.Sprintf("fd42:%d::1/64", subnet), "dev", iface, "nodad")
	runIP(t, "-6", "addr", "flush", "dev", iface, "scope", "link")
	runIP(t, "-6", "addr", "add", "fe80::1/64", "dev", iface, "nodad")
	if err := os.WriteFile(filepath.Join(p.dir, "configure"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitFile(t, filepath.Join(p.dir, "ready"))
	return p
}
func (p *peer) request(t *testing.T, operation, address string) bool {
	t.Helper()
	p.command++
	data, err := json.Marshal(peerCommand{Sequence: p.command, Operation: operation, Address: address})
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(p.dir, "request.tmp")
	if err = os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(tmp, filepath.Join(p.dir, "request")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(p.dir, "result"))
		if err == nil {
			var r peerResult
			if json.Unmarshal(data, &r) == nil && r.Sequence == p.command {
				if !r.Reachable && r.Error != "" {
					t.Log(r.Error)
				}
				return r.Reachable
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("peer request timed out")
	return false
}

func TestKernelForwarding(t *testing.T) {
	isolated(t)
	for path, value := range map[string]string{"/proc/sys/net/ipv4/ip_forward": "1", "/proc/sys/net/ipv6/conf/all/forwarding": "1"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	startPeer(t, "vpn", 2)
	lan := startPeer(t, "lan", 1)
	// IPv6 forwarding is per-interface; enable it after the veth links exist.
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	b := openTestBackend(t, t.TempDir())
	c, err := fw.New(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := policy()
	p.Lifetime = fw.Temporary
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.80.2.2:23456", "[fd42:2::2]:23456"} {
		if !lan.request(t, "tcp", address) {
			for _, args := range [][]string{{"-6", "route"}, {"-6", "neigh"}, {"-6", "addr"}} {
				out, _ := exec.Command("ip", args...).CombinedOutput()
				t.Log(string(out))
			}
			t.Fatalf("baseline forwarded TCP failed: %s", address)
		}
	}
	for _, address := range []string{"10.80.2.2:23457", "[fd42:2::2]:23457"} {
		if !lan.request(t, "udp", address) {
			t.Fatalf("baseline forwarded UDP failed: %s", address)
		}
	}
	r := portRule("lan-to-vpn", fw.Forward, 6, 23456)
	r.When = fw.All(r.When, fw.Is(fw.Match{Field: fw.InputInterface, Text: "lan0"}), fw.Is(fw.Match{Field: fw.OutputInterface, Text: "vpn0"}))
	p.Rules = []fw.Rule{r}
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.80.2.2:23456", "[fd42:2::2]:23456"} {
		if lan.request(t, "tcp", address) {
			t.Fatal("LAN to VPN TCP escaped forward drop")
		}
	}
	if !lan.request(t, "udp", "10.80.2.2:23457") {
		t.Fatal("TCP rule unexpectedly blocked UDP")
	}
	// The same interface name may refer to a newly attached VPN link. A rename
	// deliberately stops matching until the caller updates the desired policy.
	runIP(t, "link", "set", "vpn0", "name", "vpn1")
	if !lan.request(t, "tcp", "10.80.2.2:23456") {
		t.Fatal("old interface predicate matched renamed link")
	}
	p.Rules[0].When = fw.All(portRule("unused", fw.Forward, 6, 23456).When, fw.Is(fw.Match{Field: fw.OutputInterface, Text: "vpn1"}))
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if lan.request(t, "tcp", "10.80.2.2:23456") {
		t.Fatal("updated VPN interface predicate did not enforce")
	}
	// Existing TCP flows remain allowed only when explicitly permitted by state.
	p.Rules = nil
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if !lan.request(t, "open", "10.80.2.2:23456") {
		t.Fatal("open active forwarded TCP")
	}
	p.Defaults[fw.Forward] = fw.Drop
	p.AcknowledgeLockout = true
	p.Rules = []fw.Rule{{ID: "existing", Direction: fw.Forward, Family: fw.Dual, Action: fw.Allow, When: fw.Is(fw.Match{Field: fw.ConnectionState, Number: fw.StateEstablished | fw.StateRelated})}}
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if !lan.request(t, "exchange", "") {
		t.Fatal("explicit ESTABLISHED allow failed")
	}
	if lan.request(t, "tcp", "10.80.2.2:23456") {
		t.Fatal("default deny allowed NEW TCP")
	}
	p.Rules = nil
	if _, err = c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if lan.request(t, "exchange", "") {
		t.Fatal("old flow bypassed new state policy")
	}
}

func TestKernelPeer(t *testing.T) {
	role := os.Getenv("FIREWALL_PEER_ROLE")
	if role == "" {
		t.Skip("internal peer helper")
	}
	isolated(t)
	dir := os.Getenv("FIREWALL_PEER_DIR")
	subnet := os.Getenv("FIREWALL_PEER_SUBNET")
	if (role != "lan" && role != "vpn") || (subnet != "1" && subnet != "2") {
		t.Fatal("invalid peer configuration")
	}
	if err := os.WriteFile(filepath.Join(dir, "namespace"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitFile(t, filepath.Join(dir, "configure"))
	iface := role + "peer"
	runIP(t, "link", "set", iface, "up")
	runIP(t, "addr", "add", "10.80."+subnet+".2/24", "dev", iface)
	runIP(t, "route", "add", "default", "via", "10.80."+subnet+".1")
	runIP(t, "-6", "addr", "add", "fd42:"+subnet+"::2/64", "dev", iface, "nodad")
	runIP(t, "-6", "addr", "flush", "dev", iface, "scope", "link")
	runIP(t, "-6", "addr", "add", "fe80::2/64", "dev", iface, "nodad")
	runIP(t, "-6", "route", "add", "default", "via", "fd42:"+subnet+"::1")
	if role == "vpn" {
		for _, address := range []string{"10.80.2.2:23456", "[fd42:2::2]:23456"} {
			l, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go func() {
				for {
					conn, err := l.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
				}
			}()
		}
		udpListener(t, "10.80.2.2:23457")
		udpListener(t, "[fd42:2::2]:23457")
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if role == "vpn" {
		select {}
	}
	var live net.Conn
	last := 0
	for {
		data, err := os.ReadFile(filepath.Join(dir, "request"))
		if err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		var request peerCommand
		if json.Unmarshal(data, &request) != nil || request.Sequence <= last {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		last = request.Sequence
		reachable := false
		switch request.Operation {
		case "tcp":
			conn, e := net.DialTimeout("tcp", request.Address, 300*time.Millisecond)
			err = e
			if e == nil {
				conn.Close()
				reachable = true
			}
		case "udp":
			reachable = udpReachable(request.Address)
		case "open":
			if live != nil {
				live.Close()
			}
			live, err = net.DialTimeout("tcp", request.Address, 200*time.Millisecond)
			reachable = err == nil
		case "exchange":
			if live != nil {
				live.SetDeadline(time.Now().Add(200 * time.Millisecond))
				_, err = live.Write([]byte("ping"))
				if err == nil {
					var reply [4]byte
					_, err = io.ReadFull(live, reply[:])
					reachable = err == nil && string(reply[:]) == "ping"
				}
			}
		}
		message := ""
		if !reachable && err != nil {
			message = err.Error()
		}
		data, err = json.Marshal(peerResult{Sequence: last, Reachable: reachable, Error: message})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "result.tmp"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(filepath.Join(dir, "result.tmp"), filepath.Join(dir, "result")); err != nil {
			t.Fatal(err)
		}
	}
}
