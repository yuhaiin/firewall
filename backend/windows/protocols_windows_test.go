//go:build windows && (amd64 || arm64)

package windows

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/windows"
)

func TestNativeProtocolsAndIdentity(t *testing.T) {
	if os.Getenv("FIREWALL_WFP_TEST") != "1" {
		t.Skip("requires disposable elevated Windows runner")
	}
	b, err := New(Config{Owner: "protocol-tests", Lifetime: fw.Temporary})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c, err := fw.New(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		for _, direction := range []fw.Direction{fw.Inbound, fw.Outbound} {
			t.Run(fmt.Sprintf("%s/%s", address, direction), func(t *testing.T) {
				p := fw.Policy{Lifetime: fw.Temporary, Defaults: map[fw.Direction]fw.Action{fw.Inbound: fw.Allow, fw.Outbound: fw.Allow}}
				if _, err = c.Apply(t.Context(), p); err != nil {
					t.Fatal(err)
				}
				conn, err := net.ListenPacket("udp", address)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				go func() {
					var buf [32]byte
					for {
						n, from, e := conn.ReadFrom(buf[:])
						if e != nil {
							return
						}
						conn.WriteTo(buf[:n], from)
					}
				}()
				port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
				probe := func() bool {
					x, e := net.Dial("udp", conn.LocalAddr().String())
					if e != nil {
						return false
					}
					defer x.Close()
					x.SetDeadline(time.Now().Add(150 * time.Millisecond))
					if _, e = x.Write([]byte("test")); e != nil {
						return false
					}
					var data [8]byte
					n, e := x.Read(data[:])
					return e == nil && string(data[:n]) == "test"
				}
				if !probe() {
					t.Fatal("baseline native UDP failed")
				}
				p.Rules = []fw.Rule{{ID: "identity-udp", Direction: direction, Family: fw.Dual, Action: fw.Drop, When: fw.All(fw.Is(fw.Match{Field: fw.Application, Text: executable}), fw.Is(fw.Match{Field: fw.User, Text: token.User.Sid.String()}), fw.Is(fw.Match{Field: fw.Protocol, Number: 17}), fw.Is(fw.Match{Field: fw.DestinationPort, Ports: fw.PortRange{First: port, Last: port}}))}}
				if _, err = c.Apply(t.Context(), p); err != nil {
					t.Fatal(err)
				}
				if probe() {
					t.Fatal("native application/SID UDP rule did not block")
				}
				if err = c.Remove(t.Context()); err != nil {
					t.Fatal(err)
				}
				if !probe() {
					t.Fatal("UDP did not recover after native removal")
				}
			})
		}
	}
}
