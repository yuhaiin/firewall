//go:build windows && (amd64 || arm64)

package windows

import (
	"testing"
	"unsafe"

	fw "github.com/yuhaiin/firewall"
)

func TestSDKLayouts(t *testing.T) {
	// Verified against x86_64-w64-mingw32 fwpmtypes.h; all offsets are bytes.
	for _, tt := range []struct {
		name      string
		got, want uintptr
	}{{"filter", unsafe.Sizeof(filter{}), 200}, {"session", unsafe.Sizeof(session{}), 72}, {"provider", unsafe.Sizeof(provider{}), 64}, {"sublayer", unsafe.Sizeof(sublayer{}), 72}, {"condition", unsafe.Sizeof(condition{}), 40}, {"enum template", unsafe.Sizeof(enumTemplate{}), 72}, {"action offset", unsafe.Offsetof(filter{}.Action), 128}, {"context offset", unsafe.Offsetof(filter{}.Context), 152}, {"filter ID offset", unsafe.Offsetof(filter{}.ID), 176}, {"condition pointer offset", unsafe.Offsetof(filter{}.Conditions), 120}} {
		if tt.got != tt.want {
			t.Errorf("%s: got %d want %d", tt.name, tt.got, tt.want)
		}
	}
}
func TestNativeCompilation(t *testing.T) {
	b := &Backend{config: Config{Owner: "test", Lifetime: fw.Temporary}}
	b.provider = guid("test", "provider")
	b.sublayer = guid("test", "sublayer")
	p := fw.Policy{Lifetime: fw.Temporary, Defaults: map[fw.Direction]fw.Action{fw.Outbound: fw.Allow}, Rules: []fw.Rule{{ID: "tcp", Family: fw.Dual, Direction: fw.Outbound, Action: fw.Drop, When: fw.All(fw.Is(fw.Match{Field: fw.Protocol, Number: 6}), fw.Is(fw.Match{Field: fw.DestinationPort, Ports: fw.PortRange{First: 80, Last: 90}}))}}}
	s, err := fw.Compile(p, b.features())
	if err != nil {
		t.Fatal(err)
	}
	a := &arena{}
	defer a.close()
	filters, err := b.compile(s, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 4 || filters[0].Count != 2 || filters[0].Weight.Data == 0 || filters[0].Layer != connect4 || filters[1].Layer != connect6 {
		t.Fatalf("bad compiled filters: %+v", filters)
	}
}
