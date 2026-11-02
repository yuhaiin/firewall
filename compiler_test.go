package firewall

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
)

func testCapabilities() Capabilities {
	return Capabilities{Available: true, Permitted: true, IPv4: true, IPv6: true, Inbound: true, Outbound: true, Forward: true, Negation: true, Reject: true, Logging: true, Temporary: true, Persistent: true, Fields: map[Field]bool{Protocol: true, SourcePrefix: true, DestinationPrefix: true, SourcePort: true, DestinationPort: true, InputInterface: true, OutputInterface: true, Application: true, User: true, ConnectionState: true, PacketMark: true}}
}
func testPolicy() Policy {
	return Policy{Lifetime: Persistent, Defaults: map[Direction]Action{Outbound: Allow}, Rules: []Rule{{ID: "deny", Direction: Outbound, Family: Dual, Action: Drop, When: Is(Match{Field: DestinationPrefix, Prefix: netip.MustParsePrefix("10.0.0.0/8")})}}}
}

func TestValidation(t *testing.T) {
	cases := map[string]func(*Policy){
		"missing lifetime": func(p *Policy) { p.Lifetime = "" },
		"lockout":          func(p *Policy) { p.Defaults[Outbound] = Drop },
		"duplicate IDs":    func(p *Policy) { p.Rules = append(p.Rules, p.Rules[0]) },
		"invalid prefix":   func(p *Policy) { p.Rules[0].When = Is(Match{Field: SourcePrefix}) },
		"reversed ports":   func(p *Policy) { p.Rules[0].When = Is(Match{Field: SourcePort, Ports: PortRange{10, 1}}) },
		"untyped ports":    func(p *Policy) { p.Rules[0].When = Is(Match{Field: SourcePort, Ports: PortRange{1, 10}}) },
		"OR port branch": func(p *Policy) {
			p.Rules[0].When = Any(Is(Match{Field: Protocol, Number: 6}), Is(Match{Field: DestinationPort, Ports: PortRange{80, 80}}))
		},
		"contradiction": func(p *Policy) { c := p.Rules[0].When; p.Rules[0].When = All(c, Not(c)) },
		"disjoint prefixes": func(p *Policy) {
			p.Rules[0].When = All(p.Rules[0].When, Is(Match{Field: DestinationPrefix, Prefix: netip.MustParsePrefix("192.0.2.0/24")}))
		},
		"family":            func(p *Policy) { p.Rules[0].Family = IPv6 },
		"unknown field":     func(p *Policy) { p.Rules[0].When = Is(Match{Field: "typo"}) },
		"extraneous value":  func(p *Policy) { p.Rules[0].When = Is(Match{Field: Protocol, Number: 6, Text: "ignored?"}) },
		"missing condition": func(p *Policy) { p.Rules[0].When = Condition{} },
		"impossible families": func(p *Policy) {
			p.Rules[0].When = All(p.Rules[0].When, Is(Match{Field: SourcePrefix, Prefix: netip.MustParsePrefix("2001:db8::/32")}))
		},
		"excluded prefix": func(p *Policy) {
			p.Rules[0].When = All(p.Rules[0].When, Not(Is(Match{Field: DestinationPrefix, Prefix: netip.MustParsePrefix("0.0.0.0/0")})))
		},
		"nesting": func(p *Policy) {
			for range 34 {
				p.Rules[0].When = Not(p.Rules[0].When)
			}
		},
		"zone cycle": func(p *Policy) { p.Zones = []Zone{{Name: "a", When: ZoneCondition("a")}} },
		"empty OR":   func(p *Policy) { p.Rules[0].When = Any() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := testPolicy()
			mutate(&p)
			_, err := Compile(p, testCapabilities())
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
	c := testCapabilities()
	delete(c.Fields, DestinationPrefix)
	if _, err := Compile(testPolicy(), c); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestNormalizationAndOrder(t *testing.T) {
	p := testPolicy()
	p.Rules[0].When = All(Is(Match{Field: Protocol, Number: 6}), Not(Any(Is(Match{Field: DestinationPrefix, Prefix: netip.MustParsePrefix("10.0.0.0/8")}), Is(Match{Field: DestinationPrefix, Prefix: netip.MustParsePrefix("2001:db8::/32")}))), Not(Is(Match{Field: DestinationPort, Ports: PortRange{80, 90}})))
	s, err := Compile(p, testCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		address string
		port    uint16
		want    Action
	}{{"192.0.2.1", 443, Drop}, {"192.0.2.1", 85, Allow}, {"10.1.2.3", 443, Allow}, {"2001:db8::1", 443, Allow}, {"2001:db9::1", 443, Drop}} {
		addr := netip.MustParseAddr(tt.address)
		f := Flow{Direction: Outbound, Source: netip.AddrPortFrom(addr, 100), Destination: netip.AddrPortFrom(addr, tt.port), Protocol: 6}
		if got, _ := Evaluate(s, f); got != tt.want {
			t.Fatalf("%+v: got %s", tt, got)
		}
	}
	p = testPolicy()
	p.Rules = append(p.Rules, Rule{ID: "allow-first", Priority: -1, Direction: Outbound, Family: Dual, Action: Allow, When: All()})
	s, err = Compile(p, testCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	if s.Rules[0].ID != "allow-first" {
		t.Fatal(s.Rules)
	}
	p.Rules[0].When = All()
	if s.Policy.Rules[1].When.Op != "match" {
		t.Fatal("snapshot aliases caller policy")
	}
}

func TestCompilerMatchesExpression(t *testing.T) {
	rng := rand.New(rand.NewPCG(123, 456))
	var makeCondition func(int) Condition
	makeCondition = func(depth int) Condition {
		if depth == 0 {
			return Is(Match{Field: DestinationPrefix, Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(rng.IntN(256)), 0, 0, 0}), 8)})
		}
		switch rng.IntN(3) {
		case 0:
			return Not(makeCondition(depth - 1))
		case 1:
			return All(makeCondition(depth-1), makeCondition(depth-1))
		default:
			return Any(makeCondition(depth-1), makeCondition(depth-1))
		}
	}
	var original func(Condition, Flow) bool
	original = func(c Condition, f Flow) bool {
		switch c.Op {
		case "match":
			return matchFlow(*c.Match, f)
		case "not":
			return !original(c.Children[0], f)
		case "all":
			for _, x := range c.Children {
				if !original(x, f) {
					return false
				}
			}
			return true
		case "any":
			for _, x := range c.Children {
				if original(x, f) {
					return true
				}
			}
		}
		return false
	}
	for range 100 {
		p := testPolicy()
		p.Rules[0].When = makeCondition(3)
		s, err := Compile(p, testCapabilities())
		if errors.Is(err, ErrInvalid) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for range 100 {
			a := netip.AddrFrom4([4]byte{byte(rng.IntN(256)), 1, 2, 3})
			f := Flow{Direction: Outbound, Source: netip.AddrPortFrom(a, 10), Destination: netip.AddrPortFrom(a, 20)}
			want := Allow
			if original(p.Rules[0].When, f) {
				want = Drop
			}
			if got, _ := Evaluate(s, f); got != want {
				t.Fatalf("expression mismatch: %+v", p)
			}
		}
	}
}

func BenchmarkCompile(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			p := largePolicy(n)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Compile(p, testCapabilities()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
func largePolicy(n int) Policy {
	p := testPolicy()
	p.Rules = nil
	for i := range n {
		p.Rules = append(p.Rules, Rule{ID: fmt.Sprintf("rule-%05d", i), Direction: Outbound, Family: Dual, Action: Drop, When: Is(Match{Field: DestinationPrefix, Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)})})
	}
	return p
}
func BenchmarkEvaluate(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, err := Compile(largePolicy(n), testCapabilities())
			if err != nil {
				b.Fatal(err)
			}
			f := Flow{Direction: Outbound, Source: netip.MustParseAddrPort("192.0.2.1:10"), Destination: netip.MustParseAddrPort("203.0.113.1:20")}
			b.ReportAllocs()
			for b.Loop() {
				Evaluate(s, f)
			}
		})
	}
}
func BenchmarkDiff(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			a, c := largePolicy(n), largePolicy(n)
			c.Rules[n-1].Action = Allow
			b.ReportAllocs()
			for b.Loop() {
				Diff(a, c)
			}
		})
	}
}

func TestZonesAndExpansionBudget(t *testing.T) {
	a, b := testPolicy(), testPolicy()
	a.Zones = []Zone{{Name: "lan", When: Is(Match{Field: DestinationPrefix, Prefix: netip.MustParsePrefix("10.0.0.0/8")})}}
	b.Zones = []Zone{{Name: "lan", When: Is(Match{Field: DestinationPrefix, Prefix: netip.MustParsePrefix("192.168.0.0/16")})}}
	a.Rules[0].When = ZoneCondition("lan")
	b.Rules[0].When = ZoneCondition("lan")
	if !Diff(a, b).ZonesChanged {
		t.Fatal("zone-only change omitted from diff")
	}
	if _, err := Compile(a, testCapabilities()); err != nil {
		t.Fatal(err)
	}
	var terms []Condition
	for range 16 {
		terms = append(terms, Any(Is(Match{Field: Protocol, Number: 6}), Is(Match{Field: Protocol, Number: 17})))
	}
	a.Rules[0].When = All(terms...)
	if _, err := Compile(a, testCapabilities()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expansion budget: %v", err)
	}
}
