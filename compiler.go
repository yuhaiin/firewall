package firewall

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const (
	maxDepth = 32
	maxNodes = 200000
	maxTerms = 100000
	maxRules = 10000
)

// Compile validates, expands zones, orders rules and converts expressions into
// bounded disjunctive normal form. It does not contact or alter the OS.
func Compile(p Policy, caps Capabilities) (Snapshot, error) {
	bad := func(s string) (Snapshot, error) { return Snapshot{}, fmt.Errorf("%w: %s", ErrInvalid, s) }
	if p.Lifetime != Temporary && p.Lifetime != Persistent {
		return bad("explicit lifetime required")
	}
	if (p.Lifetime == Temporary && !caps.Temporary) || (p.Lifetime == Persistent && !caps.Persistent) {
		return Snapshot{}, fmt.Errorf("%w: %s lifetime", ErrUnsupported, p.Lifetime)
	}
	if len(p.Defaults) == 0 {
		return bad("at least one explicit default required")
	}
	for d, a := range p.Defaults {
		if !validDirection(d, caps) {
			return Snapshot{}, fmt.Errorf("%w: direction %s", ErrUnsupported, d)
		}
		if a != Allow && a != Drop {
			return bad("defaults must allow or drop")
		}
		if a == Drop && !p.AcknowledgeLockout {
			return bad("default drop requires acknowledge_lockout; explicitly allow management, DNS and tunnel control as needed")
		}
	}
	if len(p.Rules) > maxRules {
		return bad("too many rules")
	}
	// Copy through JSON to prevent caller mutations from changing committed state.
	b, err := json.Marshal(p)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: encode: %v", ErrInvalid, err)
	}
	if len(b) > 16<<20 {
		return bad("policy exceeds 16 MiB")
	}
	var cloned Policy
	if err = json.Unmarshal(b, &cloned); err != nil {
		return Snapshot{}, fmt.Errorf("%w: decode: %v", ErrInvalid, err)
	}
	p = cloned
	zones := map[string]Condition{}
	for _, z := range p.Zones {
		if z.Name == "" {
			return bad("empty zone name")
		}
		if _, ok := zones[z.Name]; ok {
			return bad("duplicate zone " + z.Name)
		}
		zones[z.Name] = z.When
	}
	slices.SortFunc(p.Rules, func(a, b Rule) int {
		if n := cmp.Compare(a.Priority, b.Priority); n != 0 {
			return n
		}
		return strings.Compare(a.ID, b.ID)
	})
	s := Snapshot{Policy: p}
	ids := map[string]bool{}
	nodes, total, literalTotal := 0, 0, 0
	// Validate every zone, including unused definitions and cycles.
	for _, z := range p.Zones {
		if _, err := normalize(z.When, false, 0, &nodes, zones); err != nil {
			return Snapshot{}, fmt.Errorf("zone %s: %w", z.Name, err)
		}
	}
	for _, r := range p.Rules {
		if r.ID == "" || len(r.ID) > 128 || strings.ContainsAny(r.ID, "\x00\r\n") || ids[r.ID] {
			return bad("empty, duplicate, or invalid rule ID: " + r.ID)
		}
		ids[r.ID] = true
		if r.Family != Dual && r.Family != IPv4 && r.Family != IPv6 {
			return bad("explicit IP family required for " + r.ID)
		}
		if r.Direction != Inbound && r.Direction != Outbound && r.Direction != Forward {
			return bad("invalid direction")
		}
		if r.Action != Allow && r.Action != Drop && r.Action != Reject && r.Action != Log {
			return bad("invalid action")
		}
		terms, err := normalize(r.When, false, 0, &nodes, zones)
		if err != nil {
			return Snapshot{}, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		if r.Disabled {
			continue
		}
		if len(terms) == 0 {
			return bad("condition never matches: " + r.ID)
		}
		if _, ok := p.Defaults[r.Direction]; !ok {
			return bad("rule direction has no default: " + r.ID)
		}
		if !validDirection(r.Direction, caps) || (r.Family != IPv6 && !caps.IPv4) || (r.Family != IPv4 && !caps.IPv6) {
			return Snapshot{}, fmt.Errorf("%w: rule %s family/direction", ErrUnsupported, r.ID)
		}
		if (r.Action == Reject && !caps.Reject) || (r.Action == Log && !caps.Logging) {
			return Snapshot{}, fmt.Errorf("%w: action %s", ErrUnsupported, r.Action)
		}
		for _, term := range terms {
			literalTotal += len(term)
			if literalTotal > maxNodes {
				return bad("expanded policy exceeds predicate limit")
			}
			if err := validateTerm(term, r); err != nil {
				return Snapshot{}, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			for _, l := range term {
				if !caps.Fields[l.Match.Field] || (l.Not && !caps.Negation) {
					return Snapshot{}, fmt.Errorf("%w: rule %s field %s (negated=%t)", ErrUnsupported, r.ID, l.Match.Field, l.Not)
				}
			}
		}
		total += len(terms)
		if total > maxTerms {
			return bad("expanded policy exceeds term limit")
		}
		s.Rules = append(s.Rules, CompiledRule{ID: r.ID, Direction: r.Direction, Family: r.Family, Action: r.Action, Terms: terms})
	}
	b, err = json.Marshal(p)
	if err != nil {
		return Snapshot{}, err
	}
	sum := sha256.Sum256(b)
	s.Revision.Digest = hex.EncodeToString(sum[:])
	return s, nil
}

func validDirection(d Direction, c Capabilities) bool {
	return d == Inbound && c.Inbound || d == Outbound && c.Outbound || d == Forward && c.Forward
}

func normalize(c Condition, neg bool, depth int, nodes *int, zones map[string]Condition) ([][]Literal, error) {
	*nodes++
	if depth > maxDepth || *nodes > maxNodes {
		return nil, fmt.Errorf("%w: expression limit exceeded", ErrInvalid)
	}
	bad := func(s string) ([][]Literal, error) { return nil, fmt.Errorf("%w: %s", ErrInvalid, s) }
	if c.Op == "zone" {
		if c.Match == nil || len(c.Children) != 0 || *c.Match != (Match{Text: c.Match.Text}) {
			return bad("invalid zone reference")
		}
		z, ok := zones[c.Match.Text]
		if !ok {
			return bad("unknown zone " + c.Match.Text)
		}
		return normalize(z, neg, depth+1, nodes, zones)
	}
	if c.Op == "match" {
		if c.Match == nil || len(c.Children) != 0 {
			return bad("invalid leaf")
		}
		m, err := validateMatch(*c.Match)
		if err != nil {
			return nil, err
		}
		return [][]Literal{{{Match: m, Not: neg}}}, nil
	}
	if c.Match != nil {
		return bad("unexpected match on logical expression")
	}
	if c.Op == "not" {
		if len(c.Children) != 1 {
			return bad("NOT requires exactly one child")
		}
		return normalize(c.Children[0], !neg, depth+1, nodes, zones)
	}
	if c.Op != "all" && c.Op != "any" {
		return bad("unknown or missing expression operator")
	}
	if c.Op == "any" && len(c.Children) == 0 {
		return bad("empty OR")
	}
	and := (c.Op == "all") != neg
	var out [][]Literal
	cost := 0
	if and {
		out = [][]Literal{{}}
	}
	for _, child := range c.Children {
		v, err := normalize(child, neg, depth+1, nodes, zones)
		if err != nil {
			return nil, err
		}
		if !and {
			if len(out)+len(v) > maxTerms {
				return bad("OR expansion limit")
			}
			for _, term := range v {
				cost += len(term)
			}
			if cost > maxNodes {
				return bad("OR predicate expansion limit")
			}
			out = append(out, v...)
			continue
		}
		if len(v) > 0 && len(out) > maxTerms/len(v) {
			return bad("AND expansion limit")
		}
		next := make([][]Literal, 0, len(out)*len(v))
		cost = 0
		for _, a := range out {
			for _, b := range v {
				cost += len(a) + len(b)
				if cost > maxNodes {
					return bad("AND predicate expansion limit")
				}
				if len(a)+len(b) > 256 {
					return bad("term exceeds predicate limit")
				}
				x := make([]Literal, 0, len(a)+len(b))
				x = append(x, a...)
				x = append(x, b...)
				next = append(next, x)
			}
		}
		out = next
	}
	return out, nil
}

func validateMatch(m Match) (Match, error) {
	bad := func(s string) (Match, error) { return Match{}, fmt.Errorf("%w: %s", ErrInvalid, s) }
	var want Match
	want.Field = m.Field
	switch m.Field {
	case SourcePrefix, DestinationPrefix:
		if !m.Prefix.IsValid() || m.Prefix.Addr().Is4In6() {
			return bad("invalid or IPv4-mapped prefix")
		}
		m.Prefix = m.Prefix.Masked()
		want.Prefix = m.Prefix
	case SourcePort, DestinationPort:
		if m.Ports.First > m.Ports.Last {
			return bad("reversed port range")
		}
		want.Ports = m.Ports
	case Protocol:
		if m.Number > 255 {
			return bad("IP protocol exceeds 255")
		}
		want.Number = m.Number
	case InputInterface, OutputInterface, Application, User:
		if m.Text == "" || strings.ContainsRune(m.Text, 0) {
			return bad("empty or NUL identity")
		}
		want.Text = m.Text
	case ConnectionState:
		if m.Number == 0 || m.Number & ^uint32(79) != 0 {
			return bad("invalid conntrack states")
		}
		want.Number = m.Number
	case PacketMark:
		if m.Mask == 0 || m.Number & ^m.Mask != 0 {
			return bad("invalid mark mask/value")
		}
		want.Number = m.Number
		want.Mask = m.Mask
	default:
		return bad("unknown field " + string(m.Field))
	}
	if want != m {
		return bad("extraneous match value for " + string(m.Field))
	}
	return m, nil
}

func validateTerm(term []Literal, r Rule) error {
	bad := func(s string) error { return fmt.Errorf("%w: %s", ErrInvalid, s) }
	proto := -1
	ports := false
	prefixFamily := 0
	for i, a := range term {
		m := a.Match
		if m.Field == Protocol && !a.Not {
			proto = int(m.Number)
		}
		if m.Field == SourcePort || m.Field == DestinationPort {
			ports = true
		}
		if !a.Not && (m.Field == SourcePrefix || m.Field == DestinationPrefix) {
			family := m.Prefix.Addr().BitLen()
			if prefixFamily != 0 && prefixFamily != family {
				return bad("source and destination prefixes have different IP families")
			}
			prefixFamily = family
		}
		if m.Field == InputInterface && r.Direction == Outbound || m.Field == OutputInterface && r.Direction == Inbound {
			return bad("interface has no meaning at this direction")
		}
		if m.Field == User && r.Direction == Forward {
			return fmt.Errorf("%w: user on forwarded traffic", ErrUnsupported)
		}
		if !a.Not && (m.Field == SourcePrefix || m.Field == DestinationPrefix) && ((r.Family == IPv4 && !m.Prefix.Addr().Is4()) || (r.Family == IPv6 && m.Prefix.Addr().Is4())) {
			return bad("prefix contradicts family")
		}
		for _, b := range term[:i] {
			if m.Field != b.Match.Field {
				continue
			}
			if m == b.Match && a.Not != b.Not {
				return bad("predicate and its negation")
			}
			if a.Not != b.Not {
				positive, negative := m, b.Match
				if a.Not {
					positive, negative = b.Match, m
				}
				switch m.Field {
				case SourcePrefix, DestinationPrefix:
					if negative.Prefix.Bits() <= positive.Prefix.Bits() && negative.Prefix.Contains(positive.Prefix.Addr()) {
						return bad("positive prefix excluded by negation")
					}
				case SourcePort, DestinationPort:
					if negative.Ports.First <= positive.Ports.First && negative.Ports.Last >= positive.Ports.Last {
						return bad("positive ports excluded by negation")
					}
				}
			}
			if a.Not || b.Not {
				continue
			}
			switch m.Field {
			case Protocol, Application, User, InputInterface, OutputInterface:
				if m != b.Match {
					return bad("conflicting identity/protocol")
				}
			case SourcePrefix, DestinationPrefix:
				if !m.Prefix.Overlaps(b.Match.Prefix) {
					return bad("disjoint prefixes in AND")
				}
			case SourcePort, DestinationPort:
				if m.Ports.Last < b.Match.Ports.First || b.Match.Ports.Last < m.Ports.First {
					return bad("disjoint ports in AND")
				}
			case PacketMark:
				if (m.Number^b.Match.Number)&m.Mask&b.Match.Mask != 0 {
					return bad("conflicting mark bits")
				}
			}
		}
	}
	if ports && proto != 6 && proto != 17 {
		return bad("port predicates require a positive TCP or UDP protocol in every term")
	}
	if proto == 1 && r.Family != IPv4 || proto == 58 && r.Family != IPv6 {
		return bad("ICMP requires its explicit IP family")
	}
	return nil
}

// Flow is input to the diagnostic evaluator, never a packet interception API.
// Identity strings have the same platform-specific meaning as Match.Text.
type Flow struct {
	Direction                                          Direction
	Source, Destination                                netip.AddrPort
	Protocol                                           uint8
	InputInterface, OutputInterface, Application, User string
	State, Mark                                        uint32
}

// Evaluate returns the first terminating action and its ID, or the default.
// Log rules continue. Callers must provide valid addresses of the same family.
func Evaluate(s Snapshot, f Flow) (Action, string) {
	if !f.Source.IsValid() || !f.Destination.IsValid() || f.Source.Addr().Is4() != f.Destination.Addr().Is4() {
		return Drop, ""
	}
	for _, r := range s.Rules {
		if r.Direction != f.Direction || r.Family == IPv4 && !f.Source.Addr().Is4() || r.Family == IPv6 && f.Source.Addr().Is4() {
			continue
		}
		for _, term := range r.Terms {
			ok := true
			for _, l := range term {
				if matchFlow(l.Match, f) == l.Not {
					ok = false
					break
				}
			}
			if ok && r.Action != Log {
				return r.Action, r.ID
			}
		}
	}
	return s.Policy.Defaults[f.Direction], ""
}

func matchFlow(m Match, f Flow) bool {
	switch m.Field {
	case Protocol:
		return uint32(f.Protocol) == m.Number
	case SourcePrefix:
		return m.Prefix.Contains(f.Source.Addr())
	case DestinationPrefix:
		return m.Prefix.Contains(f.Destination.Addr())
	case SourcePort:
		return f.Source.Port() >= m.Ports.First && f.Source.Port() <= m.Ports.Last
	case DestinationPort:
		return f.Destination.Port() >= m.Ports.First && f.Destination.Port() <= m.Ports.Last
	case InputInterface:
		return f.InputInterface == m.Text
	case OutputInterface:
		return f.OutputInterface == m.Text
	case Application:
		return f.Application == m.Text
	case User:
		return f.User == m.Text
	case ConnectionState:
		return f.State&m.Number != 0
	case PacketMark:
		return f.Mark&m.Mask == m.Number
	}
	return false
}

// Diff lists stable rule IDs added, removed or changed, in lexical order.
// Default/lifetime changes are reported separately.
type PolicyDiff struct {
	Added, Removed, Changed          []string
	DefaultsChanged, LifetimeChanged bool
	ZonesChanged                     bool
}

// Diff compares desired policies without contacting a backend.
func Diff(a, b Policy) PolicyDiff {
	d := PolicyDiff{LifetimeChanged: a.Lifetime != b.Lifetime}
	x, _ := json.Marshal(a.Defaults)
	y, _ := json.Marshal(b.Defaults)
	d.DefaultsChanged = string(x) != string(y)
	x, _ = json.Marshal(a.Zones)
	y, _ = json.Marshal(b.Zones)
	d.ZonesChanged = string(x) != string(y)
	old := make(map[string]string, len(a.Rules))
	for _, r := range a.Rules {
		x, _ := json.Marshal(r)
		old[r.ID] = string(x)
	}
	for _, r := range b.Rules {
		x, _ := json.Marshal(r)
		v, ok := old[r.ID]
		if !ok {
			d.Added = append(d.Added, r.ID)
		} else if v != string(x) {
			d.Changed = append(d.Changed, r.ID)
		}
		delete(old, r.ID)
	}
	for id := range old {
		d.Removed = append(d.Removed, id)
	}
	slices.Sort(d.Added)
	slices.Sort(d.Removed)
	slices.Sort(d.Changed)
	return d
}
