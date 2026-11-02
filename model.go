// Package firewall defines portable policies and manages native firewall backends.
// Enforcement is performed by the operating system, never by the evaluator.
package firewall

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// Stable errors can be inspected with errors.Is.
var (
	ErrInvalid     = errors.New("invalid firewall policy")
	ErrUnsupported = errors.New("unsupported firewall capability")
	ErrClosed      = errors.New("firewall handle is closed")
	ErrOwnership   = errors.New("native firewall ownership conflict")
	ErrUnavailable = errors.New("native firewall unavailable")
	ErrPermission  = errors.New("insufficient firewall permission")
	ErrDrift       = errors.New("native policy differs from expected revision")
)

// Action is a terminating decision, except Log which continues to the next rule.
type Action string

const (
	Allow  Action = "allow"
	Drop   Action = "drop"
	Reject Action = "reject"
	Log    Action = "log"
)

// Direction identifies a native filtering hook.
type Direction string

const (
	Inbound  Direction = "inbound"
	Outbound Direction = "outbound"
	Forward  Direction = "forward"
)

// Family selects IP versions. Dual is an explicit wildcard.
type Family string

const (
	Dual Family = "dual"
	IPv4 Family = "ipv4"
	IPv6 Family = "ipv6"
)

// Lifetime controls native object survival, not policy persistence to disk.
type Lifetime string

const (
	Temporary  Lifetime = "temporary"
	Persistent Lifetime = "persistent"
)

// Field identifies a predicate. Identity formats are described by each backend.
type Field string

const (
	Protocol          Field = "protocol"
	SourcePrefix      Field = "source_prefix"
	DestinationPrefix Field = "destination_prefix"
	SourcePort        Field = "source_port"
	DestinationPort   Field = "destination_port"
	InputInterface    Field = "input_interface"
	OutputInterface   Field = "output_interface"
	Application       Field = "application"
	User              Field = "user"
	ConnectionState   Field = "connection_state"
	PacketMark        Field = "packet_mark"
)

// Conntrack states use Linux's native bit representation, translated by backends.
const (
	StateInvalid     uint32 = 1
	StateEstablished uint32 = 2
	StateRelated     uint32 = 4
	StateNew         uint32 = 8
	StateUntracked   uint32 = 64
)

// PortRange is inclusive; port zero is representable.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// Match contains exactly the value appropriate to Field. A mark requires Mask.
// Protocol numbers follow IANA (TCP=6, UDP=17, ICMP=1, ICMPv6=58).
type Match struct {
	Field  Field        `json:"field"`
	Prefix netip.Prefix `json:"prefix,omitzero"`
	Ports  PortRange    `json:"ports,omitzero"`
	Number uint32       `json:"number,omitzero"`
	Mask   uint32       `json:"mask,omitzero"`
	Text   string       `json:"text,omitempty"`
}

// Condition is an expression tree: all, any, not, or match. All() matches all.
// The zero value is invalid to catch accidentally omitted security conditions.
type Condition struct {
	Op       string      `json:"op"`
	Children []Condition `json:"children,omitempty"`
	Match    *Match      `json:"match,omitempty"`
}

// All combines conditions with AND. An empty list is explicitly unrestricted.
func All(c ...Condition) Condition { return Condition{Op: "all", Children: c} }

// Any combines conditions with OR. An empty list is invalid.
func Any(c ...Condition) Condition { return Condition{Op: "any", Children: c} }

// Not negates a condition.
func Not(c Condition) Condition { return Condition{Op: "not", Children: []Condition{c}} }

// Is constructs a leaf predicate.
func Is(m Match) Condition { return Condition{Op: "match", Match: &m} }

// Rule has a stable ID. Smaller priorities win; equal priorities sort by ID.
type Rule struct {
	ID        string    `json:"id"`
	Priority  int32     `json:"priority"`
	Disabled  bool      `json:"disabled,omitzero"`
	Direction Direction `json:"direction"`
	Family    Family    `json:"family"`
	Action    Action    `json:"action"`
	When      Condition `json:"when"`
}

// Zone is an optional named expression expanded before native compilation.
type Zone struct {
	Name string    `json:"name"`
	When Condition `json:"when"`
}

// ZoneCondition returns a reference to a policy's zone. Zones convey no trust.
func ZoneCondition(name string) Condition { return Condition{Op: "zone", Match: &Match{Text: name}} }

// Policy defaults must explicitly specify the directions to enforce. Omitted
// directions install no hook. Default-deny requires AcknowledgeLockout.
type Policy struct {
	Lifetime           Lifetime             `json:"lifetime"`
	Defaults           map[Direction]Action `json:"defaults"`
	AcknowledgeLockout bool                 `json:"acknowledge_lockout,omitzero"`
	Rules              []Rule               `json:"rules,omitempty"`
	Zones              []Zone               `json:"zones,omitempty"`
}

// Capabilities describes compiled features separately from runtime permission.
// ProbeError is explanatory; callers must check Available and Permitted.
type Capabilities struct {
	Backend                                       string
	Available, Permitted                          bool
	ProbeError                                    string
	IPv4, IPv6, Inbound, Outbound, Forward        bool
	Fields                                        map[Field]bool
	Negation, Stateful, Reject, Logging, Counters bool
	Temporary, Persistent                         bool
	// TemporaryCrashCleanup distinguishes session lifetime from Close cleanup.
	TemporaryCrashCleanup bool
	// ConnectionEvents is false unless native connection observation is wired up.
	ConnectionEvents bool
}

// Literal is a normalized predicate, optionally negated.
type Literal struct {
	Match Match `json:"match"`
	Not   bool  `json:"not,omitzero"`
}

// CompiledRule contains one AND term. Multiple terms implement OR.
type CompiledRule struct {
	ID        string      `json:"id"`
	Direction Direction   `json:"direction"`
	Family    Family      `json:"family"`
	Action    Action      `json:"action"`
	Terms     [][]Literal `json:"terms"`
}

// Snapshot is immutable input to a backend. Drivers must not modify it.
type Snapshot struct {
	Policy   Policy         `json:"policy"`
	Rules    []CompiledRule `json:"rules"`
	Revision Revision       `json:"revision"`
}

// Revision identifies both a monotonically increasing generation and content.
type Revision struct {
	Generation uint64 `json:"generation"`
	Digest     string `json:"digest"`
}

// NativeState reports native metadata. It does not assert that another firewall
// permits traffic, nor authenticate changes made by another administrator.
type NativeState struct {
	Active   bool     `json:"active"`
	Revision Revision `json:"revision"`
	Lifetime Lifetime `json:"lifetime"`
}

// PolicyState combines observed native state with an optional known policy.
// Policy is nil after recovery until the caller reapplies its desired policy.
type PolicyState struct {
	NativeState
	Policy *Policy
}

// Driver is the platform boundary. Replace must atomically compare Expected and
// install Snapshot, or preserve the old policy on failure. Remove affects only
// owned objects. Close releases handles and removes temporary objects only.
// A driver is owned by one Client and must serialize cross-process writers.
type Driver interface {
	Capabilities(context.Context) (Capabilities, error)
	Inspect(context.Context) (NativeState, error)
	Replace(context.Context, Revision, Snapshot) error
	Remove(context.Context, Revision) error
	Close() error
}

// Firewall is a native firewall client. Remove is explicit enforcement removal.
type Firewall interface {
	Capabilities(context.Context) (Capabilities, error)
	Apply(context.Context, Policy) (Revision, error)
	Current(context.Context) (PolicyState, error)
	Events(context.Context) (<-chan Event, error)
	Remove(context.Context) error
	Close() error
}

// Event reports lifecycle observations; unavailable connection fields stay nil.
// Dropped counts earlier lifecycle events lost by this subscription.
type Event struct {
	Time                time.Time
	Kind                string
	Revision            Revision
	Reason              string
	Dropped             uint64
	RuleID              string
	Direction           Direction
	Protocol            *uint8
	Source, Destination *netip.AddrPort
	Interface, Process  string
	Action              Action
}
