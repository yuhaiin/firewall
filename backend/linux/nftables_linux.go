// Package linux installs native nftables rules through Netlink.
package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/unix"
)

const metadataChain = "__firewall_v1"

// Config identifies an independent firewall owner. LockDir must be a private,
// pre-existing directory shared by all clients of this owner/network namespace.
// The default is /run/yuhaiin-firewall (create it with mode 0700 as administrator).
// Priority orders our base chains relative to other products; Allow does not
// override a Drop from another base chain. Zero means normal filter priority.
type Config struct {
	Owner    string
	LockDir  string
	Priority int32
}

// Backend owns a single inet table and an exclusive advisory lock. Linux
// temporary policies are removed on Close, but survive an unclean process exit.
type Backend struct {
	mu     sync.Mutex
	config Config
	table  *nftables.Table
	lock   *os.File
	closed bool
}
type record struct {
	Magic string         `json:"magic"`
	Owner string         `json:"owner"`
	State fw.NativeState `json:"state"`
}

// New acquires ownership without changing firewall state. Permission is probed
// separately. No global ruleset, routes, or capture hooks are modified.
func New(c Config) (*Backend, error) {
	if c.Owner == "" || len(c.Owner) > 96 {
		return nil, fmt.Errorf("%w: owner must be 1..96 bytes", fw.ErrInvalid)
	}
	if c.LockDir == "" {
		c.LockDir = "/run/yuhaiin-firewall"
	}
	dir, err := os.Stat(c.LockDir)
	if err != nil {
		return nil, fmt.Errorf("private lock directory: %w", err)
	}
	if !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%w: lock directory must be private (0700)", fw.ErrOwnership)
	}
	sum := sha256.Sum256([]byte(c.Owner))
	name := "fw_" + hex.EncodeToString(sum[:12])
	// Network namespace identity prevents unrelated test namespaces contending.
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &ns); err != nil {
		return nil, err
	}
	ino := ns.Ino
	fd, err := unix.Open(c.LockDir+"/"+name+"_"+strconv.FormatUint(ino, 10)+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %v", fw.ErrOwnership, err)
	}
	return &Backend{config: c, table: &nftables.Table{Name: name, Family: nftables.TableFamilyINet}, lock: f}, nil
}

// Capabilities returns build support and a read-only runtime Netlink probe.
func (b *Backend) Capabilities(ctx context.Context) (fw.Capabilities, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fw.Capabilities{}, fw.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return fw.Capabilities{}, err
	}
	c := features()
	_, err := (&nftables.Conn{}).ListTables()
	c.Available = err == nil || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
	c.Permitted = err == nil
	if err != nil {
		c.ProbeError = err.Error()
	}
	return c, nil
}
func features() fw.Capabilities {
	return fw.Capabilities{Backend: "nftables", IPv4: true, IPv6: true, Inbound: true, Outbound: true, Forward: true, Negation: true, Stateful: true, Reject: true, Logging: true, Counters: true, Temporary: true, Persistent: true, Fields: map[fw.Field]bool{fw.Protocol: true, fw.SourcePrefix: true, fw.DestinationPrefix: true, fw.SourcePort: true, fw.DestinationPort: true, fw.InputInterface: true, fw.OutputInterface: true, fw.User: true, fw.ConnectionState: true, fw.PacketMark: true}}
}

// Inspect reads the ownership and generation marker from the actual table.
func (b *Backend) Inspect(ctx context.Context) (fw.NativeState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inspect(ctx)
}
func (b *Backend) inspect(ctx context.Context) (fw.NativeState, error) {
	if b.closed {
		return fw.NativeState{}, fw.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return fw.NativeState{}, err
	}
	c := &nftables.Conn{}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fw.NativeState{}, wrap(err)
	}
	found := false
	for _, t := range tables {
		if t.Name == b.table.Name {
			found = true
			break
		}
	}
	if !found {
		return fw.NativeState{}, nil
	}
	rules, err := c.GetRules(b.table, &nftables.Chain{Name: metadataChain, Table: b.table})
	if err != nil {
		return fw.NativeState{}, fmt.Errorf("%w: metadata missing: %v", fw.ErrOwnership, err)
	}
	if len(rules) != 1 {
		return fw.NativeState{}, fw.ErrOwnership
	}
	var r record
	if err = json.Unmarshal(rules[0].UserData, &r); err != nil || r.Magic != "yuhaiin/firewall/v1" || r.Owner != b.config.Owner || !r.State.Active || r.State.Revision.Generation == 0 || len(r.State.Revision.Digest) != 64 || (r.State.Lifetime != fw.Temporary && r.State.Lifetime != fw.Persistent) {
		return fw.NativeState{}, fw.ErrOwnership
	}
	return r.State, nil
}

// Replace installs a complete replacement as one nftables batch. The old table
// deletion and new table creation become visible together at batch commit.
func (b *Backend) Replace(ctx context.Context, expected fw.Revision, s fw.Snapshot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Recompile even direct Driver calls, never trusting supplied native terms.
	checked, err := fw.Compile(s.Policy, features())
	if err != nil {
		return err
	}
	if checked.Revision.Digest != s.Revision.Digest || s.Revision.Generation <= expected.Generation {
		return fw.ErrInvalid
	}
	checked.Revision = s.Revision
	s = checked
	state, err := b.inspect(ctx)
	if err != nil {
		return err
	}
	if state.Revision != expected {
		return fw.ErrDrift
	}
	c := &nftables.Conn{}
	if state.Active {
		c.DelTable(b.table)
	}
	c.AddTable(b.table)
	meta := c.AddChain(&nftables.Chain{Name: metadataChain, Table: b.table})
	data, err := json.Marshal(record{Magic: "yuhaiin/firewall/v1", Owner: b.config.Owner, State: fw.NativeState{Active: true, Revision: s.Revision, Lifetime: s.Policy.Lifetime}})
	if err != nil {
		return err
	}
	if len(data) > 256 {
		return fmt.Errorf("%w: ownership marker exceeds kernel userdata limit; shorten owner", fw.ErrInvalid)
	}
	// Holding a ct expression registers the namespace's native conntrack hooks
	// from the first policy onward, including while no explicit state rule is
	// present. This chain is unhooked and grants no implicit traffic permission.
	c.AddRule(&nftables.Rule{Table: b.table, Chain: meta, UserData: data, Exprs: []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}}})
	setID := uint32(0)
	for _, d := range []fw.Direction{fw.Inbound, fw.Outbound, fw.Forward} {
		a, ok := s.Policy.Defaults[d]
		if !ok {
			continue
		}
		hook := nftables.ChainHookInput
		if d == fw.Outbound {
			hook = nftables.ChainHookOutput
		} else if d == fw.Forward {
			hook = nftables.ChainHookForward
		}
		policy := nftables.ChainPolicyAccept
		if a == fw.Drop {
			policy = nftables.ChainPolicyDrop
		}
		chain := c.AddChain(&nftables.Chain{Name: string(d), Table: b.table, Hooknum: hook, Priority: new(nftables.ChainPriority(b.config.Priority)), Type: nftables.ChainTypeFilter, Policy: &policy})
		for _, r := range s.Rules {
			if r.Direction != d {
				continue
			}
			if addressSetEligible(r) {
				for _, family := range []fw.Family{fw.IPv4, fw.IPv6} {
					if r.Family != fw.Dual && r.Family != family {
						continue
					}
					setID++
					es, err := addressSet(c, b.table, r, family, setID)
					if err != nil {
						return err
					}
					if es == nil {
						continue
					}
					es = append(es, &expr.Counter{})
					es = append(es, verdict(r.Action)...)
					c.AddRule(&nftables.Rule{Table: b.table, Chain: chain, Exprs: es, UserData: []byte(r.ID)})
				}
				continue
			}
			for _, term := range r.Terms {
				for _, family := range []fw.Family{fw.IPv4, fw.IPv6} {
					if r.Family != fw.Dual && r.Family != family {
						continue
					}
					es, possible, err := expressions(term, family, d)
					if err != nil {
						return fmt.Errorf("rule %s: %w", r.ID, err)
					}
					if !possible {
						continue
					}
					es = append(es, &expr.Counter{})
					es = append(es, verdict(r.Action)...)
					c.AddRule(&nftables.Rule{Table: b.table, Chain: chain, Exprs: es, UserData: []byte(r.ID)})
				}
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return wrap(c.Flush())
}

// Remove deletes only the table whose metadata matches this owner/revision.
func (b *Backend) Remove(ctx context.Context, r fw.Revision) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.remove(ctx, r)
}
func (b *Backend) remove(ctx context.Context, r fw.Revision) error {
	state, err := b.inspect(ctx)
	if err != nil {
		return err
	}
	if state.Revision != r {
		return fw.ErrDrift
	}
	if !state.Active {
		return nil
	}
	c := &nftables.Conn{}
	c.DelTable(b.table)
	if err = ctx.Err(); err != nil {
		return err
	}
	return wrap(c.Flush())
}

// Close removes temporary policies and releases the advisory lock. A crash
// leaves Linux rules in place; persistent policies also survive clean Close.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := b.inspect(ctx)
	if err != nil {
		return err
	}
	if s.Active && s.Lifetime == fw.Temporary {
		if err = b.remove(ctx, s.Revision); err != nil {
			return err
		}
	}
	b.closed = true
	return b.lock.Close()
}

// Release closes only the ownership handle, preserving even temporary rules.
// It is intended for failed initialization and operator-directed recovery.
func (b *Backend) Release() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	return b.lock.Close()
}

// Counter is an aggregate over native expansions of one portable rule.
type Counter struct{ Packets, Bytes uint64 }

// Counters reads native counters. Counts reset on complete policy replacement.
func (b *Backend) Counters(ctx context.Context) (map[string]Counter, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := b.inspect(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]Counter{}
	if !s.Active {
		return out, nil
	}
	c := &nftables.Conn{}
	for _, d := range []string{"inbound", "outbound", "forward"} {
		chain, err := c.ListChain(b.table, d)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, wrap(err)
		}
		rules, err := c.GetRules(b.table, chain)
		if err != nil {
			return nil, wrap(err)
		}
		for _, r := range rules {
			v := out[string(r.UserData)]
			for _, e := range r.Exprs {
				if x, ok := e.(*expr.Counter); ok {
					v.Packets += x.Packets
					v.Bytes += x.Bytes
				}
			}
			out[string(r.UserData)] = v
		}
	}
	return out, nil
}
func wrap(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return fmt.Errorf("%w: %w", fw.ErrPermission, err)
	}
	return fmt.Errorf("nftables: %w", err)
}
