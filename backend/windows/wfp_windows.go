//go:build windows && (amd64 || arm64)

// Package windows implements native Windows Filtering Platform ALE filtering.
package windows

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Config chooses a stable owner and native session lifetime. PersistentService
// must name an installed automatic-start Windows service for persistent policy:
// WFP can disable provider filters after BFE restart without that association.
// Switching lifetimes requires explicit removal and a new backend/session.
type Config struct {
	Owner             string
	Lifetime          fw.Lifetime
	PersistentService string
}

// Backend owns a WFP engine, provider, sublayer and cross-process mutex.
type Backend struct {
	mu                 sync.Mutex
	config             Config
	handle             windows.Handle
	mutex              windows.Handle
	provider, sublayer windows.GUID
	closed             bool
}
type record struct {
	Magic, Owner string
	State        fw.NativeState
}

// New opens WFP without installing filters. Temporary sessions use WFP's
// documented automatic cleanup on engine close and unexpected process exit.
func New(c Config) (*Backend, error) {
	if c.Owner == "" || len(c.Owner) > 96 || strings.ContainsRune(c.Owner, 0) || (c.Lifetime != fw.Temporary && c.Lifetime != fw.Persistent) {
		return nil, fw.ErrInvalid
	}
	if c.Lifetime == fw.Persistent {
		if err := checkService(c.PersistentService); err != nil {
			return nil, err
		}
	}
	b := &Backend{config: c, provider: guid(c.Owner, "provider"), sublayer: guid(c.Owner, "sublayer")}
	name := text("Global\\yuhaiin.firewall." + b.provider.String())
	// A named event is an atomic, handle-lifetime ownership token. Unlike a
	// Windows mutex, it has no OS-thread affinity when Go moves goroutines.
	m, err := windows.CreateEvent(nil, 1, 0, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(m)
		return nil, fw.ErrOwnership
	}
	if err != nil {
		return nil, err
	}
	b.mutex = m
	s := session{Display: display{Name: text("yuhaiin/firewall")}, Timeout: 1000}
	if c.Lifetime == fw.Temporary {
		s.Flags = 1
	}
	err = call(engineOpen, 0, 10, 0, uintptr(unsafe.Pointer(&s)), uintptr(unsafe.Pointer(&b.handle)))
	runtime.KeepAlive(s)
	if err != nil {
		windows.CloseHandle(m)
		return nil, wrap(err)
	}
	return b, nil
}
func guid(owner, kind string) windows.GUID {
	sum := sha256.Sum256([]byte("github.com/yuhaiin/firewall/v1/" + owner + "/" + kind))
	g := windows.GUID{Data1: binary.BigEndian.Uint32(sum[:4]), Data2: binary.BigEndian.Uint16(sum[4:6]), Data3: binary.BigEndian.Uint16(sum[6:8])}
	copy(g.Data4[:], sum[8:16])
	g.Data3 = (g.Data3 & 0xfff) | 0x5000
	g.Data4[0] = (g.Data4[0] & 0x3f) | 0x80
	return g
}
func checkService(name string) error {
	if name == "" || strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: persistent WFP requires an automatic-start service", fw.ErrInvalid)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return err
	}
	if c.StartType != mgr.StartAutomatic {
		return fmt.Errorf("%w: service must start automatically", fw.ErrInvalid)
	}
	return nil
}

func (b *Backend) features() fw.Capabilities {
	return fw.Capabilities{Backend: "wfp", IPv4: true, IPv6: true, Inbound: true, Outbound: true, Negation: true, Stateful: true, Temporary: b.config.Lifetime == fw.Temporary, Persistent: b.config.Lifetime == fw.Persistent, TemporaryCrashCleanup: true, Fields: map[fw.Field]bool{fw.Protocol: true, fw.SourcePrefix: true, fw.DestinationPrefix: true, fw.SourcePort: true, fw.DestinationPort: true, fw.Application: true, fw.User: true}}
}

// Capabilities reports the active engine and conservative administrator access.
func (b *Backend) Capabilities(ctx context.Context) (fw.Capabilities, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fw.Capabilities{}, fw.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return fw.Capabilities{}, err
	}
	c := b.features()
	c.Available = b.handle != 0
	c.Permitted = windows.GetCurrentProcessToken().IsElevated()
	if !c.Permitted {
		c.ProbeError = "elevated administrator token required"
	}
	return c, nil
}

// Inspect reads provider metadata and verifies the owned sublayer association.
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
	var p *provider
	err := call(providerGet, uintptr(b.handle), uintptr(unsafe.Pointer(&b.provider)), uintptr(unsafe.Pointer(&p)))
	if errors.Is(err, windows.Errno(0x80320005)) {
		return fw.NativeState{}, nil
	}
	if err != nil {
		return fw.NativeState{}, wrap(err)
	}
	defer release(&p)
	if p.Data.Size == 0 || p.Data.Size > 4096 || p.Data.Data == nil {
		return fw.NativeState{}, fw.ErrOwnership
	}
	var r record
	if err = json.Unmarshal(unsafe.Slice(p.Data.Data, p.Data.Size), &r); err != nil || r.Magic != "yuhaiin/firewall/v1" || r.Owner != b.config.Owner || !r.State.Active || r.State.Revision.Generation == 0 || len(r.State.Revision.Digest) != 64 || r.State.Lifetime != b.config.Lifetime {
		return fw.NativeState{}, fw.ErrOwnership
	}
	if p.Flags&0x10 != 0 {
		return fw.NativeState{}, fmt.Errorf("%w: WFP provider disabled", fw.ErrUnavailable)
	}
	var sl *sublayer
	if err = call(sublayerGet, uintptr(b.handle), uintptr(unsafe.Pointer(&b.sublayer)), uintptr(unsafe.Pointer(&sl))); err != nil {
		return fw.NativeState{}, wrap(err)
	}
	defer release(&sl)
	if sl.Provider == nil || *sl.Provider != b.provider {
		return fw.NativeState{}, fw.ErrOwnership
	}
	return r.State, nil
}

func (b *Backend) transaction(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := call(txnBegin, uintptr(b.handle), 0); err != nil {
		return wrap(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = call(txnAbort, uintptr(b.handle))
		}
	}()
	if err := fn(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := call(txnCommit, uintptr(b.handle)); err != nil {
		return wrap(err)
	}
	committed = true
	return nil
}

// Replace compiles filters before committing a WFP transaction. Invalid native
// conditions abort the transaction and leave the previous policy effective.
func (b *Backend) Replace(ctx context.Context, expected fw.Revision, s fw.Snapshot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fw.ErrClosed
	}
	checked, err := fw.Compile(s.Policy, b.features())
	if err != nil {
		return err
	}
	if checked.Revision.Digest != s.Revision.Digest || s.Revision.Generation <= expected.Generation {
		return fw.ErrInvalid
	}
	checked.Revision = s.Revision
	s = checked
	a := &arena{}
	defer a.close()
	filters, err := b.compile(s, a)
	if err != nil {
		return err
	}
	return b.transaction(ctx, func() error {
		state, err := b.inspect(ctx)
		if err != nil {
			return err
		}
		if state.Revision != expected {
			return fw.ErrDrift
		}
		if state.Active {
			if err = b.deleteOwned(); err != nil {
				return err
			}
		}
		data, err := json.Marshal(record{Magic: "yuhaiin/firewall/v1", Owner: b.config.Owner, State: fw.NativeState{Active: true, Revision: s.Revision, Lifetime: s.Policy.Lifetime}})
		if err != nil {
			return err
		}
		p := provider{Key: b.provider, Display: display{Name: text("firewall: " + b.config.Owner)}, Data: bytesBlob(data)}
		sl := sublayer{Key: b.sublayer, Display: p.Display, Provider: &b.provider, Weight: 0x8000}
		if s.Policy.Lifetime == fw.Persistent {
			p.Flags = 1
			p.Service = text(b.config.PersistentService)
			sl.Flags = 1
		}
		if err = call(providerAdd, uintptr(b.handle), uintptr(unsafe.Pointer(&p)), 0); err != nil {
			return wrap(err)
		}
		runtime.KeepAlive(data)
		runtime.KeepAlive(p)
		if err = call(sublayerAdd, uintptr(b.handle), uintptr(unsafe.Pointer(&sl)), 0); err != nil {
			return wrap(err)
		}
		runtime.KeepAlive(sl)
		for _, f := range filters {
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = call(filterAdd, uintptr(b.handle), uintptr(unsafe.Pointer(f)), 0, 0); err != nil {
				return wrap(err)
			}
		}
		runtime.KeepAlive(filters)
		return nil
	})
}

func (b *Backend) deleteOwned() error {
	var keys []windows.GUID
	for _, layer := range []windows.GUID{connect4, connect6, receive4, receive6} {
		page, err := b.filterKeys(layer)
		if err != nil {
			return err
		}
		keys = append(keys, page...)
	}
	for _, k := range keys {
		if err := call(filterDelete, uintptr(b.handle), uintptr(unsafe.Pointer(&k))); err != nil {
			return wrap(err)
		}
	}
	if err := call(sublayerDelete, uintptr(b.handle), uintptr(unsafe.Pointer(&b.sublayer))); err != nil {
		return wrap(err)
	}
	return wrap(call(providerDelete, uintptr(b.handle), uintptr(unsafe.Pointer(&b.provider))))
}

func (b *Backend) filterKeys(layer windows.GUID) ([]windows.GUID, error) {
	// A non-nil enumeration template requires a real layer key; zero is not
	// a wildcard. Scope each enumeration by both layer and provider.
	tpl := enumTemplate{Provider: &b.provider, Layer: layer, Type: 1, ActionMask: 0xffffffff}
	var h windows.Handle
	if err := call(filterEnumCreate, uintptr(b.handle), uintptr(unsafe.Pointer(&tpl)), uintptr(unsafe.Pointer(&h))); err != nil {
		return nil, wrap(err)
	}
	defer call(filterEnumDestroy, uintptr(b.handle), uintptr(h))
	var keys []windows.GUID
	for {
		var page **filter
		var count uint32
		err := call(filterEnum, uintptr(b.handle), uintptr(h), 128, uintptr(unsafe.Pointer(&page)), uintptr(unsafe.Pointer(&count)))
		if err != nil {
			return nil, wrap(err)
		}
		if count == 0 {
			if page != nil {
				release(&page)
			}
			break
		}
		for _, f := range unsafe.Slice(page, count) {
			if f.Provider == nil || *f.Provider != b.provider || f.Sublayer != b.sublayer {
				release(&page)
				return nil, fw.ErrOwnership
			}
			keys = append(keys, f.Key)
			if len(keys) > 200000 {
				release(&page)
				return nil, fmt.Errorf("%w: owned filter limit", fw.ErrInvalid)
			}
		}
		release(&page)
	}
	return keys, nil
}

// Remove explicitly removes owned filters, sublayer and provider in one transaction.
func (b *Backend) Remove(ctx context.Context, r fw.Revision) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fw.ErrClosed
	}
	return b.transaction(ctx, func() error {
		s, err := b.inspect(ctx)
		if err != nil {
			return err
		}
		if s.Revision != r {
			return fw.ErrDrift
		}
		if !s.Active {
			return nil
		}
		return b.deleteOwned()
	})
}

// Close closes the engine. WFP removes this session's dynamic filters; persistent
// filters remain until Remove. It does not disable Windows Defender Firewall.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	if err := call(engineClose, uintptr(b.handle)); err != nil {
		return wrap(err)
	}
	b.closed = true
	return windows.CloseHandle(b.mutex)
}
func wrap(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%w: %w", fw.ErrPermission, err)
	}
	return err
}
