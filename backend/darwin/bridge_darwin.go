// Package darwin coordinates a signed Network Extension host. It never invokes
// PF or performs per-packet IPC. Build/sign the host under native/darwin first.
package darwin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/unix"
)

// Config selects the signed app executable and its configured owner. The host's
// bundle/app-group/signing identifiers are build settings, not Go runtime flags.
// LockDir is private, shared by clients of this host, and must already exist.
type Config struct{ HostExecutable, Owner, LockDir string }

// Backend delegates control operations to a minimal signed Swift host.
type Backend struct {
	mu     sync.Mutex
	config Config
	lock   *os.File
	closed bool
}
type request struct {
	Command  string       `json:"command"`
	Owner    string       `json:"owner"`
	Expected fw.Revision  `json:"expected"`
	Snapshot *fw.Snapshot `json:"snapshot,omitempty"`
}
type response struct {
	State     fw.NativeState `json:"state"`
	Available bool           `json:"available"`
	Permitted bool           `json:"permitted"`
	Error     string         `json:"error"`
	Code      string         `json:"code"`
}

// New acquires exclusive ownership without activating the extension or filter.
// Activation and user approval are explicit deployment steps.
func New(c Config) (*Backend, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: the signed host must run as root to share the system extension's app-group container", fw.ErrPermission)
	}
	if c.Owner == "" || !filepath.IsAbs(c.HostExecutable) || !filepath.IsAbs(c.LockDir) {
		return nil, fmt.Errorf("%w: absolute host/lock directory and owner required", fw.ErrInvalid)
	}
	info, err := os.Stat(c.LockDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fw.ErrOwnership
	}
	fd, err := unix.Open(filepath.Join(c.LockDir, "networkextension.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "networkextension.lock")
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fw.ErrOwnership
	}
	return &Backend{config: c, lock: f}, nil
}
func features() fw.Capabilities {
	return fw.Capabilities{Backend: "networkextension", IPv4: true, IPv6: true, Inbound: true, Outbound: true, Negation: true, Stateful: true, Persistent: true, Fields: map[fw.Field]bool{fw.Protocol: true, fw.SourcePrefix: true, fw.DestinationPrefix: true, fw.SourcePort: true, fw.DestinationPort: true, fw.Application: true}}
}

// Capabilities distinguishes compiled support from the signed host's probe.
func (b *Backend) Capabilities(ctx context.Context) (fw.Capabilities, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.invoke(ctx, request{Command: "probe"})
	c := features()
	if canceled := ctx.Err(); canceled != nil {
		return c, canceled
	}
	if err != nil {
		c.ProbeError = err.Error()
		return c, nil
	}
	c.Available = r.Available
	c.Permitted = r.Permitted
	return c, nil
}

// Inspect queries the data provider's active in-memory revision over control IPC.
func (b *Backend) Inspect(ctx context.Context) (fw.NativeState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, err := b.invoke(ctx, request{Command: "inspect"})
	return r.State, err
}

// Replace persists a validated snapshot and waits for the data provider to swap
// its in-memory rules. Existing allowed flows are not forcibly terminated.
func (b *Backend) Replace(ctx context.Context, expected fw.Revision, s fw.Snapshot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	checked, err := fw.Compile(s.Policy, features())
	if err != nil {
		return err
	}
	if checked.Revision.Digest != s.Revision.Digest || s.Revision.Generation <= expected.Generation {
		return fw.ErrInvalid
	}
	checked.Revision = s.Revision
	for _, r := range checked.Rules {
		for _, term := range r.Terms {
			for _, l := range term {
				if l.Match.Field == fw.Protocol && l.Match.Number != 6 && l.Match.Number != 17 {
					return fmt.Errorf("%w: macOS supports TCP/UDP flow policies only", fw.ErrUnsupported)
				}
			}
		}
	}
	r, err := b.invoke(ctx, request{Command: "replace", Expected: expected, Snapshot: &checked})
	if err != nil {
		return err
	}
	if !r.State.Active || r.State.Revision != s.Revision {
		return fw.ErrDrift
	}
	return nil
}

// Remove disables and removes this host's content-filter configuration explicitly.
func (b *Backend) Remove(ctx context.Context, r fw.Revision) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.invoke(ctx, request{Command: "remove", Expected: r})
	return err
}

// Close releases only the Go handle. macOS policies have system-managed lifetime.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	return b.lock.Close()
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p)+b.Len() > 1<<20 {
		return 0, fmt.Errorf("native response exceeds limit")
	}
	return b.Buffer.Write(p)
}
func (b *Backend) invoke(ctx context.Context, r request) (response, error) {
	if b.closed {
		return response{}, fw.ErrClosed
	}
	r.Owner = b.config.Owner
	data, err := json.Marshal(r)
	if err != nil {
		return response{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.config.HostExecutable)
	cmd.Stdin = bytes.NewReader(data)
	var out, stderr limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		kind := fw.ErrUnavailable
		if r.Command == "replace" || r.Command == "remove" {
			kind = fw.ErrIndeterminate
		}
		return response{}, fmt.Errorf("%w: signed host: %w: %s", kind, err, stderr.String())
	}
	var result response
	dec := json.NewDecoder(&out)
	if err = dec.Decode(&result); err != nil {
		return response{}, fmt.Errorf("native response: %w", err)
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return response{}, fmt.Errorf("invalid trailing native response")
	}
	if result.Error != "" {
		kind := fw.ErrUnavailable
		switch result.Code {
		case "invalid":
			kind = fw.ErrInvalid
		case "ownership":
			kind = fw.ErrOwnership
		case "drift":
			kind = fw.ErrDrift
		case "permission":
			kind = fw.ErrPermission
		case "unsupported":
			kind = fw.ErrUnsupported
		case "indeterminate":
			kind = fw.ErrIndeterminate
		}
		return response{}, fmt.Errorf("%w: %s", kind, result.Error)
	}
	return result, nil
}
