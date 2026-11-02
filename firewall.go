package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"
)

// Client serializes native transactions and maintains bounded subscriptions.
// It must be closed. Persistent policies are removed only by Remove.
type Client struct {
	driver       Driver
	gate         chan struct{}
	closed       bool
	known        *Policy
	revision     Revision
	events       sync.Mutex
	subs         map[*subscription]struct{}
	eventsClosed bool
}
type subscription struct {
	ch   chan Event
	lost uint64
	stop func() bool
}

// New takes ownership of driver on success. On failure the caller still owns it.
// It probes and inspects existing state without installing or removing rules.
func New(ctx context.Context, driver Driver) (*Client, error) {
	if driver == nil {
		return nil, fmt.Errorf("%w: nil driver", ErrInvalid)
	}
	caps, err := driver.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if !caps.Available {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, caps.ProbeError)
	}
	if !caps.Permitted {
		return nil, fmt.Errorf("%w: %s", ErrPermission, caps.ProbeError)
	}
	s, err := driver.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	c := &Client{driver: driver, gate: make(chan struct{}, 1), revision: s.Revision, subs: map[*subscription]struct{}{}}
	c.gate <- struct{}{}
	return c, nil
}

func (c *Client) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.gate:
	}
	if err := ctx.Err(); err != nil {
		c.unlock()
		return err
	}
	if c.closed {
		c.unlock()
		return ErrClosed
	}
	return nil
}
func (c *Client) unlock() { c.gate <- struct{}{} }

// Capabilities probes the backend's current availability and permission.
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := c.lock(ctx); err != nil {
		return Capabilities{}, err
	}
	defer c.unlock()
	return c.driver.Capabilities(ctx)
}

// Apply compiles the entire policy before a native atomic replacement. Failed
// validation or installation leaves the previous policy in place. Cancellation
// before commit aborts; after native commit the committed revision is returned.
func (c *Client) Apply(ctx context.Context, p Policy) (Revision, error) {
	return c.apply(ctx, p, false)
}

// Reconcile explicitly restores the complete desired policy, even when native
// metadata has the same digest. Use it after external object deletion or an
// ambiguous commit error. It supersedes the current revision of this owner;
// unlike Apply, it does not reject a changed generation observed by Inspect.
func (c *Client) Reconcile(ctx context.Context, p Policy) (Revision, error) {
	return c.apply(ctx, p, true)
}

func (c *Client) apply(ctx context.Context, p Policy, reconcile bool) (Revision, error) {
	if err := c.lock(ctx); err != nil {
		return Revision{}, err
	}
	defer c.unlock()
	caps, err := c.driver.Capabilities(ctx)
	if err != nil {
		return Revision{}, c.failure(err)
	}
	if !caps.Available || !caps.Permitted {
		return Revision{}, c.failure(fmt.Errorf("%w: %s", ErrUnavailable, caps.ProbeError))
	}
	s, err := Compile(p, caps)
	if err != nil {
		return Revision{}, err
	}
	if err = ctx.Err(); err != nil {
		return Revision{}, err
	}
	state, err := c.driver.Inspect(ctx)
	if err != nil {
		return Revision{}, c.failure(err)
	}
	if state.Revision != c.revision && !reconcile {
		return Revision{}, c.failure(ErrDrift)
	}
	if !reconcile && state.Active && s.Revision.Digest == state.Revision.Digest {
		c.known = &s.Policy
		return state.Revision, nil
	}
	generation := max(c.revision.Generation, state.Revision.Generation)
	if generation == math.MaxUint64 {
		return Revision{}, fmt.Errorf("%w: generation exhausted", ErrInvalid)
	}
	s.Revision.Generation = generation + 1
	if err = c.driver.Replace(ctx, state.Revision, s); err != nil {
		return Revision{}, c.failure(err)
	}
	c.revision = s.Revision
	c.known = &s.Policy
	c.publish(Event{Time: time.Now(), Kind: "policy_applied", Revision: s.Revision})
	return s.Revision, nil
}

// Current reads native metadata, reporting drift instead of returning stale
// desired state as actual enforcement. It does not reconstruct rule source.
func (c *Client) Current(ctx context.Context) (PolicyState, error) {
	if err := c.lock(ctx); err != nil {
		return PolicyState{}, err
	}
	defer c.unlock()
	s, err := c.driver.Inspect(ctx)
	if err != nil {
		return PolicyState{}, c.failure(err)
	}
	if s.Revision != c.revision {
		return PolicyState{NativeState: s}, ErrDrift
	}
	out := PolicyState{NativeState: s}
	if c.known != nil && s.Active {
		b, err := json.Marshal(c.known)
		if err != nil {
			return PolicyState{}, err
		}
		if err = json.Unmarshal(b, &out.Policy); err != nil {
			return PolicyState{}, err
		}
	}
	return out, nil
}

// Remove explicitly removes owned enforcement. The operation is idempotent.
// It does not disable any other firewall product.
func (c *Client) Remove(ctx context.Context) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if err := c.driver.Remove(ctx, c.revision); err != nil {
		return c.failure(err)
	}
	c.known = nil
	c.revision = Revision{}
	c.publish(Event{Time: time.Now(), Kind: "policy_removed"})
	return nil
}

// Close releases the backend and subscriptions. Temporary policy cleanup may
// fail; an error is returned and Close can be retried. Persistent rules remain.
func (c *Client) Close() error {
	<-c.gate
	defer c.unlock()
	if c.closed {
		return nil
	}
	if err := c.driver.Close(); err != nil {
		return c.failure(err)
	}
	c.closed = true
	c.events.Lock()
	defer c.events.Unlock()
	c.eventsClosed = true
	for s := range c.subs {
		if s.stop != nil {
			s.stop()
		}
		close(s.ch)
		delete(c.subs, s)
	}
	return nil
}

// Events subscribes to lifecycle events, with 64 entries and at most 64
// subscribers. Overflow drops the newest event and reports loss on the next
// delivered event. Canceling ctx or closing the Client closes the channel.
// Native connection logging is available only if ConnectionEvents is true.
func (c *Client) Events(ctx context.Context) (<-chan Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.events.Lock()
	defer c.events.Unlock()
	if c.eventsClosed {
		return nil, ErrClosed
	}
	if len(c.subs) >= 64 {
		return nil, fmt.Errorf("%w: subscription limit", ErrUnavailable)
	}
	s := &subscription{ch: make(chan Event, 64)}
	c.subs[s] = struct{}{}
	s.stop = context.AfterFunc(ctx, func() {
		c.events.Lock()
		defer c.events.Unlock()
		if _, ok := c.subs[s]; ok {
			delete(c.subs, s)
			close(s.ch)
		}
	})
	return s.ch, nil
}

func (c *Client) publish(e Event) {
	c.events.Lock()
	defer c.events.Unlock()
	for s := range c.subs {
		e.Dropped = s.lost
		select {
		case s.ch <- e:
			s.lost = 0
		default:
			s.lost++
		}
	}
}
func (c *Client) failure(err error) error {
	c.publish(Event{Time: time.Now(), Kind: "backend_error", Revision: c.revision, Reason: err.Error()})
	return err
}
