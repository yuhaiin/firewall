package firewall

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

type mockDriver struct {
	state  NativeState
	fail   error
	block  chan struct{}
	closed bool
}

func (d *mockDriver) Capabilities(context.Context) (Capabilities, error) {
	return testCapabilities(), nil
}
func (d *mockDriver) Inspect(context.Context) (NativeState, error) { return d.state, nil }
func (d *mockDriver) Replace(ctx context.Context, r Revision, s Snapshot) error {
	if d.block != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.block:
		}
	}
	if d.fail != nil {
		return d.fail
	}
	if d.state.Revision != r {
		return ErrDrift
	}
	d.state = NativeState{Active: true, Revision: s.Revision, Lifetime: s.Policy.Lifetime}
	return nil
}
func (d *mockDriver) Remove(_ context.Context, r Revision) error {
	if r != d.state.Revision {
		return ErrDrift
	}
	d.state = NativeState{}
	return nil
}
func (d *mockDriver) Close() error {
	if d.state.Lifetime == Temporary {
		d.state = NativeState{}
	}
	d.closed = true
	return nil
}
func newTestClient(t *testing.T) (*Client, *mockDriver) {
	t.Helper()
	d := &mockDriver{}
	c, err := New(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, d
}

func TestRollbackRecoveryAndLifecycle(t *testing.T) {
	c, d := newTestClient(t)
	p := testPolicy()
	r, err := c.Apply(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	p.Rules[0].Action = Allow
	d.fail = errors.New("transaction rejected")
	if _, err = c.Apply(t.Context(), p); err == nil {
		t.Fatal("expected failure")
	}
	state, err := c.Current(t.Context())
	if err != nil || state.Revision != r || state.Policy.Rules[0].Action != Drop {
		t.Fatalf("rollback: %+v %v", state, err)
	}
	state.Policy.Rules[0].Action = Log
	state, _ = c.Current(t.Context())
	if state.Policy.Rules[0].Action != Drop {
		t.Fatal("Current aliases policy")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if !d.state.Active {
		t.Fatal("Close removed persistent policy")
	}
	d.closed = false
	recovered, err := New(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	state, err = recovered.Current(t.Context())
	if err != nil || state.Policy != nil || state.Revision != r {
		t.Fatalf("recovery %+v %v", state, err)
	}
	d.fail = nil
	p = testPolicy()
	r2, err := recovered.Apply(t.Context(), p)
	if err != nil || r2 != r {
		t.Fatalf("idempotency: %v %v", r2, err)
	}
	if err = recovered.Remove(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = recovered.Remove(t.Context()); err != nil {
		t.Fatal(err)
	}
	if d.state.Active {
		t.Fatal("Remove left enforcement")
	}
}
func TestConcurrentApplyAndCancellation(t *testing.T) {
	c, _ := newTestClient(t)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			p := testPolicy()
			p.Rules[0].Priority = int32(i)
			if _, err := c.Apply(t.Context(), p); err != nil {
				t.Error(err)
			}
			if _, err := c.Current(t.Context()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	s, err := c.Current(t.Context())
	if err != nil || s.Revision.Generation != 32 {
		t.Fatalf("concurrent revision %+v %v", s, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = c.Apply(ctx, testPolicy()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Current(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
func TestEventsOverflowAndCancellation(t *testing.T) {
	c, _ := newTestClient(t)
	ctx, cancel := context.WithCancel(t.Context())
	ch, err := c.Events(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for range 70 {
		c.publish(Event{Kind: "test"})
	}
	for range 64 {
		<-ch
	}
	c.publish(Event{Kind: "after"})
	if e := <-ch; e.Dropped != 6 {
		t.Fatalf("lost=%d", e.Dropped)
	}
	cancel()
	for range ch {
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Events(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
func TestTemporaryAndDrift(t *testing.T) {
	c, d := newTestClient(t)
	p := testPolicy()
	p.Lifetime = Temporary
	if _, err := c.Apply(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	d.state.Revision.Generation++
	if _, err := c.Current(t.Context()); !errors.Is(err, ErrDrift) {
		t.Fatal(err)
	}
	if _, err := c.Apply(t.Context(), p); !errors.Is(err, ErrDrift) {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if d.state.Active {
		t.Fatal("temporary policy remains")
	}
}
func BenchmarkEventQueue(b *testing.B) {
	c, _ := New(b.Context(), &mockDriver{})
	defer c.Close()
	ch, _ := c.Events(b.Context())
	b.ReportAllocs()
	for b.Loop() {
		c.publish(Event{})
		<-ch
	}
}
func BenchmarkConcurrentReadsUpdates(b *testing.B) {
	c, _ := New(b.Context(), &mockDriver{})
	defer c.Close()
	p := testPolicy()
	c.Apply(b.Context(), p)
	b.ReportAllocs()
	var operations atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if n := operations.Add(1); n%16 == 0 {
				p := testPolicy()
				p.Rules[0].Priority = int32(n)
				if _, err := c.Apply(b.Context(), p); err != nil {
					b.Error(err)
				}
				continue
			}
			if _, err := c.Current(b.Context()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestExplicitReconciliation(t *testing.T) {
	c, d := newTestClient(t)
	p := testPolicy()
	first, err := c.Apply(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Reconcile(t.Context(), p)
	if err != nil || second.Generation != first.Generation+1 {
		t.Fatalf("forced replacement: %+v %v", second, err)
	}
	d.state = NativeState{} // External native object deletion.
	if _, err = c.Apply(t.Context(), p); !errors.Is(err, ErrDrift) {
		t.Fatal(err)
	}
	third, err := c.Reconcile(t.Context(), p)
	if err != nil || third.Generation != second.Generation+1 || !d.state.Active {
		t.Fatalf("reconcile missing objects: %+v %v", third, err)
	}
}

func TestCanceledInitialization(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := New(ctx, &mockDriver{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("initialization cancellation: %v", err)
	}
}
