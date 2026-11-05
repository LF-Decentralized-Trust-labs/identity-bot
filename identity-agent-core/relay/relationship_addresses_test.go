package relay_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/relay"
	"identity-agent-core/relay/relaytest"
)

// blockFirstAllocate delays the first allocate request until release is closed,
// as a slow relay would.
type blockFirstAllocate struct {
	relay.Signer
	armed   atomic.Bool
	first   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (b *blockFirstAllocate) SignCanonical(aid string, body map[string]interface{}) (string, error) {
	if body["op"] == "allocate" && b.armed.Load() {
		// Only the first call waits. (A sync.Once would hold the others too.)
		if b.first.CompareAndSwap(false, true) {
			close(b.entered)
			<-b.release
		}
	}
	return b.Signer.SignCanonical(aid, body)
}

func startedManager(t *testing.T, cfgFn func(*relay.Config)) (*relay.Manager, *relaytest.Relay, *enrolment) {
	t.Helper()
	rl := relaytest.New(relayproto.ModePrivate)
	t.Cleanup(rl.Close)
	e := newEnrolment(t)
	cfg := relay.Config{
		BaseURL: rl.URL(), Mode: relayproto.ModePrivate, EnrollmentAID: e.aid,
		KEL: func() []byte { return e.kel }, Session: e.keri, Requests: e,
		RAID: e.aid, Handler: identityAgent(), PrivateMayReach: relationshipRoutes,
		TLS: rl.TLS(), HTTPClient: rl.Client(),
	}
	if cfgFn != nil {
		cfgFn(&cfg)
	}
	m := relay.NewManager(cfg)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	waitFor(t, "the relay address", func() bool { return m.URL() != "" })
	return m, rl, e
}

// An address whose secret could not be written down is given back, not kept:
// one nobody can hold again after a restart or give back is lost.
func TestAnAddressThatCannotBeRecordedIsGivenBack(t *testing.T) {
	m, rl, _ := startedManager(t, nil)
	m.OnAllocatedMustSucceed(func([]relay.Allocation) error { return errors.New("the disk is full") })

	_, err := m.AllocateFor(context.Background(), "ERelationshipNotRecorded0000000000000000000")
	if !errors.Is(err, relay.ErrNotRecorded) {
		t.Fatalf("an address that could not be recorded was kept: %v", err)
	}
	if m.AddressFor("ERelationshipNotRecorded0000000000000000000") != nil {
		t.Error("the manager still lists the address")
	}
	waitFor(t, "the relay to hold only the primary address", func() bool {
		return len(m.RelationshipAddresses()) == 0
	})
	// The relay has been told to forget it: it holds exactly the primary.
	held := 0
	for _, a := range m.Allocations() {
		if rl.Holds(a.Label) {
			held++
		}
	}
	if held != 1 {
		t.Errorf("the relay holds %d of this agent's addresses, want only the primary", held)
	}
}

// A slow relay holds up the relationship it is making an address for, and
// nobody else: the lock that orders changes to the held addresses is not held
// across the request.
func TestASlowAllocationDoesNotHoldUpOtherRelationships(t *testing.T) {
	slow := &blockFirstAllocate{entered: make(chan struct{}), release: make(chan struct{})}
	m, _, _ := startedManager(t, func(c *relay.Config) {
		slow.Signer = c.Requests
		c.Requests = slow
	})
	slow.armed.Store(true) // the primary address was made before this

	first := make(chan error, 1)
	go func() {
		_, err := m.AllocateFor(context.Background(), "EFirstRelationship0000000000000000000000")
		first <- err
	}()
	select {
	case <-slow.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first allocation never reached the relay")
	}

	// While the first waits on the relay, another relationship is made, and
	// one is ended.
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := m.AllocateFor(ctx, "ESecondRelationship000000000000000000000")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the second relationship was held up by the first: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the second relationship waited on the first's slow allocation")
	}
	close(slow.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

// The number of addresses an agent holds for its relationships is bounded, and
// giving one back makes room.
func TestRelationshipAddressesAreCapped(t *testing.T) {
	m, _, _ := startedManager(t, func(c *relay.Config) { c.MaxRelationshipAddresses = 2 })
	ctx := context.Background()
	for _, aid := range []string{"ECapOne0000000000000000000000000000000000", "ECapTwo0000000000000000000000000000000000"} {
		if _, err := m.AllocateFor(ctx, aid); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.AllocateFor(ctx, "ECapThree00000000000000000000000000000000"); !errors.Is(err, relay.ErrTooManyAddresses) {
		t.Fatalf("an address was made past the cap: %v", err)
	}
	// One already held is returned, not refused.
	if _, err := m.AllocateFor(ctx, "ECapOne0000000000000000000000000000000000"); err != nil {
		t.Errorf("an existing relationship's address was refused at the cap: %v", err)
	}
	if err := m.ReleaseFor(ctx, "ECapOne0000000000000000000000000000000000"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AllocateFor(ctx, "ECapThree00000000000000000000000000000000"); err != nil {
		t.Errorf("giving an address back did not make room: %v", err)
	}
}
