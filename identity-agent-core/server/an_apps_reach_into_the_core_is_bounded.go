package server

import (
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"identity-agent-core/limits"
	"identity-agent-core/mediation"
	"identity-agent-core/trail"
)

// An app is held to limits that protect the Identity Agent from it (ADR-069), at the one place an app's back end meets the routes people talk
// through: thePersonAsking, which every request an app's back end signs for a
// person passes before any route acts on it.
//
//   - a request rate per app, with a retry time that backs off while the app
//     keeps asking (limits.Rate.Try);
//   - the numbers the conversation trail is held to (forwarding timeout, read
//     size, entries per conversation, messages an hour, turns): AppLimits, which
//     an add-on passes to trail.New;
//   - the delivery queue for sealed messages, kept in a file in the data
//     directory so a restart does not lose a message the sender was told was
//     queued: DeliveryQueue.

// deliveryQueueFile is where the delivery queue is kept, in the data directory.
const deliveryQueueFile = "delivery-queue.json"

// appLimitState is the rate limiter and the delivery queue, made the first time
// either is asked for.
type appLimitState struct {
	once  sync.Once
	rate  *limits.Rate
	queue *mediation.Queue
	qerr  error
}

// SetLimits replaces the limits before the server serves. A phone passes
// limits.Defaults().ForPhone().
func (s *CoreServer) SetLimits(l limits.Limits) {
	s.limitsMu.Lock()
	defer s.limitsMu.Unlock()
	s.limits = l.WithDefaults()
}

// AppLimits is the limits apps are held to.
func (s *CoreServer) AppLimits() limits.Limits {
	s.limitsMu.Lock()
	defer s.limitsMu.Unlock()
	return s.limits.WithDefaults()
}

func (s *CoreServer) appLimitState() *appLimitState {
	st := &s.appLimits
	st.once.Do(func() {
		l := s.AppLimits()
		st.rate = limits.NewRate(l, nil)
		st.queue, st.qerr = mediation.Open(filepath.Join(s.DataDir, deliveryQueueFile), l, nil)
	})
	return st
}

// DeliveryQueue is the queue of sealed messages held for a recipient that is
// briefly offline, as it was when this server last stopped, for an add-on whose
// conversation record is t. Naming the trail is the price of the queue: the core
// marks an expired delivery in it, on every tick, so nothing can be held that the
// core cannot expire. A nil trail is refused. Each add-on names its own trail;
// the queue is one. A queue file that cannot be read is an error, and is left as
// it is.
func (s *CoreServer) DeliveryQueue(t *trail.Trail) (*mediation.Queue, error) {
	if t == nil {
		return nil, errors.New("the delivery queue needs the trail an expired delivery is marked in")
	}
	st := s.appLimitState()
	if st.qerr != nil {
		return nil, st.qerr
	}
	s.expiryMu.Lock()
	known := false
	for _, k := range s.expiryTrails {
		known = known || k == t
	}
	if !known {
		s.expiryTrails = append(s.expiryTrails, t)
	}
	s.expiryMu.Unlock()
	return st.queue, nil
}

// theQueue is the queue without naming a trail, for the core's own tick, which
// holds nothing in it.
func (s *CoreServer) theQueue() (*mediation.Queue, error) {
	st := s.appLimitState()
	return st.queue, st.qerr
}

// refuseExpiredDeliveries is the core's part of each tick. Every message the
// queue has held for its whole age is marked not delivered in the trail that
// keeps its conversation, then deleted. A message whose conversation no trail
// keeps, or more than one does, is left held and logged: it is never deleted
// ahead of the record that explains it.
func (s *CoreServer) refuseExpiredDeliveries() {
	s.expiryMu.Lock()
	trails := append([]*trail.Trail(nil), s.expiryTrails...)
	s.expiryMu.Unlock()
	if len(trails) == 0 {
		return
	}
	q, err := s.theQueue()
	if err != nil {
		log.Printf("[delivery] queue: %v", err)
		return
	}
	for _, d := range q.Due() {
		var owner *trail.Trail
		n := 0
		for _, t := range trails {
			if t.Keeps(d.Conversation) {
				owner, n = t, n+1
			}
		}
		if n != 1 {
			log.Printf("[delivery] %s is past its age and %d trails keep its conversation: left held", d.ID, n)
			continue
		}
		told, err := owner.RefuseExpired(q, d.ID)
		if err != nil {
			log.Printf("[delivery] expiring: %v", err)
		}
		for _, x := range told {
			log.Printf("[delivery] %s was not delivered in time and is refused", x.ID)
		}
	}
}

// AppOverItsRate is what a request from an app's back end is refused with when
// the app is over its rate. Wait is when it may try again.
type AppOverItsRate struct{ Wait time.Duration }

func (e *AppOverItsRate) Error() string {
	return fmt.Sprintf("this app has made too many requests; try again in %s", e.Wait.Round(time.Second))
}

// holdAppToItsRate takes one request for the app a machine is the back end of.
// A machine bound to no app is not held here: it is a person's own device.
func (s *CoreServer) holdAppToItsRate(app string) error {
	if app == "" {
		return nil
	}
	if ok, wait := s.appLimitState().rate.Try(app, rand.Float64()); !ok {
		return &AppOverItsRate{Wait: wait}
	}
	return nil
}

// TheAppIsOverItsRate says whether err is a refusal for the app's rate, and
// when to try again.
func TheAppIsOverItsRate(err error) (time.Duration, bool) {
	var e *AppOverItsRate
	if errors.As(err, &e) {
		return e.Wait, true
	}
	return 0, false
}

// RefuseAnAppOverItsRate answers a request with 429 and a Retry-After in whole
// seconds (at least one), when err is the refusal for an app's rate, and says
// so. A route that asks ThePersonAsking calls it first with the error, and goes
// on to its own errors only when it returns false.
func RefuseAnAppOverItsRate(w http.ResponseWriter, err error) bool {
	wait, ok := TheAppIsOverItsRate(err)
	if !ok {
		return false
	}
	secs := max(1, int(math.Ceil(wait.Seconds())))
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, err.Error(), "")
	return true
}
