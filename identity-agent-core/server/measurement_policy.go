package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"identity-agent-core/atomicfile"
	"identity-agent-core/iacrypto"
	"identity-agent-core/measurementlist"
	"identity-agent-core/measurementlist/anchored"
)

// Which software an owner will adopt a sealed box for.
//
// A launch measurement says what a machine booted. Deciding whether that is
// software you accept is a separate question, and not one the machine being
// checked can answer — it is the owner's policy, so it has to arrive from the
// owner's side or the check is the box marking its own work.
//
// Two ways in, both the owner's:
//
//   - The published list of accepted software (package measurementlist/anchored):
//     a credential issued under the publisher's identity, which this build pins
//     (an identifier, never a key), and anchored in that identity's witnessed
//     key history. An app hands the core a candidate bundle on
//     POST /api/measurement-list; the core asks the publisher's witnesses for
//     the publisher's latest state itself, checks the bundle against it and
//     against the floors it keeps, and only then stages the list. A staged
//     list is the policy for a short time after that check and while its own
//     dates hold (see measurementLists.policy), and nothing else is added to
//     it — except by the owner's own statement on one adoption request, below,
//     which survives an accepted list on purpose. Nothing is read from a file
//     or the environment: whoever delivers bytes decides nothing.
//   - AGENT_ACCEPTED_MEASUREMENTS on this agent, for a standing policy that
//     survives restarts. It is the bootstrap: used only while no list has ever
//     been accepted here; after one has, it is never used again.
//   - accepted_measurements on the adoption request itself, for one adoption.
//     /api/pairing/adopt is owner-only, so this is the owner speaking, not the
//     box — but see the warning on the request field. It is kept after a list
//     has been accepted because it is the owner's own signed-in statement, not
//     a policy anyone else can supply; it can only ADD the values the owner
//     named in that one request, and never reopens the bootstrap or anything
//     else a refused list rules out (acceptableOrOwnerNamed).
//
// An empty policy stays a refusal. It would be easy to read "no list" as
// "accept anything", and that single default would make every other check in
// the adoption path decorative: the report would be parsed, bound to the
// offered keys, checked for debug mode, and then measured against nothing.

// parseMeasurements reads measurements written as hex.
//
// Hex because that is how a measurement is published, printed by the image
// build, and compared by eye. Accepting base64 as well would mean two ways to
// write the same value and a class of "why does this not match" that costs an
// afternoon.
func parseMeasurements(values []string) ([][]byte, error) {
	var out [][]byte
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		raw, err := iacrypto.DecodeHex(v)
		if err != nil {
			return nil, fmt.Errorf("%q is not lowercase hex, so it is not a measurement: %w", short(v), err)
		}
		// SEV-SNP measurements are 48 bytes. A wrong length is almost always a
		// truncated copy-paste, and it would otherwise fail later as a
		// mismatch — which reads as "this box is running something else"
		// rather than "you pasted half a value".
		if len(raw) != 48 {
			return nil, fmt.Errorf("%q decodes to %d bytes; a launch measurement is 48",
				short(v), len(raw))
		}
		out = append(out, raw)
	}
	return out, nil
}

// acceptedMeasurementsFromEnv reads the standing policy for this agent.
//
// Separated by commas or whitespace, so a value pasted from a list, a shell
// variable or a config file all work without thinking about it.
func acceptedMeasurementsFromEnv() ([][]byte, error) {
	v := os.Getenv("AGENT_ACCEPTED_MEASUREMENTS")
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	m, err := parseMeasurements(fields)
	if err != nil {
		return nil, fmt.Errorf("AGENT_ACCEPTED_MEASUREMENTS: %w", err)
	}
	return m, nil
}

// shortMeasurement trims a value for an error message. A measurement is 96 characters and
// a mistyped one is usually recognisable from its start.
func shortMeasurement(v string) string {
	if len(v) <= 20 {
		return v
	}
	return v[:20] + "…"
}

// measurementFloorsFile is where the floors are kept (anchored.FileFloors): the
// highest list sequence accepted and the list accepted at it, and the newest
// place of the publisher's key history seen.
const measurementFloorsFile = "measurement_list_floors.json"

// measurementDuplicityFile keeps the evidence when a publisher's history
// conflicts with the one this core holds: the place, both digests and the
// signed message offered.
const measurementDuplicityFile = "measurement_publisher_duplicity.json"

// listFreshFor is how long after the publisher's witnesses were asked a list is
// still used for a decision. A withdrawal or a newer list can only be seen by
// asking again, so this is the longest a withdrawn list can outlive its
// withdrawal here; an adoption asks first (the app calls the route before it
// offers one), so for an adoption the answer is as fresh as the question.
const listFreshFor = time.Hour

// acceptedMeasurements is the policy without the reason, for callers that only
// need the measurements. The error is only for a malformed bootstrap.
func acceptedMeasurements(dataDir, entityType string, now time.Time) ([][]byte, error) {
	m, _, err := (&measurementLists{dataDir: dataDir}).policy(entityType, now)
	return m, err
}

// measurementLists is what a core knows of the publisher's list: the floors on
// disk and the list it last checked (in memory only: after a restart it has to
// be checked again, with the witnesses, before it decides anything).
type measurementLists struct {
	dataDir string
	// pin is what this build trusts; nil is anchored.Pinned.
	pin func() (anchored.Pin, error)
	// asker is who asks the publisher's witnesses; nil means nobody can be asked.
	asker func() anchored.TipAsker
	now   func() time.Time

	mu       sync.Mutex
	staged   *measurementlist.List
	stagedAt time.Time
}

func (m *measurementLists) floors() anchored.FileFloors {
	return anchored.FileFloors{Path: filepath.Join(m.dataDir, measurementFloorsFile)}
}

func (m *measurementLists) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// policy decides this agent's standing policy at time now: the list checked
// with the publisher's witnesses, if there is a fresh one, otherwise the
// bootstrap from the environment — but the bootstrap only until a list has ever
// been accepted here.
//
// Once a list has been accepted (the recorded floor is above zero) the
// bootstrap is never consulted again. The bootstrap is the oldest policy there
// is; letting any list failure fall back to it would let a restart, a deleted
// file, an older list or an expired one force that policy, and undo the
// rollback protection the floor exists for. From then on every failure of the
// list means NO measurement is accepted, and the second result says why.
//
// Fail closed at every step. A verified list that names nothing for this
// agent's image kind yields an empty policy, which acceptableMeasurement
// refuses: the publisher has said nothing is acceptable.
func (m *measurementLists) policy(entityType string, now time.Time) ([][]byte, string, error) {
	floors, floorErr := m.floors().Load()
	if floorErr != nil {
		// A damaged record is not "nothing accepted yet".
		why := fmt.Sprintf("the record of the newest accepted list of software cannot be read, so no box is accepted: %v", floorErr)
		log.Printf("[identity-agent-core] %s", why)
		return nil, why, nil
	}
	everAccepted := floors.ListSequence > 0

	m.mu.Lock()
	list, at := m.staged, m.stagedAt
	m.mu.Unlock()

	var listErr error
	switch {
	case list != nil && now.Before(at):
		listErr = errors.New("this computer's clock is earlier than when the list was last checked")
	case list != nil && now.Sub(at) > listFreshFor:
		listErr = fmt.Errorf("the list was last checked with the publisher's witnesses at %s, which is too long ago to rely on: a withdrawal could have come since",
			at.UTC().Format(time.RFC3339))
	case list != nil && !now.Before(list.ExpiresAt):
		listErr = fmt.Errorf("the list expired at %s", list.ExpiresAt.UTC().Format(time.RFC3339))
	case list != nil:
		if entityType == "" {
			why := "a list of software verified but this agent does not declare its image kind, so no box is accepted"
			log.Printf("[identity-agent-core] %s", why)
			return nil, why, nil
		}
		out := list.MeasurementsAt(entityType, now)
		log.Printf("[identity-agent-core] using the publisher's list sequence %d: %d accepted for %q", list.Sequence, len(out), entityType)
		return out, "", nil
	case everAccepted:
		listErr = errors.New("the list has not been checked with the publisher's witnesses since this core started")
	}
	if everAccepted {
		why := fmt.Sprintf("a list of software (sequence %d) was accepted here before and the list now cannot be used (%v); "+
			"the older bootstrap policy is never used again, so no box is accepted until the list is checked again",
			floors.ListSequence, listErr)
		log.Printf("[identity-agent-core] %s", why)
		return nil, why, nil
	}
	m.mu.Lock()
	staged := m.staged != nil
	m.mu.Unlock()
	if staged {
		// a list was checked this run, so a floor should exist; one that does not
		// is the floors file removed, not "nothing was ever accepted"
		why := fmt.Sprintf("a list was checked here but its record is gone (%v), so no box is accepted", listErr)
		log.Printf("[identity-agent-core] %s", why)
		return nil, why, nil
	}
	b, err := acceptedMeasurementsFromEnv()
	return b, "", err
}

// check is the whole of the route's work: the bundle is checked against the pin,
// the floors and the publisher's witnesses (asked now), and staged if it holds.
func (m *measurementLists) check(ctx context.Context, raw []byte) (*anchored.Result, error) {
	pinFn := m.pin
	if pinFn == nil {
		pinFn = anchored.Pinned
	}
	pin, err := pinFn()
	if err != nil {
		return nil, err
	}
	b, err := anchored.ParseBundle(raw)
	if err != nil {
		return nil, err
	}
	var asker anchored.TipAsker
	if m.asker != nil {
		asker = m.asker()
	}
	checker := &anchored.Checker{Pin: pin, Store: m.floors()}
	now := m.clock()
	res, err := checker.CheckAsking(b, anchored.Resolver{Witnesses: asker}.Asker(ctx), now)
	if err != nil {
		var dup *anchored.Duplicity
		if errors.As(err, &dup) {
			m.recordDuplicity(dup)
		}
		return nil, err
	}
	m.mu.Lock()
	m.staged, m.stagedAt = res.List, now
	m.mu.Unlock()
	return res, nil
}

// recordDuplicity keeps the evidence of a conflicting history. It is never read
// back to accept anything; it is what the owner or a watcher is shown.
func (m *measurementLists) recordDuplicity(d *anchored.Duplicity) {
	rec, _ := json.Marshal(map[string]any{"sn": d.SN, "held": d.Held, "offered": d.Offered,
		"offered_message_b64": base64.StdEncoding.EncodeToString(d.Message), "seen_at": m.clock().UTC().Format(time.RFC3339)})
	if err := atomicfile.Write(filepath.Join(m.dataDir, measurementDuplicityFile), append(rec, '\n'), 0o600); err != nil {
		log.Printf("[identity-agent-core] the publisher's history conflicts with the one held here (place %d), and the evidence could not be kept: %v", d.SN, err)
		return
	}
	log.Printf("[identity-agent-core] THE PUBLISHER'S HISTORY CONFLICTS with the one held here at place %d: evidence kept in %s", d.SN, measurementDuplicityFile)
}

// currentMeasurements is the policy to decide with, right now. A server built
// with a policy function decides it on every call, so a list that expired or
// went stale since startup is not honoured on a decision made today. The second
// result is why nothing is accepted, when that is the list's doing.
func (s *CoreServer) currentMeasurements() ([][]byte, string) {
	if s.measurementPolicy == nil {
		return s.AcceptedMeasurements, ""
	}
	s.measurementPolicyMu.Lock()
	defer s.measurementPolicyMu.Unlock()
	return s.measurementPolicy(time.Now())
}

// acceptableOrOwnerNamed is the adoption-time test when the owner named
// measurements on the request: the current policy, or exactly those values.
//
// It is an OR with the policy and never a replacement or a mutation. When the
// list is refused (rollback, expiry, tampering) the policy is empty, so the
// only thing accepted is what the owner named; everything else the list ruled
// out, including the bootstrap, stays refused. Nothing is stored, so the next
// request, and every other owner or caller, sees the unchanged policy.
func (s *CoreServer) acceptableOrOwnerNamed(named [][]byte) func([]byte) bool {
	return func(m []byte) bool {
		if s.acceptableMeasurement(m) {
			return true
		}
		for _, a := range named {
			if bytes.Equal(a, m) {
				return true
			}
		}
		return false
	}
}
