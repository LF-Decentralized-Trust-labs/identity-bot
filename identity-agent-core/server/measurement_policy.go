package server

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/measurementlist"
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
//   - The signed, published measurement list (package measurementlist), read
//     from AGENT_MEASUREMENT_LIST_FILE and checked against the publisher key
//     pinned in this build. When one verifies it is the policy, and nothing
//     else is added to it — except by the owner's own statement on one
//     adoption request, below, which survives an accepted list on purpose.
//     When the variable is unset the file measurement_list.json in the data
//     directory is read instead, which is how an app hands the core a list
//     (desktop and embedded alike): the app supplies the bytes and the core
//     decides.
//   - AGENT_ACCEPTED_MEASUREMENTS on this agent, for a standing policy that
//     survives restarts. It is the bootstrap: used only while no signed list
//     has ever been accepted here; after one has, it is never used again.
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

// measurementListFloorFile records the highest list sequence accepted here,
// and the hash of the list accepted at it.
const measurementListFloorFile = "measurement_list_sequence"

// acceptedMeasurements is measurementPolicy without the reason, for callers
// that only need the measurements. The error is only for a malformed bootstrap.
func acceptedMeasurements(dataDir, entityType string, now time.Time) ([][]byte, error) {
	m, _, err := measurementPolicy(dataDir, entityType, now)
	return m, err
}

// measurementPolicy decides this agent's standing policy at time now: the
// verified signed list if there is one, otherwise the bootstrap from the
// environment — but the bootstrap only until a signed list has ever been
// accepted here.
//
// Once a list has been accepted (the recorded floor is above zero) the
// bootstrap is never consulted again. The bootstrap is the oldest policy there
// is; letting any list failure fall back to it would let a corrupted file, a
// deleted file, an older list or an expired one force that policy, and undo the
// rollback protection the floor exists for. From then on every failure of the
// list means NO measurement is accepted, and the second result says why.
//
// Fail closed at every step. A verified list that names nothing for this
// agent's image kind yields an empty policy, which acceptableMeasurement
// refuses: the publisher has said nothing is acceptable.
func measurementPolicy(dataDir, entityType string, now time.Time) ([][]byte, string, error) {
	floor, _, floorErr := measurementlist.ReadFloor(filepath.Join(dataDir, measurementListFloorFile))
	if floorErr != nil {
		// A damaged record is not "nothing accepted yet".
		why := fmt.Sprintf("the record of the newest accepted measurement list cannot be read, so no box is accepted: %v", floorErr)
		log.Printf("[identity-agent-core] %s", why)
		return nil, why, nil
	}
	everAccepted := floor > 0

	path := measurementListPath(dataDir)
	var listErr error
	switch {
	case path != "":
		list, err := verifiedMeasurementList(path, dataDir, now)
		if err == nil {
			if entityType == "" {
				why := "a measurement list verified but this agent does not declare its image kind, so no box is accepted"
				log.Printf("[identity-agent-core] %s", why)
				return nil, why, nil
			}
			m := list.Measurements(entityType)
			log.Printf("[identity-agent-core] using signed measurement list sequence %d: %d accepted for %q",
				list.Sequence, len(m), entityType)
			return m, "", nil
		}
		listErr = err
	case everAccepted:
		listErr = fmt.Errorf("there is no measurement list: AGENT_MEASUREMENT_LIST_FILE is not set and %s is absent", defaultMeasurementListFile)
	}
	if everAccepted {
		why := fmt.Sprintf("a signed measurement list (sequence %d) was accepted here before and the list now cannot be used (%v); "+
			"the older bootstrap policy is never used again, so no box is accepted until a valid list at that sequence or later is in place",
			floor, listErr)
		log.Printf("[identity-agent-core] %s", why)
		return nil, why, nil
	}
	if listErr != nil {
		log.Printf("[identity-agent-core] the measurement list was NOT used (%v); using the bootstrap policy", listErr)
	}
	m, err := acceptedMeasurementsFromEnv()
	return m, "", err
}

// defaultMeasurementListFile is where an app that launches this core, or an
// embedded one that has no environment to give, leaves the signed list: inside
// the data directory, under this name. It is only bytes; the core verifies it
// against the pinned key, the floor and the expiry on every decision, so
// whoever writes it decides nothing.
const defaultMeasurementListFile = "measurement_list.json"

// measurementListPath is AGENT_MEASUREMENT_LIST_FILE when set, otherwise the
// default file in the data directory when one is there, otherwise "".
func measurementListPath(dataDir string) string {
	if p := strings.TrimSpace(os.Getenv("AGENT_MEASUREMENT_LIST_FILE")); p != "" {
		return p
	}
	if dataDir == "" {
		return ""
	}
	p := filepath.Join(dataDir, defaultMeasurementListFile)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// pinnedPublisherKey is the compiled-in key; a variable only so a test can pin its own.
var pinnedPublisherKey = measurementlist.Pinned

func verifiedMeasurementList(path, dataDir string, now time.Time) (*measurementlist.List, error) {
	key, err := pinnedPublisherKey()
	if err != nil {
		return nil, err
	}
	return measurementlist.LoadFile(path, filepath.Join(dataDir, measurementListFloorFile), key, now)
}

// currentMeasurements is the policy to decide with, right now. A server built
// with a policy function re-reads the list file and re-checks its expiry and
// entry windows on every call, so a list that expired or was replaced since
// startup is not honoured on a decision made today. The second result is why
// nothing is accepted, when that is the list's doing.
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
