// Package machineusereport is the published form of a sealed box's own account of what it
// uses, and the check anyone given one runs.
//
// A host that runs a sealed box may see only the outside of it. Anything finer comes from the
// box, as a report signed by the box's identity key and served to its owner over the sealed
// connection, so the host can neither read it nor change it. This package is what a report
// looks like and how it is verified; the code that takes the readings and serves the report
// is an add-on and is not here (ADR-079).
package machineusereport

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"identity-agent-core/login"
)

// Kind is inside the signed text, so a signature made for this cannot be presented as
// something else the same key signed.
const Kind = "machine-usage/1"

// FutureSlack is how far past the report's signing time a reading may claim to be.
const FutureSlack = 5 * time.Minute

// Reading is one look at the machine. MemoryCacheBytes and the load figures are absent where
// the system does not say (Windows has no load average), so "unknown" is never read as "none".
type Reading struct {
	At                      time.Time `json:"at"`
	MemoryTotalBytes        uint64    `json:"memory_total_bytes"`
	MemoryProgramsBytes     uint64    `json:"memory_programs_bytes"`
	MemoryCacheBytes        *uint64   `json:"memory_cache_bytes,omitempty"`
	MemoryProgramsPeakBytes uint64    `json:"memory_programs_peak_bytes"`
	Load1                   *float64  `json:"load_1,omitempty"`
	Load5                   *float64  `json:"load_5,omitempty"`
	Load15                  *float64  `json:"load_15,omitempty"`
	DiskUsedBytes           uint64    `json:"disk_used_bytes"`
	DiskTotalBytes          uint64    `json:"disk_total_bytes"`
	CPUCores                int       `json:"cpu_cores"`
}

// Report is what is signed.
type Report struct {
	Kind     string    `json:"kind"`
	Identity string    `json:"identity"`
	Nonce    string    `json:"nonce,omitempty"`
	SignedAt time.Time `json:"signed_at"`
	Since    time.Time `json:"since"`
	Readings []Reading `json:"readings"`
}

// Signed is a report as served: Payload is exactly the text signed (a checker verifies the
// bytes it was given, never a re-encoding), Signature is the CESR signature of the box's key.
type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Verify checks s against pub, the box's key from its key log, and returns what it reports.
// expectIdentity is the box the caller means; a report signed by the right key that names
// another box is refused. expectNonce is required: it is what the caller sent with its
// request, and a report that does not carry it is refused, so an old report cannot be
// replayed as a new answer.
//
// That pub is the key of expectIdentity is the caller's to ensure, from the box's key log;
// a key learned from anywhere else (the host, say) proves nothing here.
//
// What a valid report does not show: that the readings are true. They are the box's word,
// signed; a box that is compromised can sign anything.
func Verify(s Signed, pub []byte, expectIdentity, expectNonce string) (Report, error) {
	if expectNonce == "" {
		return Report{}, errors.New("a nonce is required: a report cannot be checked against nothing")
	}
	if ok, err := login.VerifyString(s.Payload, s.Signature, pub); err != nil || !ok {
		return Report{}, errors.New("the report was not signed by this box's key")
	}
	var r Report
	if err := json.Unmarshal([]byte(s.Payload), &r); err != nil {
		return Report{}, errors.New("the signed report is unreadable")
	}
	switch {
	case r.Kind != Kind:
		return Report{}, fmt.Errorf("this is not a machine-use report (%q)", r.Kind)
	case r.Identity != expectIdentity:
		return Report{}, errors.New("the report is for another box")
	case r.Nonce != expectNonce:
		return Report{}, errors.New("the report answers another request")
	case r.Since.After(r.SignedAt):
		return Report{}, errors.New("the report starts after it was signed")
	}
	var prev time.Time
	for i, rd := range r.Readings {
		switch {
		case rd.At.Before(r.Since) || rd.At.After(r.SignedAt.Add(FutureSlack)):
			return Report{}, fmt.Errorf("reading %d is outside the period the report covers", i)
		case i > 0 && !rd.At.After(prev):
			return Report{}, fmt.Errorf("reading %d is not after the one before it", i)
		case rd.MemoryProgramsBytes > rd.MemoryTotalBytes, rd.MemoryProgramsPeakBytes > rd.MemoryTotalBytes,
			rd.MemoryProgramsPeakBytes < rd.MemoryProgramsBytes, rd.DiskUsedBytes > rd.DiskTotalBytes:
			return Report{}, fmt.Errorf("reading %d is impossible (more used than there is)", i)
		}
		prev = rd.At
	}
	return r, nil
}
