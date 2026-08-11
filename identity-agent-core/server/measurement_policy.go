package server

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
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
//   - AGENT_ACCEPTED_MEASUREMENTS on this agent, for a standing policy that
//     survives restarts. This is where a published, signed measurement list
//     ends up once one exists.
//   - accepted_measurements on the adoption request itself, for one adoption.
//     /api/pairing/adopt is owner-only, so this is the owner speaking, not the
//     box — but see the warning on the request field.
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
		raw, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%q is not hex, so it is not a measurement: %w", short(v), err)
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
