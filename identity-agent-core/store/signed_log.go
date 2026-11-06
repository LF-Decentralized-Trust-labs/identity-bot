package store

import (
	"fmt"
	"sort"

	"identity-agent-core/drivers"
)

// SignedLogOf reads the key log this Identity Agent keeps into the signed
// events the engine judges, in sequence order. It is the one place a stored
// log becomes SignedEventBytes: a row kept without its bytes or without a
// signature is not an event of the log, and the log is refused, naming it.
//
// The signatures are ControllerSignatures, not Signatures alone: a row written
// before lists were kept carries its one signature in CesrSignature, and is
// as signed as any other.
func SignedLogOf(events []EventRecord) ([]drivers.SignedEventBytes, error) {
	ordered := append([]EventRecord(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].SequenceNumber < ordered[j].SequenceNumber })
	out := make([]drivers.SignedEventBytes, 0, len(ordered))
	for _, rec := range ordered {
		sigs := rec.ControllerSignatures()
		if rec.RawBytesB64 == "" || len(sigs) == 0 {
			return nil, fmt.Errorf("the event at sequence number %d is kept without its signed bytes", rec.SequenceNumber)
		}
		out = append(out, drivers.SignedEventBytes{RawB64: rec.RawBytesB64, Sigs: sigs})
	}
	return out, nil
}
