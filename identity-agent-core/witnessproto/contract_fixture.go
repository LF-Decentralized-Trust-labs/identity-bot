package witnessproto

import (
	_ "embed"
	"encoding/json"
)

// KelLogContractFixture is one key log as a watcher is sent it and as a watcher
// serves it, so that the two sides of GET /witness/kel (the Identity Agent that
// fetches a log to judge it, and the hosted watcher that serves it) test against
// one document instead of each against its own fake.
//
// It holds a multi-key identity (three keys, two of which must sign) with a
// rotation, and a second validly signed event at one place:
//
//   - Submissions are what a controller sends a watcher, in order, as the
//     request body of POST /witness/event (event_b64, cesr_signature as the
//     first signature, cesr_signatures as all of them). The last is the rival at
//     RivalSeq; a watcher holds the first event at a place and answers the rival
//     409, keeping it beside.
//   - Served is the answer to GET /witness/kel/{aid} after all of them: the held
//     log and the conflicting events, each with its bytes and every signature.
//   - Digests are what GET /public/kel-digest answers at a place: the digest of
//     the held log through it and whether a rival is held at or below it.
//
// kel-log-contract-fixture.json is regenerated, deterministically, by
// REGENERATE_KEL_FIXTURE=1 go test -run TestRegenerate in this package; a test
// checks it is still correct.
//
//go:embed kel-log-contract-fixture.json
var KelLogContractFixture []byte

// KelLogContract is KelLogContractFixture read.
type KelLogContract struct {
	AID         string `json:"aid"`
	RivalSeq    int    `json:"rival_seq"`
	Submissions []struct {
		AID            string   `json:"aid"`
		EventB64       string   `json:"event_b64"`
		CesrSignature  string   `json:"cesr_signature"`
		CesrSignatures []string `json:"cesr_signatures"`
	} `json:"submissions"`
	Served struct {
		AID         string                   `json:"aid"`
		KEL         []map[string]interface{} `json:"kel"`
		Conflicting []map[string]interface{} `json:"conflicting"`
		Count       int                      `json:"count"`
	} `json:"served"`
	Digests []struct {
		Seq            int    `json:"seq"`
		Digest         string `json:"digest"`
		RivalAtOrBelow bool   `json:"rival_at_or_below"`
	} `json:"digests"`
}

// ReadKelLogContract reads the fixture.
func ReadKelLogContract() (*KelLogContract, error) {
	var c KelLogContract
	if err := json.Unmarshal(KelLogContractFixture, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
