package anchored

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/witness"
)

// The core's own tests (package server) need a real publisher: a pin, a bundle
// and the witnesses' signing seeds, to answer a freshness question as the
// witnesses would. They cannot import this package's fixtures, so this writes
// them once, from the fixtures, as test data: run with WRITE_SERVER_VECTORS=1.
// The test below checks the committed file still verifies under the checker, so
// a change to the checker that the vectors no longer satisfy is seen here.

type serverVectors struct {
	Publisher  string            `json:"publisher"`
	Inception  string            `json:"inception_b64"`
	Registry   string            `json:"registry"`
	Schema     string            `json:"schema"`
	WitnessAID []string          `json:"witness_aids"`
	WitnessSd  []string          `json:"witness_seeds_hex"`
	Bundles    map[string]string `json:"bundles"`
	Measure    map[string]string `json:"measurement_of"`
	Now        string            `json:"now"`
}

const serverVectorsFile = "testdata/server_vectors.json"

func makeServerVectors(t *testing.T) serverVectors {
	// the keys of the members are random per run, so the vectors are made once
	// and committed; Now sits inside every list's window
	p := onekey(t)
	published(p, 7)
	b7, err := p.bundle().Encode()
	if err != nil {
		t.Fatal(err)
	}
	published(p, 8)
	b8, err := p.bundle().Encode()
	if err != nil {
		t.Fatal(err)
	}
	v := serverVectors{Publisher: p.aid, Inception: base64RawURL(p.icp), Registry: p.registry, Schema: p.schema,
		Bundles: map[string]string{"seq7": string(b7), "seq8": string(b8)},
		Measure: map[string]string{"seq7": meas(7), "seq8": meas(8)}, Now: t0.Add(time.Hour).Format(time.RFC3339)}
	for _, w := range p.witness {
		v.WitnessAID = append(v.WitnessAID, w.pub)
		v.WitnessSd = append(v.WitnessSd, hex.EncodeToString(w.seed))
	}
	return v
}

func TestTheVectorsTheServerUsesAreWhatTheFixturesMake(t *testing.T) {
	if os.Getenv("WRITE_SERVER_VECTORS") == "1" {
		v := makeServerVectors(t)
		b, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(serverVectorsFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(serverVectorsFile)
	if err != nil {
		t.Fatalf("%v (WRITE_SERVER_VECTORS=1 writes it)", err)
	}
	var v serverVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// the committed vectors still verify under the checker, from the pin alone
	pin, err := ParsePin(v.Publisher, v.Inception, v.Registry, v.Schema)
	if err != nil {
		t.Fatal(err)
	}
	for name, enc := range v.Bundles {
		b, err := ParseBundle([]byte(enc))
		if err != nil {
			t.Fatal(err)
		}
		// asked with answers made from the committed seeds, as the server's tests do
		now, _ := time.Parse(time.RFC3339, v.Now)
		tip := tipOfBundle(t, b)
		replies := repliesFromSeeds(t, v, pin, tip)
		res, err := Verify(b, pin, replies, Floors{}, now)
		if err != nil {
			t.Fatalf("the committed %s vector is refused: %v", name, err)
		}
		if got := hex.EncodeToString(res.List.Images["individual"][0].Measurement); got != v.Measure[name] {
			t.Fatalf("%s: measurement %s, vector says %s", name, got, v.Measure[name])
		}
	}
}

func tipOfBundle(t *testing.T, b *Bundle) Tip {
	t.Helper()
	raw, err := keri.EventOfMessage(b.KEL[len(b.KEL)-1])
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Tip{SN: int(ev.SN), SAID: ev.SAID}
}

func repliesFromSeeds(t *testing.T, v serverVectors, pin Pin, tip Tip) []TipReply {
	t.Helper()
	var out []TipReply
	for i, sd := range v.WitnessSd {
		seed, _ := hex.DecodeString(sd)
		sg, err := keri.NewSoftwareSigner(seed, false)
		if err != nil {
			t.Fatal(err)
		}
		n := nonce()
		raw, err := sg.Sign([]byte(witness.TipStatement(pin.Publisher, n, tip.SN, tip.SAID)))
		if err != nil {
			t.Fatal(err)
		}
		q, err := keri.MatterQB64("0B", raw)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, TipReply{Nonce: n, Answer: witness.TipAnswer{AID: pin.Publisher, Nonce: n, SN: tip.SN, SAID: tip.SAID, WitnessAID: v.WitnessAID[i], Signature: q}})
	}
	return out
}
