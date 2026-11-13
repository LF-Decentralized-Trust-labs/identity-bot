package machineusereport

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"identity-agent-core/login"
)

const seedHex = "c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"
const identity = "EBoxIdentifierForTheMachineUseVectors0000000"

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func cache(n uint64) *uint64 { return &n }

func reading(min int, programs, peak uint64) Reading {
	return Reading{At: t0.Add(time.Duration(min) * time.Minute), MemoryTotalBytes: 1 << 30, MemoryProgramsBytes: programs,
		MemoryCacheBytes: cache(1 << 28), MemoryProgramsPeakBytes: peak, Load1: 0.5, Load5: 0.4, Load15: 0.3,
		DiskUsedBytes: 5 << 30, DiskTotalBytes: 20 << 30, CPUCores: 2}
}

func sign(t *testing.T, seed []byte, r Report) Signed {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := login.SignString(string(b), seed)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{Payload: string(b), Signature: sig}
}

func base() Report {
	return Report{Kind: Kind, Identity: identity, Nonce: "n-1", SignedAt: t0.Add(3 * time.Minute), Since: t0,
		Readings: []Reading{reading(0, 100<<20, 150<<20), reading(1, 120<<20, 120<<20), reading(2, 110<<20, 200<<20)}}
}

// build makes the vector set from fixed inputs; Ed25519 is deterministic, so the file is reproducible.
func build(t *testing.T) VectorSet {
	seed, _ := hex.DecodeString(seedHex)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	v := VectorSet{
		About:   "A sealed box's signed machine-use report (ADR-079), worked from a fixed key. payload is the exact text signed; signature is CESR (code 0B) over those bytes. Each refused report must fail Verify with the key and the expectations given.",
		SeedHex: seedHex, Identity: identity, PublicKeyHex: hex.EncodeToString(pub), Nonce: "n-1",
		Valid: sign(t, seed, base()),
	}
	add := func(why string, s Signed, id, nonce string) {
		v.Refused = append(v.Refused, struct {
			Why            string `json:"why"`
			ExpectIdentity string `json:"expect_identity,omitempty"`
			ExpectNonce    string `json:"expect_nonce,omitempty"`
			Report         Signed `json:"report"`
		}{why, id, nonce, s})
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(i + 1)
	}
	add("signed by another key", sign(t, other, base()), "", "")
	// Well-formed JSON with one figure changed and the old signature: refused only because
	// the signature is checked over the bytes given.
	add("one figure changed after signing, still well-formed", Signed{Payload: strings.Replace(v.Valid.Payload, `"cpu_cores":2`, `"cpu_cores":9`, 1), Signature: v.Valid.Signature}, "", "")
	// The same meaning, re-spaced, with the old signature: bytes are what is signed.
	var generic map[string]any
	_ = json.Unmarshal([]byte(v.Valid.Payload), &generic)
	respaced, _ := json.MarshalIndent(generic, "", " ")
	add("the same report re-encoded, with the old signature", Signed{Payload: string(respaced), Signature: v.Valid.Signature}, "", "")
	add("the right key, but a report for another box", v.Valid, "EAnotherBox0000000000000000000000000000000", "")
	add("a replay: answers another request", v.Valid, "", "n-2")
	add("no nonce given by the checker", v.Valid, "", "-")
	nn := base()
	nn.Nonce = ""
	add("a report with no nonce, checked with none", sign(t, seed, nn), "", "-")
	k := base()
	k.Kind = "something-else/1"
	add("the right key, signed as another kind of thing", sign(t, seed, k), "", "")
	im := base()
	im.Readings[1].MemoryProgramsBytes = 2 << 30
	add("a reading with more in programs than the machine has", sign(t, seed, im), "", "")
	ord := base()
	ord.Readings[1], ord.Readings[2] = ord.Readings[2], ord.Readings[1]
	add("readings out of order", sign(t, seed, ord), "", "")
	late := base()
	late.Readings[2].At = late.SignedAt.Add(time.Hour)
	add("a reading from after the report was signed", sign(t, seed, late), "", "")
	pk := base()
	pk.Readings[0].MemoryProgramsPeakBytes = 1
	add("a peak below what was held", sign(t, seed, pk), "", "")
	return v
}

func TestVectorFileIsReproducibleAndHolds(t *testing.T) {
	want := build(t)
	if os.Getenv("UPDATE_VECTORS") == "1" {
		b, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile("machine-usage-vectors.json", append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Fatal("the published vectors differ from what the fixed inputs produce (UPDATE_VECTORS=1 rewrites them)")
	}
	pub, _ := hex.DecodeString(got.PublicKeyHex)
	r, err := Verify(got.Valid, pub, got.Identity, got.Nonce)
	if err != nil || len(r.Readings) != 3 {
		t.Fatalf("the valid report was refused: %v", err)
	}
	for _, c := range got.Refused {
		id, nonce := c.ExpectIdentity, c.ExpectNonce
		if id == "" {
			id = got.Identity
		}
		if nonce == "" {
			nonce = got.Nonce
		}
		if nonce == "-" {
			nonce = "" // the checker supplied no nonce
		}
		if _, err := Verify(c.Report, pub, id, nonce); err == nil {
			t.Errorf("accepted: %s", c.Why)
		}
	}
	if len(got.Refused) < 12 {
		t.Fatal("a refusal case was removed")
	}
}
