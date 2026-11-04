//go:build kerigo_pqtest

package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/keymath"
	"identity-agent-core/store"
)

// A paired machine has no identity of its own: its owner is another identity,
// known to it only by the log it holds of that owner. An owner at stage two is
// held to both keys there too, whatever the shape of the key list (ADR-061
// section 6), and an owner whose log cannot be read is not let through.

// deferredToT945 is why the paired-machine stage-two tests below are skipped and
// not deleted: they are the specification T-945 (verify multi-key contact logs,
// then hold a paired machine's stage-two owner to both keys) is to satisfy.
// Until then ownerPostQuantumKey asks nothing of an owner that is not this
// core's own identity, because a stage-two contact log cannot be verified
// (drivers/validate_kel.go refuses a multi-key log).
const deferredToT945 = "deferred to T-945: a paired machine's stage-two owner is not held to the second key until multi-key contact logs can be verified"

// aPairedMachineWhoseOwnerLogIs seals a machine with no identity to owner and
// stores the owner's log as the establishment events named, each a key list.
func aPairedMachineWhoseOwnerLogIs(t *testing.T, ownerKey []byte, establishments ...[]string) *CoreServer {
	t.Helper()
	s := appHeldCore(t)
	owner := "Eowner" + strings.Repeat("A", 38)
	if err := s.SealOwnerAuthority(OwnerAuthority{AID: owner, PublicKey: verkeyOf(ownerKey)}); err != nil {
		t.Fatal(err)
	}
	var kel []map[string]interface{}
	for i, keys := range establishments {
		ks := make([]interface{}, 0, len(keys))
		for _, k := range keys {
			ks = append(ks, k)
		}
		ilk := "rot"
		if i == 0 {
			ilk = "icp"
		}
		kel = append(kel, map[string]interface{}{"t": ilk, "s": strconv.Itoa(i), "d": "D" + strconv.Itoa(i), "k": ks})
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{AID: owner, KEL: kel}); err != nil {
		t.Fatal(err)
	}
	return s
}

func anOwnerRequestTo(t *testing.T, s *CoreServer, ownerKey []byte, pqSeed []byte, pqIndex int) error {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339)
	path := "/api/identity/" + strconv.FormatInt(time.Now().UnixNano(), 10)
	req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
	sig, err := SignOwnerRequest("", http.MethodGet, path, stamp, nil, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerOwnerSig, sig)
	req.Header.Set(headerOwnerTimestamp, stamp)
	req.Header.Set(headerBodyDigest, iacrypto.Blake3QB64Must(nil))
	if pqSeed != nil {
		raw, err := keymath.SignMLDSA65(pqSeed, []byte(canonicalOwnerRequest("", http.MethodGet, path, stamp, nil)))
		if err != nil {
			t.Fatal(err)
		}
		q, err := keymath.EncodeMLDSA65CurrentOnlySignature(raw, pqIndex)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(headerOwnerSigPostQuantum, q)
	}
	return s.verifyOwnerSignature(req)
}

func aPostQuantumKey(t *testing.T, seed byte) ([]byte, string) {
	t.Helper()
	s := append([]byte{seed}, make([]byte, 31)...)
	key, err := keymath.PostQuantumNextKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return s, key.Verkey
}

func TestAStageTwoOwnerOfAPairedMachineIsHeldToBothKeys(t *testing.T) {
	t.Skip(deferredToT945)
	k := appSeeds(2)
	pq, pqKey := aPostQuantumKey(t, 0xB1)
	s := aPairedMachineWhoseOwnerLogIs(t, k[1], []string{verkeyOf(k[0])}, []string{verkeyOf(k[1]), pqKey})

	if err := anOwnerRequestTo(t, s, k[1], nil, 0); err == nil || !strings.Contains(err.Error(), "stage two") {
		t.Fatalf("the classical signature alone was taken on a paired machine: %v", err)
	}
	if err := anOwnerRequestTo(t, s, k[1], pq, 0); err == nil {
		t.Fatal("a post-quantum signature at the classical key's place was taken")
	}
	if err := anOwnerRequestTo(t, s, k[1], pq, 1); err != nil {
		t.Fatalf("both signatures were refused: %v", err)
	}
}

// A two-owner stage-two list is [ed0, pq0, ed1, pq1] (ADR-061 section 6), which
// names two post-quantum keys. One header carries one post-quantum signature,
// so this code REFUSES such an owner outright, whichever signature is sent, and
// says why. Refusing is deliberate for now; honouring a two-owner stage two
// needs a request that carries one post-quantum signature per owner.
func TestATwoOwnerIdentityAtStageTwoIsRefusedForWantOfTwoPostQuantumSignatures(t *testing.T) {
	t.Skip(deferredToT945)
	k := appSeeds(2)
	pq0, pqKey0 := aPostQuantumKey(t, 0xB1)
	_, pqKey1 := aPostQuantumKey(t, 0xB2)
	s := aPairedMachineWhoseOwnerLogIs(t, k[0], []string{verkeyOf(k[0])},
		[]string{verkeyOf(k[0]), pqKey0, verkeyOf(k[1]), pqKey1})

	for _, c := range []struct {
		name string
		pq   []byte
		at   int
	}{{"classical alone", nil, 0}, {"post-quantum at key 1", pq0, 1}, {"post-quantum at key 3", pq0, 3}} {
		if err := anOwnerRequestTo(t, s, k[0], c.pq, c.at); err == nil || !strings.Contains(err.Error(), "more than one post-quantum key") {
			t.Fatalf("%s: a two-owner stage-two identity was not refused for its two post-quantum keys: %v", c.name, err)
		}
	}
}

// One owner with the classical key after other keys: the post-quantum key is
// found wherever it is, not assumed to be key 1.
func TestAnOwnerWithOneClassicalKeyAfterAnotherIsHeldToItsPostQuantumKeyWhereverItIs(t *testing.T) {
	t.Skip(deferredToT945)
	k := appSeeds(2)
	pq, pqKey := aPostQuantumKey(t, 0xB1)
	s := aPairedMachineWhoseOwnerLogIs(t, k[0], []string{verkeyOf(k[0])}, []string{verkeyOf(k[0]), verkeyOf(k[1]), pqKey})

	if err := anOwnerRequestTo(t, s, k[0], nil, 0); err == nil {
		t.Fatal("the classical signature alone was taken at stage two")
	}
	if err := anOwnerRequestTo(t, s, k[0], pq, 1); err == nil {
		t.Fatal("a post-quantum signature at the wrong place was taken")
	}
	if err := anOwnerRequestTo(t, s, k[0], pq, 2); err != nil {
		t.Fatalf("both signatures at their places were refused: %v", err)
	}
}

func TestAnOwnerWhoseLogCannotBeReadIsNotLetThrough(t *testing.T) {
	t.Skip(deferredToT945)
	k := appSeeds(1)
	// A log held of the owner that names no establishment event at all.
	s := aPairedMachineWhoseOwnerLogIs(t, k[0])
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: "Eowner" + strings.Repeat("A", 38), KEL: []map[string]interface{}{{"t": "ixn", "s": "1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := anOwnerRequestTo(t, s, k[0], nil, 0); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("an owner whose key state cannot be read was let through: %v", err)
	}
}

func TestAnOwnerWhoseLogIsAtStageOneIsUnchangedOnAPairedMachine(t *testing.T) {
	k := appSeeds(1)
	s := aPairedMachineWhoseOwnerLogIs(t, k[0], []string{verkeyOf(k[0])})
	if err := anOwnerRequestTo(t, s, k[0], nil, 0); err != nil {
		t.Fatalf("a stage-one owner's request: %v", err)
	}
}
