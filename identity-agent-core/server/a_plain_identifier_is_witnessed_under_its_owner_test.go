package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// A plain identifier an owner makes for its own purpose (no delegator, not a
// contact) is witnessed only once its owner says it is its own, signed, and then
// under the owner as a delegate is: the owner's agreement has to cover it, and
// every refusal is one answer, so a stranger learns nothing of who this witness
// witnesses for.
func TestAPlainIdentifierIsWitnessedOnlyOnceItsOwnerSaysItIsItsOwn(t *testing.T) {
	_, key, srv, peer := aRoutedWitness(t)
	aid, said, raw, sig, idSigner := signedInceptionBy(t, key)
	logOf := func(raw []byte, sig string) []witness.SignedEvent {
		return []witness.SignedEvent{{RawBytesB64: base64.StdEncoding.EncodeToString(raw), CesrSignature: sig}}
	}
	idSign := func(who, wit, id, d, stamp string, by keri.Signer) string {
		b, err := by.Sign([]byte(witness.CoverStatement(who, wit, id, d, stamp)))
		if err != nil {
			t.Fatal(err)
		}
		s, _ := keri.MatterQB64(keri.CodeEd25519Sig, b)
		return s
	}

	owner, _ := keri.GenerateSigner(true)
	ownerKey, _ := owner.PublicKey()
	const ownerAID = "EOwnerRootIdentifierxxxxxxxxxxxxxxxxxxxxxxxxxx"
	peer.willWitnessFor(t, ownerAID)
	if err := peer.svc.Contacts.SaveContact(store.ContactRecord{AID: ownerAID, PublicKey: ownerKey, Status: "accepted", ContactCategory: "general"}); err != nil {
		t.Fatal(err)
	}

	sign := func(stamp string, over ...string) string {
		who, wit, id, d := ownerAID, key, aid, said
		for i, o := range over {
			switch i {
			case 0:
				who = o
			case 1:
				wit = o
			}
		}
		b, err := owner.Sign([]byte(witness.CoverStatement(who, wit, id, d, stamp)))
		if err != nil {
			t.Fatal(err)
		}
		s, _ := keri.MatterQB64(keri.CodeEd25519Sig, b)
		return s
	}
	post := func(path string, v any) (int, string) {
		b, _ := json.Marshal(v)
		res, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(out)
	}
	cover := func(over func(*witness.CoverRequest)) (int, string) {
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		req := witness.CoverRequest{Owner: ownerAID, AID: aid, Log: logOf(raw, sig), Stamp: stamp, Signature: sign(stamp), AIDSignature: idSign(ownerAID, key, aid, said, stamp, idSigner)}
		if over != nil {
			over(&req)
		}
		return post("/api/witness/cover", req)
	}
	event := func() int {
		code, _ := post("/api/witness/event", map[string]any{"aid": aid, "event_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signatures": []string{sig}})
		return code
	}

	// Not witnessed before the owner says so, and not by a declaration that is
	// not the owner's, not for this witness, not fresh, not this inception's, or
	// not covered by the owner's agreement. All the same answer.
	if got := event(); got != http.StatusForbidden {
		t.Fatalf("a plain identifier nobody declared was witnessed: %d", got)
	}
	// The owner's agreement does not cover its identifiers yet: a declaration that is otherwise right is refused.
	_, refused := cover(nil)
	if code, _ := cover(nil); code != http.StatusForbidden {
		t.Fatalf("a declaration was taken though the owner's agreement does not cover its identifiers: %d", code)
	}
	if err := peer.svc.Store.SetConfig("witness.delegators_covered", `{"`+ownerAID+`":true}`); err != nil {
		t.Fatal(err)
	}
	for name, over := range map[string]func(*witness.CoverRequest){
		"another witness's": func(r *witness.CoverRequest) {
			r.Signature = sign(r.Stamp, ownerAID, "BSomeOtherWitnessKeyxxxxxxxxxxxxxxxxxxxxxxxxx")
		},
		"a stranger's": func(r *witness.CoverRequest) { r.Owner = "EAStrangerxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
		"a stale": func(r *witness.CoverRequest) {
			r.Stamp = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			r.Signature = sign(r.Stamp)
		},
		"another identifier's": func(r *witness.CoverRequest) {
			// The owner signed it, for this identifier and this inception's digest: what is wrong is only that the event is another's.
			_, said2, r2, sig2, by2 := signedInceptionBy(t, key)
			r.Log = logOf(r2, sig2)
			r.Signature = sign(r.Stamp)
			r.AIDSignature = idSign(ownerAID, key, aid, said2, r.Stamp, by2)
		},
		"one whose inception does not derive its identifier": func(r *witness.CoverRequest) {
			r.Log = logOf(bytes.Replace(raw, []byte(`"bt":"1"`), []byte(`"bt":"0"`), 1), sig)
		},
		// The inception is public, so a squatter has it whole and signs as the owner it is itself:
		// what it cannot do is sign as the identifier.
		"one the identifier's own key did not sign": func(r *witness.CoverRequest) {
			squatter, _ := keri.GenerateSigner(true)
			r.AIDSignature = idSign(ownerAID, key, aid, said, r.Stamp, squatter)
		},
		"one with no signature of the identifier's": func(r *witness.CoverRequest) { r.AIDSignature = "" },
		"one whose log is not signed by the identifier": func(r *witness.CoverRequest) {
			squatter, _ := keri.GenerateSigner(true)
			rawSig, _ := squatter.Sign(raw)
			bad, _ := keri.MatterQB64(keri.CodeEd25519Sig, rawSig)
			r.Log = logOf(raw, bad)
		},
		"one whose owner this witness does not witness for": func(r *witness.CoverRequest) {
			meta, _ := peer.svc.Store.GetContactMeta(ownerAID)
			meta.WitnessingFor = false
			_ = peer.svc.Store.SaveContactMeta(*meta)
		},
	} {
		code, body := cover(over)
		if code != http.StatusForbidden || body != refused {
			t.Fatalf("%s declaration: %d %s, want the one refusal %s", name, code, body, refused)
		}
		peer.willWitnessFor(t, ownerAID)
		_ = peer.svc.Contacts.SaveContact(store.ContactRecord{AID: ownerAID, PublicKey: ownerKey, Status: "accepted", ContactCategory: "general"})
	}
	if got := event(); got != http.StatusForbidden {
		t.Fatalf("a refused declaration still got the identifier witnessed: %d", got)
	}

	// Right in every respect: taken, and the identifier is witnessed under the owner.
	if code, body := cover(nil); code != http.StatusOK {
		t.Fatalf("a declaration the owner signed was refused: %d %s", code, body)
	}
	if got := event(); got != http.StatusOK {
		t.Fatalf("a covered identifier's inception was not taken: %d", got)
	}
	// An identifier held under one owner cannot be taken by another that says it is its own, nor can a
	// contact this witness already witnesses for be declared anybody's.
	owner2, _ := keri.GenerateSigner(true)
	owner2Key, _ := owner2.PublicKey()
	const owner2AID = "ESecondOwnerIdentifierxxxxxxxxxxxxxxxxxxxxxxxx"
	peer.willWitnessFor(t, owner2AID)
	_ = peer.svc.Contacts.SaveContact(store.ContactRecord{AID: owner2AID, PublicKey: owner2Key, Status: "accepted", ContactCategory: "general"})
	_ = peer.svc.Store.SetConfig("witness.delegators_covered", `{"`+ownerAID+`":true,"`+owner2AID+`":true}`)
	declareBy := func(who string, signer keri.Signer, id string, inception []byte, isig, said string, by keri.Signer) (int, string) {
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		b, _ := signer.Sign([]byte(witness.CoverStatement(who, key, id, said, stamp)))
		sg, _ := keri.MatterQB64(keri.CodeEd25519Sig, b)
		return post("/api/witness/cover", witness.CoverRequest{Owner: who, AID: id, Log: logOf(inception, isig), Stamp: stamp, Signature: sg, AIDSignature: idSign(who, key, id, said, stamp, by)})
	}
	// Even with the identifier's own key, another owner cannot take what is held under this one.
	if code, _ := declareBy(owner2AID, owner2, aid, raw, sig, said, idSigner); code != http.StatusForbidden {
		t.Fatalf("an identifier held under one owner was taken by another: %d", code)
	}
	contactAID, contactSaid, contactRaw, contactSig, contactBy := signedInceptionBy(t, key)
	peer.willWitnessFor(t, contactAID)
	if code, _ := declareBy(ownerAID, owner, contactAID, contactRaw, contactSig, contactSaid, contactBy); code != http.StatusForbidden {
		t.Fatalf("a contact this witness already witnesses for was declared another's: %d", code)
	}
	// Said again by the owner it is held under, it is taken (and is not counted twice).
	if code, body := cover(nil); code != http.StatusOK {
		t.Fatalf("an owner could not say again what it had said: %d %s", code, body)
	}

	// And only while the owner is witnessed: when it is not, the identifier is not either.
	meta, _ := peer.svc.Store.GetContactMeta(ownerAID)
	meta.WitnessingFor = false
	_ = peer.svc.Store.SaveContactMeta(*meta)
	if code, _ := post("/api/witness/event", map[string]any{"aid": aid, "event_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signatures": []string{sig}}); code != http.StatusForbidden {
		t.Fatalf("an identifier was still witnessed after its owner was not: %d", code)
	}
}

// An event from before this witness was named is held and not receipted, said
// plainly, so the controller seeding the log of an identifier it later gave
// witnesses can tell it from a refusal: the log from there on carries on from it.
func TestAnEventFromBeforeThisWitnessWasNamedIsHeldNotReceipted(t *testing.T) {
	svc, key, srv, _ := aRoutedWitness(t)
	real := svc.SignEventReceipt
	svc.SignEventReceipt = func(raw []byte, designated []string) (string, string, error) {
		if drivers.WitnessPosition(designated, key) < 0 {
			return "", "", witness.ErrNotDesignated
		}
		return real(raw, designated)
	}
	aid, _, raw, sig := signedInception(t, "") // names no witness
	// held under an owner, as a declared identifier is
	if err := svc.Store.SaveContactMeta(witness.ContactMeta{ContactAID: aid, BackendType: witness.BackendDesktop, WitnessingFor: true, WitnessStatus: witness.StatusOnline}); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"aid": aid, "event_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signatures": []string{sig}})
	res, err := http.Post(srv.URL+"/api/witness/event", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var ans map[string]any
	_ = json.NewDecoder(res.Body).Decode(&ans)
	if res.StatusCode != http.StatusOK || ans["held"] != true || ans["receipted"] != false || ans["cesr_signature"] != nil {
		t.Fatalf("the event was not held and said not to be receipted: %d %v", res.StatusCode, ans)
	}
	held, err := svc.GetKelReplica(aid)
	if err != nil || len(held) != 1 || held[0]["witness_receipts"] != nil {
		t.Fatalf("the event is not held without a receipt: %v %v", err, held)
	}
}

// An inception is public, so an owner that has it can say the identifier is its
// own: only the identifier's key in force shows the declaration is its
// controller's. A squatter that gets there first is refused, and the real
// controller is then witnessed.
func TestASquatterCannotClaimAnotherOwnersIdentifierAtASharedWitness(t *testing.T) {
	_, key, srv, peer := aRoutedWitness(t)
	aid, said, raw, sig, idSigner := signedInceptionBy(t, key)
	type party struct {
		aid    string
		signer keri.Signer
	}
	mk := func(name string) party {
		sg, _ := keri.GenerateSigner(true)
		pk, _ := sg.PublicKey()
		id := "E" + name + "OwnerIdentifierxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"[:43-len(name)]
		peer.willWitnessFor(t, id)
		if err := peer.svc.Contacts.SaveContact(store.ContactRecord{AID: id, PublicKey: pk, Status: "accepted", ContactCategory: "general"}); err != nil {
			t.Fatal(err)
		}
		return party{id, sg}
	}
	squatter, real := mk("Squatter"), mk("Real")
	_ = peer.svc.Store.SetConfig("witness.delegators_covered", `{"`+squatter.aid+`":true,"`+real.aid+`":true}`)
	declare := func(by party, idKey keri.Signer) int {
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		st := []byte(witness.CoverStatement(by.aid, key, aid, said, stamp))
		b, _ := by.signer.Sign(st)
		sg, _ := keri.MatterQB64(keri.CodeEd25519Sig, b)
		ib, _ := idKey.Sign(st)
		isg, _ := keri.MatterQB64(keri.CodeEd25519Sig, ib)
		body, _ := json.Marshal(witness.CoverRequest{Owner: by.aid, AID: aid, Stamp: stamp, Signature: sg, AIDSignature: isg,
			Log: []witness.SignedEvent{{RawBytesB64: base64.StdEncoding.EncodeToString(raw), CesrSignature: sig}}})
		res, err := http.Post(srv.URL+"/api/witness/cover", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	own, _ := keri.GenerateSigner(true)
	if code := declare(squatter, own); code != http.StatusForbidden {
		t.Fatalf("a squatter that is not the identifier's controller was taken: %d", code)
	}
	if code := declare(real, idSigner); code != http.StatusOK {
		t.Fatalf("the identifier's controller was refused after a squatter was: %d", code)
	}
	if code := declare(squatter, own); code != http.StatusForbidden {
		t.Fatalf("a squatter was taken after the real owner: %d", code)
	}
}
