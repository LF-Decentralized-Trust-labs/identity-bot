package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/store"
)

func vouchRow(t *testing.T, seed []byte, aid, org, signedName, shownName string) asset.Employee {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{
		"v": "VOUCH1", "action": "sign_org", "signer_aid": aid, "org_aid": org, "name": signedName})
	sig, err := login.SignAsk(payload, seed)
	if err != nil {
		t.Fatal(err)
	}
	return asset.Employee{PairwiseAID: aid, Name: shownName, IsSigner: true, Status: "active",
		VouchSig: sig, VouchPayload: string(payload)}
}

func TestAnOwnerIsNamedOnlyByAName(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 7
	key := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	otherSeed := make([]byte, 32)
	otherSeed[0] = 9

	// Signed by the owner: named.
	good := []asset.Employee{vouchRow(t, seed, "EOWNER", "EORG", "Ada Lovelace", "Ada Lovelace")}
	if got, _ := signedNameOf("EOWNER", "EORG", key, good); got.Name != "Ada Lovelace" || got.Payload == "" || got.Signature == "" {
		t.Fatalf("a name the owner signed was not shown: %q", got)
	}

	// The roster name edited after signing: the case that would have shown a
	// forged name before this change.
	edited := []asset.Employee{vouchRow(t, seed, "EOWNER", "EORG", "Ada Lovelace", "Mallory")}
	if got, ok := signedNameOf("EOWNER", "EORG", key, edited); ok || got.Name != "" {
		t.Errorf("an unsigned roster name was shown: %q", got)
	}

	// Signed by some other key.
	forged := []asset.Employee{vouchRow(t, otherSeed, "EOWNER", "EORG", "Mallory", "Mallory")}
	if got, ok := signedNameOf("EOWNER", "EORG", key, forged); ok || got.Name != "" {
		t.Errorf("a name signed by another key was shown: %q", got)
	}

	// A vouch for a different organisation does not name this one's owner.
	elsewhere := []asset.Employee{vouchRow(t, seed, "EOWNER", "EOTHER", "Ada Lovelace", "Ada Lovelace")}
	if got, ok := signedNameOf("EOWNER", "EORG", key, elsewhere); ok || got.Name != "" {
		t.Errorf("a vouch for another organisation named this owner: %q", got)
	}

	// An old row with a name and no signed payload.
	old := []asset.Employee{{PairwiseAID: "EOWNER", Name: "Ada Lovelace", IsSigner: true, Status: "active", VouchSig: "x"}}
	if got, ok := signedNameOf("EOWNER", "EORG", key, old); ok || got.Name != "" {
		t.Errorf("a roster name with no signed payload was shown: %q", got)
	}
}

// The same, through key resolution and the handler.

func seedOf(b byte) []byte { s := make([]byte, 32); s[0] = b; return s }

func keyOf(seed []byte) string {
	return iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

// anOrgWithOwners is an organisation whose own log names the owners, with a
// roster holding the given rows. The first owner is the founder.
func anOrgWithOwners(t *testing.T, owners []string, rows ...asset.Employee) *CoreServer {
	t.Helper()
	s := serverWithIdentity(t, "EORG")
	var anchors []interface{}
	for _, o := range owners {
		anchors = append(anchors, map[string]interface{}{"i": o, "s": "0", "d": o})
	}
	s.KeriDriver = &driverfake.Engine{
		GetKelFunc: func(string) (*drivers.DriverKelResponse, error) {
			return &drivers.DriverKelResponse{AID: "EORG", KEL: []map[string]interface{}{{
				"t": "icp", "i": "EORG", "a": anchors}}}, nil
		},
	}
	st, err := asset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if err := st.UpsertEmployee(r); err != nil {
			t.Fatal(err)
		}
	}
	s.assetHandler = &asset.Handler{Store: st}
	return s
}

func verifiedLog(t *testing.T, s *CoreServer, aid, key string) {
	t.Helper()
	ks, err := didcomm.GenerateKeySet(aid)
	if err != nil {
		t.Fatal(err)
	}
	// A log is kept as verified only with the bytes it was verified by.
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: aid, KEL: inceptionCommittingTo(t, aid, ks),
		KelVerified: true, CurrentPublicKey: key, EventsValidated: 1}); err != nil {
		t.Fatal(err)
	}
}

func listedOwners(t *testing.T, s *CoreServer) (names map[string]string, vouches map[string]signedOwnerName) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleListOwners(rec, httptest.NewRequest(http.MethodGet, "/api/owners/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("listing owners: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Names   map[string]string          `json:"owner_names"`
		Vouches map[string]signedOwnerName `json:"owner_name_vouches"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Names, body.Vouches
}

func TestTheFoundersCurrentKeyNamesThem(t *testing.T) {
	seed := seedOf(1)
	s := anOrgWithOwners(t, []string{"EFOUNDER"}, vouchRow(t, seed, "EFOUNDER", "EORG", "Ada", "Ada"))
	if err := s.SealOwnerAuthority(OwnerAuthority{AID: "EFOUNDER", PublicKey: keyOf(seed)}); err != nil {
		t.Fatal(err)
	}
	names, vouches := listedOwners(t, s)
	if names["EFOUNDER"] != "Ada" {
		t.Fatalf("a name the founder signed with their current key was not shown: %v", names)
	}
	v := vouches["EFOUNDER"]
	if v.Name != "Ada" || v.Payload == "" || v.Signature == "" {
		t.Fatalf("the signed vouch did not travel with the name: %+v", v)
	}
	pub, _ := login.DecodeVerkey(keyOf(seed))
	if ok, err := login.VerifyAsk([]byte(v.Payload), v.Signature, pub); err != nil || !ok {
		t.Fatal("the vouch returned does not verify under the owner's key")
	}
}

func TestAnOwnerWhoHasRotatedShowsNoNameUntilTheySignAgain(t *testing.T) {
	oldSeed := seedOf(1)
	// The founder's real signed history: founded on the old key, rotated to the
	// new one. Its identifier is derived from the inception, so it is the
	// founder's AID throughout.
	log := signedlog.Incept(t, signedlog.KeysFromSeeds(t, oldSeed, seedOf(2))).Rotate()
	founder := log.AID
	s := anOrgWithOwners(t, []string{founder}, vouchRow(t, oldSeed, founder, "EORG", "Ada", "Ada"))
	// Sealed at pairing with the old key; nothing updates it on rotation. The
	// verified log knows the new one.
	if err := s.SealOwnerAuthority(OwnerAuthority{AID: founder, PublicKey: keyOf(oldSeed)}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: founder, KelVerified: true, CurrentPublicKey: log.Key(), EventsValidated: log.Len(),
		KEL: log.Records()}); err != nil {
		t.Fatal(err)
	}
	if names, _ := listedOwners(t, s); len(names) != 0 {
		t.Fatalf("a vouch signed by a superseded key still named the owner: %v", names)
	}
}

func TestANameSignedByAnotherOwnersKeyIsNotShown(t *testing.T) {
	founder, other := seedOf(1), seedOf(3)
	// EOTHER's row carries a vouch the founder's key signed.
	s := anOrgWithOwners(t, []string{"EFOUNDER", "EOTHER"},
		vouchRow(t, founder, "EOTHER", "EORG", "Mallory", "Mallory"))
	if err := s.SealOwnerAuthority(OwnerAuthority{AID: "EFOUNDER", PublicKey: keyOf(founder)}); err != nil {
		t.Fatal(err)
	}
	verifiedLog(t, s, "EOTHER", keyOf(other))
	if names, _ := listedOwners(t, s); names["EOTHER"] != "" {
		t.Fatalf("a name signed by another owner's key was shown: %v", names)
	}
}

func TestANonFounderIsNamedOnlyThroughAVerifiedLog(t *testing.T) {
	founder, other := seedOf(1), seedOf(3)
	s := anOrgWithOwners(t, []string{"EFOUNDER", "EOTHER"},
		vouchRow(t, other, "EOTHER", "EORG", "Grace", "Grace"))
	if err := s.SealOwnerAuthority(OwnerAuthority{AID: "EFOUNDER", PublicKey: keyOf(founder)}); err != nil {
		t.Fatal(err)
	}
	// Only an unverified contact row, which a caller can write: no name.
	if err := s.DataStore.SaveContact(store.ContactRecord{
		AID: "EOTHER", Status: "accepted", PublicKey: keyOf(other)}); err != nil {
		t.Fatal(err)
	}
	if names, _ := listedOwners(t, s); names["EOTHER"] != "" {
		t.Fatalf("an unverified contact row decided a name: %v", names)
	}
	// Once their log is verified, the same vouch names them.
	verifiedLog(t, s, "EOTHER", keyOf(other))
	if names, _ := listedOwners(t, s); names["EOTHER"] != "Grace" {
		t.Fatalf("a name signed under a verified log was not shown: %v", names)
	}
}
