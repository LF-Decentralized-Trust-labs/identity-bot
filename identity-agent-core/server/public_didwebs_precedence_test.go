package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"
)

// The endpoint that writes this map is unauthenticated, and has to be: a pairwise
// counterparty we have never met cannot authenticate before publishing the key
// that identifies it. What must never follow is a stranger's claim overriding
// what we already know about our own assets — this function feeds signed-request
// verification, so an override there is a forged request as that agent.

func serverWithAsset(t *testing.T, a asset.Asset) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	store, err := asset.NewStore(dir)
	if err != nil {
		t.Fatalf("asset store: %v", err)
	}
	if err := store.UpsertAsset(a); err != nil {
		t.Fatalf("save asset: %v", err)
	}
	return &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, assetHandler: &asset.Handler{Store: store}}
}

func TestSelfRegisteredKeyCannotOverrideOurOwnAsset(t *testing.T) {
	const aid = "EOurOwnProvisionedAgentAID"
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recorded := base64.RawURLEncoding.EncodeToString(pub)
	s := serverWithAsset(t, asset.Asset{
		ID: "a1", AssetType: "ai_agent", PairwiseAID: aid,
		PublicKey: recorded,
	})

	// An attacker who knows the AID publishes a key of their own choosing.
	pairwiseKeys.Lock()
	pairwiseKeys.m[aid] = "attacker-supplied-key"
	pairwiseKeys.Unlock()
	t.Cleanup(func() {
		pairwiseKeys.Lock()
		delete(pairwiseKeys.m, aid)
		pairwiseKeys.Unlock()
	})

	if got := s.publicDidWebsPubKey(aid); got != recorded {
		t.Fatalf("a self-registered key overrode our own record: got %q", got)
	}
}

func TestAKnownAssetWeCannotResolveAnswersNothing(t *testing.T) {
	// Falling back to the map here would be the same hole by another route: a
	// known asset with an unresolvable key must be a failure to answer, not an
	// invitation to accept whatever a stranger published for it.
	const aid = "EKnownButUnresolvable"
	s := serverWithAsset(t, asset.Asset{
		ID: "a2", AssetType: "ai_agent", PairwiseAID: aid,
		// no PublicKey, no SigningIndex
	})
	pairwiseKeys.Lock()
	pairwiseKeys.m[aid] = "attacker-supplied-key"
	pairwiseKeys.Unlock()
	t.Cleanup(func() {
		pairwiseKeys.Lock()
		delete(pairwiseKeys.m, aid)
		pairwiseKeys.Unlock()
	})

	if got := s.publicDidWebsPubKey(aid); got != "" {
		t.Fatalf("a known asset we cannot resolve must answer nothing, got %q", got)
	}
}

func TestAStrangerIsStillAnsweredFromTheRegistry(t *testing.T) {
	// The legitimate case the endpoint exists for: an AID we hold no record of.
	// Closing the hole must not close this.
	const aid = "ESomeCounterpartyWeHaveNeverMet"
	s := serverWithAsset(t, asset.Asset{ID: "a3", PairwiseAID: "EDifferentAID", PublicKey: "x"})

	pairwiseKeys.Lock()
	pairwiseKeys.m[aid] = "their-published-key"
	pairwiseKeys.Unlock()
	t.Cleanup(func() {
		pairwiseKeys.Lock()
		delete(pairwiseKeys.m, aid)
		pairwiseKeys.Unlock()
	})

	if got := s.publicDidWebsPubKey(aid); got != "their-published-key" {
		t.Fatalf("an unknown AID should still resolve from the registry, got %q", got)
	}
}

// An enrolling machine sends its key as qb64, or as hex, and the record keeps
// what it sent. Everything downstream takes 32 bytes in unpadded base64url: the
// DID document publishes the key as a JWK "x", which RFC 8037 defines as
// exactly that, and signed-request verification decodes it in that spelling.
// Passing the recorded string through published a qb64 key as a JWK and left a
// machine enrolled in hex unable to sign a request at all.
func TestARecordedAssetKeyIsAnsweredInOneSpelling(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(pub)
	for name, recorded := range map[string]string{
		"qb64":      iacrypto.VerkeyQB64(pub),
		"hex":       hex.EncodeToString(pub),
		"base64url": want,
	} {
		t.Run(name, func(t *testing.T) {
			const aid = "EAMachineThatBroughtItsOwnKey"
			s := serverWithAsset(t, asset.Asset{ID: "m1", PairwiseAID: aid, PublicKey: recorded})
			if got := s.publicDidWebsPubKey(aid); got != want {
				t.Fatalf("recorded as %s %q, answered %q, want %q", name, recorded, got, want)
			}
		})
	}
}

func TestARecordedAssetKeyThatDoesNotReadAnswersNothing(t *testing.T) {
	const aid = "EAMachineWithAnUnreadableKey"
	s := serverWithAsset(t, asset.Asset{ID: "m2", PairwiseAID: aid, PublicKey: "not-a-key"})
	if got := s.publicDidWebsPubKey(aid); got != "" {
		t.Fatalf("an unreadable recorded key must answer nothing, got %q", got)
	}
}
