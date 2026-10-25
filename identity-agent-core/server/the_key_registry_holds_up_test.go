package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/login"
)

type registrySigner struct {
	s   keri.Signer
	pub string
}

func aRegistrySigner(t *testing.T, transferable bool) registrySigner {
	t.Helper()
	s, err := keri.GenerateSigner(transferable)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return registrySigner{s, p}
}

func (r registrySigner) sign(t *testing.T, raw []byte) string {
	t.Helper()
	sig, err := r.s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	q, err := keri.MatterQB64(keri.CodeEd25519Sig, sig)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func (r registrySigner) next(t *testing.T) string {
	t.Helper()
	d, err := keri.NextDigest(r.pub)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A thief who stole an identity's key appends an interaction event with it
// and publishes that log first. The owner, who still holds the pre-rotated
// key, rotates, and the rotation takes the identity back: a thief can extend
// a log with interactions, but only the owner can rotate.
func TestAThiefsInteractionDoesNotHoldTheIdentityAgainstItsOwner(t *testing.T) {
	k0, k1, k2 := aRegistrySigner(t, true), aRegistrySigner(t, true), aRegistrySigner(t, true)
	witness := aRegistrySigner(t, false)
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{k0.pub}, NextDigests: []string{k1.next(t)},
		Witnesses: []string{witness.pub}, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(icp)
	aid := ev.Identifier

	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: ev.SAID, SN: 1})
	if err != nil {
		t.Fatal(err)
	}
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: aid, Keys: []string{k1.pub}, PriorSAID: ev.SAID, SN: 1,
		NextDigests: []string{k2.next(t)}, PriorWitnesses: []string{witness.pub},
	})
	if err != nil {
		t.Fatal(err)
	}
	thiefs, err := login.EncodeKeyLog([][]byte{icp, ixn}, []string{k0.sign(t, icp), k0.sign(t, ixn)})
	if err != nil {
		t.Fatal(err)
	}
	owners, err := login.EncodeKeyLog([][]byte{icp, rot}, []string{k0.sign(t, icp), k1.sign(t, rot)})
	if err != nil {
		t.Fatal(err)
	}

	registry := theOrganisationsRegistry(t, &CoreServer{DataDir: t.TempDir()})
	if code, body := register(t, registry, aid, "", thiefs); code != http.StatusOK {
		t.Fatalf("the thief's log was refused before the owner's, so the test proves nothing: %d %s", code, body)
	}
	if code, body := register(t, registry, aid, "", owners); code != http.StatusOK {
		t.Fatalf("the owner's rotation could not take the identity back from the thief: %d %s", code, body)
	}
	pub, _ := login.KeyFromKeyLog(aid, owners)
	if got := publishedKey(t, registry, aid); got == "" || got != base64.RawURLEncoding.EncodeToString(pub) {
		t.Fatalf("after recovery the registry answers %q, want the owner's rotated key", got)
	}
	// And the thief cannot undo it with their interaction again.
	if code, _ := register(t, registry, aid, "", thiefs); code == http.StatusOK {
		t.Fatal("the thief's log replaced the owner's rotation")
	}
}

// The registry is bounded by the bytes its logs take, not only by how many
// identities it holds, so a stranger cannot fill it with long logs.
func TestTheRegistryIsBoundedByWhatItsLogsWeigh(t *testing.T) {
	reg := &keyRegistry{m: map[string]registeredKey{}, unreadable: map[string]bool{}}
	reg.bytes = maxRegisteredKeysBytes - 10
	aid, log, pub := theirKeyLog(t, 1000201)
	if code, err := reg.put(aid, registeredKey{KeyLog: log, PublicKeyB64: pub}); err == nil || code != http.StatusInsufficientStorage {
		t.Fatalf("a registry at its byte bound accepted another log (%d, %v)", code, err)
	}
}

// Publishing the same key again writes nothing, so a person signing in every
// day does not rewrite the registry every day.
func TestPublishingTheSameKeyAgainWritesNothing(t *testing.T) {
	dir := t.TempDir()
	s := &CoreServer{DataDir: dir}
	aid, log, pub := theirKeyLog(t, 1000202)
	if _, err := s.keyRegistry().put(aid, registeredKey{KeyLog: log, PublicKeyB64: pub}); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "registered_keys")
	// The directory read-only now: any write would fail, so success means
	// nothing was written.
	if err := os.Chmod(keys, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keys, 0o700) })
	if _, err := s.keyRegistry().put(aid, registeredKey{KeyLog: log, PublicKeyB64: pub}); err != nil {
		t.Fatalf("an unchanged registration rewrote its entry: %v", err)
	}
}

// An entry that cannot be read is neither answered for nor overwritten, so a
// damaged file is something a person sees, not a key quietly lost.
func TestAnEntryThatCannotBeReadIsNeitherAnsweredNorReplaced(t *testing.T) {
	dir := t.TempDir()
	aid, log, pub := theirKeyLog(t, 1000203)
	if err := os.MkdirAll(filepath.Join(dir, "registered_keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "registered_keys", aid+".json")
	if err := os.WriteFile(file, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := theOrganisationsRegistry(t, &CoreServer{DataDir: dir})
	if got := publishedKey(t, registry, aid); got != "" {
		t.Fatalf("an unreadable entry was answered for: %s", got)
	}
	if code, _ := register(t, registry, aid, pub, log); code != http.StatusConflict {
		t.Fatalf("an unreadable entry was replaced (status %d)", code)
	}
	if b, _ := os.ReadFile(file); string(b) != "not json" {
		t.Fatal("the unreadable entry was overwritten")
	}
}

// Two agents sharing one data directory each write only their own entries,
// so neither loses the other's.
func TestTwoWritersOnOneDirectoryLoseNothing(t *testing.T) {
	dir := t.TempDir()
	a, b := &CoreServer{DataDir: dir}, &CoreServer{DataDir: dir}
	var wg sync.WaitGroup
	var aids []string
	var mu sync.Mutex
	for i := 0; i < 10; i++ {
		aid, log, pub := theirKeyLog(t, 1000300+i)
		aids = append(aids, aid)
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func(s *CoreServer, aid, log, pub string) {
			defer wg.Done()
			if _, err := s.keyRegistry().put(aid, registeredKey{KeyLog: log, PublicKeyB64: pub}); err != nil {
				mu.Lock()
				t.Errorf("put %s: %v", aid, err)
				mu.Unlock()
			}
		}(s, aid, log, pub)
	}
	wg.Wait()
	restarted := &CoreServer{DataDir: dir}
	for _, aid := range aids {
		if _, ok := restarted.keyRegistry().get(aid); !ok {
			t.Errorf("%s was lost between two writers", aid)
		}
	}
}

// The open key-log routes give each caller a share, so one caller cannot keep
// this agent checking logs.
func TestTheKeyLogRoutesGiveEachCallerAShare(t *testing.T) {
	registry := theOrganisationsRegistry(t, &CoreServer{})
	body, _ := json.Marshal(map[string]string{"aid": "E", "key_log": "x"})
	limited := false
	for i := 0; i < keyLogChecksPerMinute+5; i++ {
		resp, err := http.Post(registry.URL+"/public/login/key", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("%d requests from one caller were all checked", keyLogChecksPerMinute+5)
	}
}

// The relay: a site copies the organisation's live challenge (its audience,
// nonce and session) into a challenge it signs itself, and the person approves
// what their agent shows as that site. The assertion names the site whose
// challenge was approved, so the organisation refuses it.
func TestAnAssertionApprovedForAnotherSiteDoesNotSignInHere(t *testing.T) {
	h, rel, _ := theirAgent(t, 1000401)
	s := theirOrganisation(t, map[string]bool{rel.PairwiseAID: true})
	const token = "session-1"
	real := login.ChallengeBundle{SiteAID: "ESiteAID", Audience: "https://portal.example",
		Nonce: "the-real-nonce", SessionToken: token}
	s.challengeMu.Lock()
	s.challenges[token] = real
	s.challengeMu.Unlock()

	relayed := real
	relayed.SiteAID = "EAttackersSite"
	a, err := h.BuildAssertion(rel, &relayed, nil)
	if err != nil {
		t.Fatal(err)
	}
	code, body := postAssertion(t, s, token, a)
	if code == http.StatusOK {
		t.Fatalf("an assertion approved for another site's challenge signed an employee in here: %s", body)
	}
	if !strings.Contains(body, "site mismatch") {
		t.Errorf("refused for the wrong reason: %d %s", code, body)
	}
}
