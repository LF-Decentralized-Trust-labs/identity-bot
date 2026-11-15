package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"identity-agent-core/enrolsecret"
	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/keriengine"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// How an ownership ceremony's rotations are made (ADR-061 sections 3, 5 and 6).
//
// A rotation that brings in other owners needs signatures this Identity Agent
// cannot make: each invited owner's key is on their own device. So the
// ceremony does not build and add the event in one step. It PREPARES the
// event, signs the part this Identity Agent's own key owes if it holds that
// key, and leaves the event held in the engine. Each owner's device then
// fetches the exact bytes, checks them against what it agreed to, signs, and
// returns its signature; the engine adds the event when the signatures meet
// both thresholds, through the one append path every other event takes.
//
// Two shapes:
//
//   - Bringing owners in alongside the identity's own key: one rotation. The
//     identity's own key (the one the last event committed to) leads, the
//     invited owners' keys follow, and the next keys include the identity's own.
//   - Handing the identity over: two rotations. The first still has to be
//     signed by the key the identity committed to, so it reveals that key and
//     adds the owners, but commits ONLY to the owners' next keys. The second
//     reveals those and is signed by the owners alone. After it this Identity
//     Agent holds and derives no key of the identity.
const (
	stageFirst  = "rot1"
	stageSecond = "rot2"
)

// ceremonyMember is one invited owner as the ceremony's events lay them out.
type ceremonyMember struct {
	Invitee CeremonyInvitee
	// Next is the digests this member commits to in the first rotation, the
	// classical one first; After is the same for the second rotation of a
	// hand-over.
	Next, After []string
}

// members are the invited owners in the order every event of the ceremony
// lists them: by identifier, ascending, so a device recomputes the layout from
// the owners it recorded and never from this Identity Agent.
func (c *OwnerCeremony) members() ([]ceremonyMember, error) {
	invited := append([]CeremonyInvitee(nil), c.Invited...)
	sort.Slice(invited, func(i, j int) bool { return invited[i].PairwiseAID < invited[j].PairwiseAID })
	out := make([]ceremonyMember, 0, len(invited))
	seen := map[string]bool{}
	for _, inv := range invited {
		if seen[inv.PairwiseAID] {
			return nil, fmt.Errorf("%s was invited twice under one identifier", inv.PairwiseAID)
		}
		seen[inv.PairwiseAID] = true
		next, err := digestsFor(inv.NextPublicKey, inv.NextPostQuantumDigest)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", inv.Name, err)
		}
		m := ceremonyMember{Invitee: inv, Next: next}
		if c.HandOver {
			m.After, err = digestsFor(inv.AfterNextPublicKey, inv.AfterNextPostQuantumDigest)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", inv.Name, err)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// digestsFor is a classical next key's digest, then its post-quantum partner
// when the owner's device made one.
func digestsFor(nextKey, postQuantumDigest string) ([]string, error) {
	d, err := keri.NextDigest(nextKey)
	if err != nil {
		return nil, fmt.Errorf("a next key to commit to: %w", err)
	}
	if postQuantumDigest == "" {
		return []string{d}, nil
	}
	return []string{d, postQuantumDigest}, nil
}

// weightedNext is the next-keys threshold over groups of digests, where each
// group is one owner's and any one of its digests stands for the owner:
// threshold of len(groups) owners, each worth 1/threshold, with a flat count
// when every owner commits to one digest (ADR-061 section 6). Where every owner
// must act it is the plain form, one clause per owner ([["1","1"],...]), which
// older KERI implementations read; the nested form, which they do not, is kept
// for when only some owners must act.
func weightedNext(threshold int, groups [][]string) json.RawMessage {
	nested := false
	for _, g := range groups {
		if len(g) > 1 {
			nested = true
		}
	}
	if !nested {
		return json.RawMessage(fmt.Sprintf("%q", fmt.Sprintf("%x", threshold)))
	}
	if threshold >= len(groups) {
		clauses := make([]string, 0, len(groups))
		for _, g := range groups {
			ones := make([]string, len(g))
			for i := range ones {
				ones[i] = `"1"`
			}
			clauses = append(clauses, "["+strings.Join(ones, ",")+"]")
		}
		return json.RawMessage("[" + strings.Join(clauses, ",") + "]")
	}
	w := keriRatio(1, threshold)
	elements := make([]string, 0, len(groups))
	for _, g := range groups {
		ones := make([]string, len(g))
		for i := range ones {
			ones[i] = `"1"`
		}
		elements = append(elements, fmt.Sprintf(`{%q:[%s]}`, w, strings.Join(ones, ",")))
	}
	return json.RawMessage("[" + strings.Join(elements, ",") + "]")
}

// keriRatio is 1/n in lowest terms, as a weight is written.
func keriRatio(num, den int) string {
	if den <= 1 {
		return "1"
	}
	return fmt.Sprintf("%d/%d", num, den)
}

func countThreshold(n int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf("%q", fmt.Sprintf("%x", n)))
}

// ceremonyRotation is the rotation a stage is: what Prepare builds it from.
func (s *CoreServer) ceremonyRotation(c *OwnerCeremony, stage string) (keriengine.PrepareRequest, error) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return keriengine.PrepareRequest{}, fmt.Errorf("this Identity Agent has no identity to rotate")
	}
	members, err := c.members()
	if err != nil {
		return keriengine.PrepareRequest{}, err
	}
	req := keriengine.PrepareRequest{Name: identity.AID, Ilk: "rot"}

	if stage == stageSecond {
		// The owners' own next keys, revealed, signed by them alone, committing
		// to the keys each named for after this.
		var after [][]string
		for _, m := range members {
			req.Keys = append(req.Keys, m.Invitee.NextPublicKey)
			after = append(after, m.After)
			req.Next = append(req.Next, m.After...)
		}
		req.Kt = countThreshold(c.Threshold)
		req.Nt = weightedNext(c.Threshold, after)
		return req, nil
	}

	// The seals: everyone who owned it before, then everyone who is accepting.
	existing, err := s.ownersOfOwnIdentity(identity.AID)
	if err != nil {
		return keriengine.PrepareRequest{}, fmt.Errorf("could not read the current owners: %w", err)
	}
	for _, aid := range existing {
		seal, err := ownerAnchorSeal(aid)
		if err != nil {
			return keriengine.PrepareRequest{}, fmt.Errorf("an existing owner cannot be anchored: %w", err)
		}
		req.Anchors = append(req.Anchors, seal)
	}
	// The identity's own key leads: it is the one the last event committed to,
	// and no verifier accepts a rotation without it.
	req.Keys = []string{c.OwnPublicKey}
	var next [][]string
	if !c.HandOver {
		// The identity's own share commits its classical next key only, so in
		// a ceremony that keeps it, it is the one share with no post-quantum
		// commitment until this core's next ordinary rotation renews one
		// (rotateCarryingTheCommitment). Carrying it here needs the owners'
		// devices to be told the identity's two digests, which the ceremony's
		// terms do not yet say.
		own, err := digestsFor(c.OwnNextPublicKey, "")
		if err != nil {
			return keriengine.PrepareRequest{}, fmt.Errorf("the identity's own next key: %w", err)
		}
		next = append(next, own)
		req.Next = append(req.Next, own...)
	}
	for _, m := range members {
		seal, err := ownerAnchorSeal(m.Invitee.PairwiseAID)
		if err != nil {
			return keriengine.PrepareRequest{}, fmt.Errorf("an incoming owner cannot be anchored: %w", err)
		}
		req.Anchors = append(req.Anchors, seal)
		req.Keys = append(req.Keys, m.Invitee.PublicKey)
		next = append(next, m.Next)
		req.Next = append(req.Next, m.Next...)
	}
	// Everybody signs the first rotation: it hands real control to each of
	// them, and one who has not seen it has not agreed to it.
	req.Kt = countThreshold(len(req.Keys))
	req.Nt = weightedNext(c.Threshold, next)
	return req, nil
}

// prepareCeremonyStage builds the stage's rotation, adds this Identity
// Agent's own signature if the stage owes one, and records the event the
// owners' devices are to sign. Callers hold ceremonyMu.
func (s *CoreServer) prepareCeremonyStage(c *OwnerCeremony, stage string) error {
	committer, ok := s.KeriDriver.(eventCommitter)
	if !ok {
		return fmt.Errorf("no KERI engine here prepares events")
	}
	req, err := s.ceremonyRotation(c, stage)
	if err != nil {
		return err
	}
	p, err := committer.Prepare(req)
	if err != nil {
		return fmt.Errorf("the rotation could not be prepared: %w", err)
	}
	c.Stage, c.PendingRawB64, c.PendingSAID, c.Status = stage, base64.StdEncoding.EncodeToString(p.Raw), p.Hint.D, ceremonySigning
	if stage == stageFirst {
		// The first rotation is signed by the identity's own key too, which is
		// held here or the ceremony does not start (mayRotateHere).
		seed, err := s.ownSeedForKey(c.OwnPublicKey)
		if err != nil {
			return fmt.Errorf("this Identity Agent cannot sign with the identity's own key: %w", err)
		}
		sig, err := keri.EncodeIndexedSignature(ed25519.Sign(ed25519.NewKeyFromSeed(seed), p.Raw), keri.SamePlace(0))
		if err != nil {
			return err
		}
		ev, err := keri.ParseEvent(p.Raw)
		if err != nil {
			return err
		}
		if _, err := s.commitAndNote(committer, ownAID(s), p.Raw, ev, []string{sig}); err != nil {
			return fmt.Errorf("the identity's own signature was refused: %w", err)
		}
	}
	return s.saveCeremony(c)
}

// ownAID is the name of the identity kept here, for the engine's calls.
func ownAID(s *CoreServer) string {
	if own, _ := s.DataStore.GetIdentity(); own != nil {
		return own.AID
	}
	return ""
}

// ceremonyForToken is the ceremony in the signing stage and the invitee whose
// invite code token is. Callers hold ceremonyMu.
func (s *CoreServer) ceremonyForToken(token string) (*OwnerCeremony, *CeremonyInvitee, int, error) {
	c, err := s.loadCeremony()
	if err != nil {
		return nil, nil, http.StatusInternalServerError, err
	}
	if c == nil || c.Status != ceremonySigning || token == "" {
		return nil, nil, http.StatusNotFound, fmt.Errorf("no ceremony is waiting for signatures")
	}
	for i := range c.Invited {
		if c.Invited[i].TokenDigest != "" && enrolsecret.Equal(token, c.Invited[i].TokenDigest) {
			return c, &c.Invited[i], 0, nil
		}
	}
	return nil, nil, http.StatusNotFound, fmt.Errorf("no ceremony is waiting for signatures")
}

// handleCeremonyEvent gives an invited owner's device the event it is to sign:
// the exact bytes, the stage, and what it needs to find its places in it. The
// device checks the bytes against what it agreed; nothing here is taken on
// trust. Public, reached by the invite code: see api_auth.go.
func (s *CoreServer) handleCeremonyEvent(w http.ResponseWriter, r *http.Request) {
	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()
	c, _, code, err := s.ceremonyForToken(chi.URLParam(r, "token"))
	if err != nil {
		writeError(w, code, "Nothing to sign", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]any{
		"stage": c.Stage, "hand_over": c.HandOver, "threshold": c.Threshold,
		"raw_b64": c.PendingRawB64, "d": c.PendingSAID,
	})
}

// ceremonyStatusForToken is where the ceremony the invite code belongs to has
// got to, in any state. Callers hold ceremonyMu.
func (s *CoreServer) ceremonyStatusForToken(token string) (status, detail string, ok bool) {
	c, err := s.loadCeremony()
	if err != nil || c == nil || token == "" {
		return "", "", false
	}
	for i := range c.Invited {
		if c.Invited[i].TokenDigest != "" && enrolsecret.Equal(token, c.Invited[i].TokenDigest) {
			return c.Status, c.Detail, true
		}
	}
	return "", "", false
}

// handleCeremonyTerms tells an invited owner's device who is taking part and on
// what terms, so the person is shown them before anything is signed and the
// device can hold the rotation to exactly them. Everything it says about the
// owners is what each of them handed over when they accepted; the event's own
// fields (identifier, place in the log, seals, witnesses) are read from the
// bytes waiting to be signed. Public, reached by the invite code.
func (s *CoreServer) handleCeremonyTerms(w http.ResponseWriter, r *http.Request) {
	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()
	token := chi.URLParam(r, "token")
	c, _, code, err := s.ceremonyForToken(token)
	if err != nil {
		// Not signing yet, or over: an owner's device that is waiting needs to tell
		// "the others have not all accepted" from "it was made" from "it was
		// dropped", so the state is said to the one holding a code of the
		// ceremony and to nobody else.
		if status, detail, ok := s.ceremonyStatusForToken(token); ok {
			// The detail is the Identity Agent's own words about why it failed, and says
			// when a hand-over stopped after its first rotation was made.
			jsonreply.Write(w, http.StatusOK, map[string]any{"status": status, "detail": detail})
			return
		}
		writeError(w, code, "Nothing to sign", err.Error())
		return
	}
	members, err := c.members()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The ceremony record is unreadable", err.Error())
		return
	}
	raw, err := base64.StdEncoding.DecodeString(c.PendingRawB64)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The ceremony record is unreadable", err.Error())
		return
	}
	var ev struct {
		I  string            `json:"i"`
		S  string            `json:"s"`
		P  string            `json:"p"`
		Bt string            `json:"bt"`
		Br []string          `json:"br"`
		Ba []string          `json:"ba"`
		A  []json.RawMessage `json:"a"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		writeError(w, http.StatusInternalServerError, "The ceremony record is unreadable", err.Error())
		return
	}
	type owner struct {
		Name    string   `json:"name"`
		AID     string   `json:"aid"`
		Key     string   `json:"key"`
		Next    []string `json:"next"`
		NextKey string   `json:"next_key,omitempty"`
		After   []string `json:"after,omitempty"`
		Signed  bool     `json:"signed"`
	}
	owners := make([]owner, 0, len(members))
	for _, m := range members {
		owners = append(owners, owner{
			Name: m.Invitee.Name, AID: m.Invitee.PairwiseAID, Key: m.Invitee.PublicKey,
			Next: m.Next, NextKey: m.Invitee.NextPublicKey, After: m.After,
			Signed: m.Invitee.SignedStage == c.Stage,
		})
	}
	ownNext := ""
	if !c.HandOver {
		if d, err := keri.NextDigest(c.OwnNextPublicKey); err == nil {
			ownNext = d
		}
	}
	jsonreply.Write(w, http.StatusOK, map[string]any{
		"status": c.Status,
		"stage":  c.Stage, "hand_over": c.HandOver, "threshold": c.Threshold,
		"aid": ev.I, "sn": ev.S, "prior": ev.P, "d": c.PendingSAID,
		"own_key": c.OwnPublicKey, "own_next_digest": ownNext,
		"toad": ev.Bt, "cuts": ev.Br, "adds": ev.Ba, "anchors": ev.A,
		"owners": owners,
	})
}

// handleCeremonySignature takes an owner's signature or signatures over the
// event in front of them. The engine adds the event when the signatures it
// holds meet both thresholds; until then it holds them. A signature that does
// not verify under the key it names is refused whoever sent it.
func (s *CoreServer) handleCeremonySignature(w http.ResponseWriter, r *http.Request) {
	var body struct {
		D    string   `json:"d"`
		Sigs []string `json:"sigs"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxKeyEventBody)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Sigs) == 0 {
		writeError(w, http.StatusBadRequest, "No signature", "send the event's digest as d and your signatures as sigs")
		return
	}
	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()
	c, who, code, err := s.ceremonyForToken(chi.URLParam(r, "token"))
	if err != nil {
		writeError(w, code, "Nothing to sign", err.Error())
		return
	}
	// Named by digest so a signature made over the first rotation cannot be
	// taken as one over the second, or the reverse.
	if body.D != c.PendingSAID {
		writeError(w, http.StatusConflict, "That is not the event waiting", "fetch the event again: it is now "+c.PendingSAID)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(c.PendingRawB64)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The ceremony record is unreadable", err.Error())
		return
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The ceremony record is unreadable", err.Error())
		return
	}
	committer, ok := s.KeriDriver.(eventCommitter)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "No KERI engine here prepares events", "")
		return
	}
	res, err := s.commitAndNote(committer, ownAID(s), raw, ev, body.Sigs)
	if err != nil {
		writeEventError(w, err)
		return
	}
	// Remembered so the person who started the ceremony can see whose device
	// has signed and whose has not, rather than only that it is waiting.
	if who != nil {
		who.SignedStage = c.Stage
		if err := s.saveCeremony(c); err != nil {
			writeError(w, http.StatusInternalServerError, "Could not record the ceremony", err.Error())
			return
		}
	}
	if res.Status == "waiting_for_signatures" {
		jsonreply.Write(w, http.StatusAccepted, map[string]any{"status": res.Status, "signed": res.Signed, "keys": res.Keys})
		return
	}
	// The event is in the log. A hand-over goes on to its second rotation; the
	// ceremony is otherwise done.
	if c.HandOver && c.Stage == stageFirst {
		if err := s.prepareCeremonyStage(c, stageSecond); err != nil {
			c.Status, c.Detail, c.RotationSAID = ceremonyFailed, "the first rotation was made, and the second could not be prepared: "+err.Error(), res.SAID
			_ = s.saveCeremony(c)
			writeError(w, http.StatusInternalServerError, "The hand-over stopped half way", c.Detail)
			return
		}
		jsonreply.Write(w, http.StatusCreated, map[string]any{"status": res.Status, "next_stage": stageSecond})
		return
	}
	if c.HandOver {
		// After the second rotation nothing here signs for this identity. The
		// record already names an owner's key as the current one, so the key
		// is read as elsewhere; what is left is the signer a box installed.
		// The mark is a second write after the rotation's: if it is lost, the
		// record still names an owner's key, which already refuses every
		// signature and rotation here; the mark is what holds if that record
		// is ever put back.
		s.eventSigners.Delete(ev.Identifier)
		if err := s.markHandedOver(ev.Identifier); err != nil {
			writeError(w, http.StatusInternalServerError, "The hand-over was made, and the record of it could not be kept", err.Error())
			return
		}
	}
	c.Status, c.Detail, c.RotationSAID = ceremonyApplied, "", res.SAID
	c.AppliedAt = time.Now().UTC()
	c.Stage, c.PendingRawB64, c.PendingSAID = "", "", ""
	if err := s.saveCeremony(c); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not record the ceremony", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusCreated, map[string]any{"status": res.Status, "applied": true})
}

// markHandedOver records on the identity that its keys now belong to its
// owners' devices, so nothing here goes on to derive one of them from the
// generation the record still holds. Saving it again is harmless.
func (s *CoreServer) markHandedOver(aid string) error {
	own, err := s.DataStore.GetIdentity()
	if err != nil || own == nil || own.AID != aid {
		return fmt.Errorf("no identity record for %s to mark", aid)
	}
	if own.HandedOver {
		return nil
	}
	own.HandedOver = true
	return s.DataStore.SaveIdentity(*own)
}
