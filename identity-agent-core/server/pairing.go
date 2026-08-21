package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"identity-agent-core/drivers"
	"identity-agent-core/witness"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"encoding/base64"
	"identity-agent-core/backup"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// Adopting an agent that is not yours yet.
//
// A freshly provisioned instance has no identity and no owner. Somebody has to
// adopt it, and the way they do it decides everything about what renting
// hardware means.
//
// The wrong way is the obvious one: hand the box your root seed and let it act
// as you. It works, it is one HTTP call, and it means your root key now lives
// on hardware somebody else owns. There is no recovering from that — not by
// unpairing, not by deleting the instance.
//
// So the box never receives a key. It generates its own, hands out only the
// public half, and the controller issues a KERI delegated inception (`dip`)
// naming that key, anchored in the controller's own KEL. The box ends up able
// to sign for itself and independently revocable; the root never moves.
//
// Two calls, both reachable before an owner exists because that is the only
// moment they are for, and both refused the instant one succeeds.

type pairingBeginResponse struct {
	// PairwiseAID is the identity the box published for discovery, echoed so a
	// controller can confirm it is adopting the box it resolved.
	PairwiseAID string `json:"pairwise_aid"`
	// PublicKey and NextPublicKey are the box's own delegated key material.
	// Public halves only — the private keys never leave the instance, which is
	// the entire point of the ceremony.
	PublicKey     string `json:"public_key"`
	NextPublicKey string `json:"next_public_key"`
	// Attestation is this machine's hardware vouching for the two keys above.
	//
	// Without it a controller fetches key material and signs a delegation over
	// it having established nothing about where it came from. Anyone able to
	// answer this request — the machine's operator, or anything terminating the
	// connection — could substitute their own keys, and the delegation the
	// owner then issues covers their machine instead. It would verify. Third
	// parties checking the chain afterwards would find it correct, and pointing
	// somewhere nobody chose.
	//
	// Empty where the machine is not sealed hardware, which is an honest answer
	// and not a failure — a laptop has no such statement to make. The adopting
	// side decides what to do about that; it must not decide silently.
	Attestation string `json:"attestation,omitempty"`
	// BackupSigningKey is the key this machine signs its own backups with, so
	// its owner can tell one of its archives from one somebody substituted.
	//
	// Published here and nowhere else, because here is the one moment the
	// hardware is vouching for what the machine hands over. A key learned
	// afterwards is a key anything in the middle can replace, and the owner
	// would record the substitute and verify forgeries against it forever.
	BackupSigningKey string `json:"backup_signing_key,omitempty"`
	// Challenge is the nonce a claimant must sign to show it holds the identity
	// it claims as. Fresh per offer and bound into what gets signed, so a
	// signature lifted from one exchange cannot be replayed into another.
	Challenge string `json:"challenge"`
}

type pairingCompleteRequest struct {
	// DipEvent is the delegated inception the controller issued over the key
	// material from begin.
	//
	// An identity that must be able to change hands sends none. A delegation
	// cannot be transferred, only destroyed, so a delegated identity could
	// never be handed on without killing it and every relationship it ever had.
	// Such an identity incepts its own root instead and names its owner in that
	// event — see FoundAsRoot.
	DipEvent map[string]interface{} `json:"dip_event"`
	// FoundAsRoot asks this instance to found an identity of its own, naming
	// who owns it, rather than become somebody's delegated agent.
	//
	// The identity gets its own key, so it can hold relationships and keep its
	// own address current without reaching for a person every time. What the
	// owner controls is the identity itself.
	FoundAsRoot bool `json:"found_as_root,omitempty"`
	// DelegatorIxn is the controller's interaction event anchoring the
	// delegation in its own KEL — what makes the delegation verifiable by a
	// third party rather than merely asserted here.
	DelegatorIxn map[string]interface{} `json:"delegator_ixn,omitempty"`
	// DelegatorAID is whose authority a delegated identity is founded under.
	//
	// Not a root identifier. Saying so was an instruction to put one into an
	// event that gets published, which is what a delegated inception does with
	// its delegator.
	//
	// Empty on everything pairing sends: nothing here delegates.
	DelegatorAID string `json:"delegator_aid"`
	// OwnerDID is the owner device's encryption keys, so this instance can
	// reach it without asking anybody for them later.
	//
	// Carried here rather than fetched afterwards, because afterwards means
	// over the network, from whoever answers, checked against nothing. That
	// fetch is the one step a party sitting between the two can answer with its
	// own keys — and then read everything encrypted to what it supplied. This
	// exchange is already proven: it takes an adoption code issued to this
	// owner and a key this instance was told to expect, so keys arriving inside
	// it are as trustworthy as the adoption itself.
	//
	// Optional, so an older client still adopts successfully. What it loses is
	// the encrypted transport, which needs a relationship that exists in both
	// directions.
	OwnerDID *didcomm.DID `json:"owner_did,omitempty"`
	// OwnerAgentEndpoint is where that owner's agent is reached.
	OwnerAgentEndpoint string `json:"owner_agent_endpoint,omitempty"`
	// OwnerOOBI is where the owner's key log can be fetched from.
	//
	// The log is presented in OwnerKEL as well, and both matter. Presented, it
	// can be checked with no network at all. Fetched, it can be checked against
	// what somebody OTHER than the claimant is serving — which is the only way
	// to notice a rotation the claimant withheld.
	OwnerOOBI string `json:"owner_oobi,omitempty"`
	// AdoptionCode is the one-time code this instance issued with its pairing
	// offer. Without it, whoever reaches an unadopted box first takes it.
	AdoptionCode string `json:"adoption_code"`
	// OwnerAID and OwnerPublicKey become the owner authority: whose signature
	// this instance will accept as its owner's from now on.
	OwnerAID       string `json:"owner_aid"`
	OwnerPublicKey string `json:"owner_public_key"`
	// OwnerKEL is the claimant's own key log, presented rather than fetched.
	//
	// A key log is self-verifying, so a machine with no route to the internet
	// can still establish who controls the claiming identity — which matters,
	// because a computer being set up is the one most likely to have no working
	// network yet.
	OwnerKEL []map[string]interface{} `json:"owner_kel,omitempty"`
	// OwnerSignature is a fresh signature over this exchange, by the key that
	// log puts in force. It is what turns the claim token from a bearer secret
	// into one factor of two.
	OwnerSignature string `json:"owner_signature,omitempty"`
	// BackupSealPublicKeyB64 is the X25519 public key this instance seals its
	// backup keys to, so it can write archives it cannot itself read.
	//
	// It arrives here rather than being configured afterwards because the gap
	// between the two is the one window where an instance is running, holding
	// real data, and unable to back any of it up safely. There is no reason to
	// have that window: the owner is already talking to it, and already has the
	// key. For an identity with several owners this carries one key per owner,
	// any of whom can then restore alone.
	BackupSealPublicKeysB64 []string `json:"backup_seal_public_keys_b64,omitempty"`
}

// pairingState holds the key material offered by begin, so complete can check
// the delegation was issued over it. Process-wide: an instance is adopted once.
var pairingState struct {
	sync.Mutex
	offered *pairingBeginResponse
	// seed is the private half, kept only in memory between the two calls.
	seed []byte
	// derivationIndex is WHERE that seed came from, and unlike the seed it is
	// written down. The seed is deliberately forgotten; the index has to
	// survive, or the identity can never rotate — a rotation carries the key
	// the previous event committed to, and that key exists only as a derivation
	// nobody could repeat.
	derivationIndex int
	// challenge is the nonce this offer issued. Kept with the offer rather than
	// regenerated, because the claimant signs the one it was given and a fresh
	// one would refuse every honest claim.
	challenge string
}

// handlePairingBegin generates this instance's delegated key material and hands
// out the public halves.
func (s *CoreServer) handlePairingBegin(w http.ResponseWriter, r *http.Request) {
	if err := s.refuseIfAlreadyPaired(w); err != nil {
		return
	}

	pairingState.Lock()
	defer pairingState.Unlock()

	// Offer the same material twice rather than generating fresh keys on a
	// retry: a controller that retried would otherwise issue a delegation over
	// a key the box had already replaced, and the box would refuse its own
	// adoption.
	if pairingState.offered != nil {
		writeJSONResponse(w, pairingState.offered)
		return
	}

	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "No key material", err.Error())
		return
	}
	// Derived, not random: the delegated key is recoverable from this
	// instance's own backup, so adoption survives the instance being restored.
	idx, err := s.DataStore.AllocateNextRelationshipIndex("delegated-identity")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not allocate a key index", err.Error())
		return
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not derive a key", err.Error())
		return
	}
	nextSeed, err := backup.DerivePairwiseSeed(rootSeed, idx, 1)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not derive a rotation key", err.Error())
		return
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)

	challenge, err := newPairingChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not create a challenge", err.Error())
		return
	}

	offer := &pairingBeginResponse{
		PublicKey:     iacrypto.VerkeyQB64(pub),
		NextPublicKey: iacrypto.VerkeyQB64(nextPub),
		Challenge:     challenge,
	}
	backupPub, err := secureenclave.BackupSigningPublicKey(s.DataDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"This machine cannot say what it signs its backups with", err.Error())
		return
	}
	offer.BackupSigningKey = base64.StdEncoding.EncodeToString(backupPub)
	// Ask the hardware to vouch for exactly these keys, so the controller can
	// establish that the offer came from a sealed machine before it signs
	// anything over it. Silence here means no such hardware, which the
	// controller is left to judge.
	if binding, berr := iacrypto.PairingOfferBinding(
		offer.PublicKey, offer.NextPublicKey, offer.BackupSigningKey); berr == nil {
		if report, rerr := secureenclave.GetSNPReport(binding); rerr == nil && report != nil {
			offer.Attestation = base64.StdEncoding.EncodeToString(report.Raw)
		}
	}
	pairingOnce.Lock()
	if pairingOnce.offer != nil {
		offer.PairwiseAID = pairingOnce.offer.AID
	}
	pairingOnce.Unlock()

	pairingState.offered = offer
	pairingState.seed = seed
	// Kept so the identity can record WHERE its key came from. Without it the
	// identity could never rotate: a rotation must carry the key the previous
	// event committed to, and that key is only findable by deriving it again
	// from this index.
	pairingState.derivationIndex = idx
	pairingState.challenge = challenge
	writeJSONResponse(w, offer)
}

// handlePairingComplete accepts the delegation and seals the owner.
//
// This is the moment an instance stops being nobody's, so every check here is
// about one question: is this delegation actually over the key this box just
// generated, from the party claiming to have issued it?
func (s *CoreServer) handlePairingComplete(w http.ResponseWriter, r *http.Request) {
	if err := s.refuseIfAlreadyPaired(w); err != nil {
		return
	}

	var req pairingCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	pairingState.Lock()
	defer pairingState.Unlock()
	if pairingState.offered == nil {
		writeError(w, http.StatusConflict, "Nothing to complete",
			"call /api/pairing/begin first — there is no key material to found an identity over")
		return
	}
	// What the claimant had to sign over, taken from what this instance issued
	// rather than from what the claim echoes back.
	challenge := pairingState.challenge
	offeredPublicKey := pairingState.offered.PublicKey

	// Check the code before anything else is considered. An instance that
	// validated a delegation first would leak whether the delegation was
	// well-formed to somebody with no standing to ask.
	expected, expectedOwner, told := expectedAdoption()
	if !told {
		// Nobody has said which identity may claim this machine, so it cannot
		// tell a real claim from a stranger's.
		//
		// A standing offer is NOT enough on its own, and that is deliberate. If
		// a claim could be made straight against a displayed code, the step
		// that locks the machine to the identity that scanned it would be
		// optional — and anyone who saw the screen would simply skip it. The
		// code earns the right to say who may claim; it is not itself a claim.
		if _, live := localPairingOffer(); live {
			writeError(w, http.StatusConflict, "Nobody has claimed this yet",
				"this computer is showing a code, and whoever scans it says which identity "+
					"may claim it before claiming. Scan it again from the device holding "+
					"your identity")
			return
		}
		writeError(w, http.StatusConflict, "Not offered for pairing",
			"this computer has not been offered for pairing. If it is in front of you, "+
				"offer it from its own screen; otherwise it is claimed with the code "+
				"issued when it was set up")
		return
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(req.AdoptionCode)) != 1 {
		writeError(w, http.StatusForbidden, "Wrong adoption code",
			"this instance was set up for somebody, and adopting it needs the token issued at that time")
		return
	}
	// The token says the claimant knows a secret. This says they are the party
	// it was issued to. Without it a leaked token would let anybody install
	// themselves as owner, which is most of what the token exists to prevent.
	//
	// Always compared now. A machine in front of you is told who to expect by
	// whoever scanned it, so there is no case left where nobody was named.
	if subtle.ConstantTimeCompare([]byte(expectedOwner), []byte(req.OwnerAID)) != 1 {
		writeError(w, http.StatusForbidden, "Wrong owner",
			"this instance was set up to answer to a different identity than the one claiming it")
		return
	}

	// AND THIS SAYS THEY HOLD IT. Everything above establishes what the
	// claimant knows; only this establishes what they control. It runs before
	// anything is minted or sealed, because an owner sealed in on an unchecked
	// claim cannot be replaced afterwards.
	if err := s.verifyClaimantControlsTheIdentity(req, challenge, offeredPublicKey); err != nil {
		writeError(w, http.StatusForbidden, "This claim does not prove who is making it", err.Error())
		return
	}
	// Checked here, before anything is minted, because the alternative is
	// unrecoverable: the identity is founded and persisted first, and if
	// sealing the owner then fails the box refuses every further attempt while
	// naming an owner whose key it cannot resolve. Administrable by nobody,
	// permanently, with no remedy but founding it again.
	if req.OwnerPublicKey == "" {
		writeError(w, http.StatusBadRequest, "This identity needs its owner's key",
			"owner_public_key is required: without it the owner is named but cannot sign, and nothing later can repair that")
		return
	}
	if _, err := login.DecodeVerkey(req.OwnerPublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "That owner key cannot be read",
			"owner_public_key must be a key this instance can verify signatures with: "+err.Error())
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Two ways to be adopted, and which one is right depends on whether the
	// thing being adopted can ever change hands.
	//
	// A PERSON'S AGENT is delegated. Its delegator is named inside its own
	// inception, which is exactly right for a relationship that is permanent by
	// nature: your computer does not stop being yours.
	//
	// AN IDENTITY THAT MUST BE ABLE TO CHANGE HANDS is not. A delegation cannot
	// be transferred, only destroyed, so it could never be handed on without
	// killing every credential and relationship it ever had. It incepts its own
	// root and names its owner in that event instead, so ownership changes by
	// rotation and the identity outlives the arrangement it was created under.
	var (
		identityAID string
		eventType   string
		eventBody   map[string]interface{}
		// Carried out of the branch so the event can be sent to the witnesses
		// it just named. Designating them and never telling them anything would
		// advertise corroboration that does not exist.
		foundedRaw       string
		foundedSig       string
		foundedWitnessed bool
	)

	if req.FoundAsRoot {
		if req.OwnerAID == "" {
			writeError(w, http.StatusBadRequest, "This identity needs an owner",
				"an identity founded as its own root must name who it answers to, or it answers to nobody")
			return
		}
		if s.KeriDriver == nil {
			writeError(w, http.StatusServiceUnavailable, "No KERI driver",
				"founding an identity as its own root needs the local KERI engine")
			return
		}
		// Designate witnesses, which nothing this machine founded ever had.
		//
		// Witnesses can only be named in the inception event, so this is the
		// one moment it is possible — an identity founded without them can
		// never be corroborated by anybody, for as long as it exists. That is
		// sharpest for an organisation, whose own key log is what counterparties
		// check for the rest of its life, and who therefore most needs somebody
		// else positioned to notice a second, differently-signed history of it.
		//
		// This runs ON THE MACHINE rather than on the owner's device, so it is
		// the machine that has to resolve them. It has the same shipped provider
		// registry, so it can.
		//
		// The identity is its own root, so it is classified as one: what it is
		// NOT is one of the owner's pairwise identities, whose witness list is
		// kept narrow because a distinctive set shared across two of them would
		// link them to one person. A machine has no contacts to leak.
		//
		// Bucketed on the offered key, because the identifier does not exist
		// yet — it is a digest of the event that names these witnesses.
		var witnesses []string
		var toad int
		if s.WitnessService != nil {
			witnesses, toad = s.WitnessService.WitnessesForNewIdentity(
				witness.AidKindRoot, pairingState.offered.PublicKey)
		}
		if len(witnesses) == 0 {
			// An honest answer rather than a failure. A computer being set up
			// may have no route out at all, and refusing there would make the
			// ordinary case impossible — the same split the corroboration
			// policy already makes.
			log.Printf("[pairing] founding %s with no witnesses — nothing will be able to "+
				"corroborate its history", req.OwnerAID)
		}

		result, ierr := s.KeriDriver.Incept(drivers.InceptionRequest{
			PublicKey:     pairingState.offered.PublicKey,
			NextPublicKey: pairingState.offered.NextPublicKey,
			OwnerAID:      req.OwnerAID,
			Witnesses:     witnesses,
			Toad:          toad,
		})
		if ierr != nil {
			writeError(w, http.StatusInternalServerError, "Could not found the identity", ierr.Error())
			return
		}
		identityAID, eventType, eventBody = result.AID, "icp", result.InceptionEvent
		foundedRaw, foundedWitnessed = result.RawBytesB64, len(witnesses) > 0

		// Signed here, with the key this machine holds and nobody else does.
		// A witness cannot attest to an event it cannot verify, and this is the
		// only place the private half exists.
		if raw, derr := base64.StdEncoding.DecodeString(result.RawBytesB64); derr == nil && pairingState.seed != nil {
			if sig, serr := login.SignString(string(raw), pairingState.seed); serr == nil {
				foundedSig = sig
			}
		}
	} else {
		// A computer you pair with founds its own root. It does not accept a
		// delegation, and this is the only place that could have granted one.
		//
		// A delegated inception names the delegator in a publicly resolvable
		// key log, so a computer paired that way publishes who owns it — and
		// therefore who you are, everywhere else that root appears. ADR-036
		// settled this on 2026-08-12 and the only caller has always asked to
		// found as root; what is refused here is a request no client of ours
		// makes and no client of ours should be able to make.
		writeError(w, http.StatusBadRequest,
			"This instance founds its own identity",
			"pairing by delegation is not supported: a delegated inception would name your "+
				"root identity as delegator in a publicly resolvable key log. Send "+
				"found_as_root with the owner this machine should answer to.")
		return
	}

	eventJSON, _ := json.Marshal(eventBody)
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID:            identityAID,
		SequenceNumber: 0,
		EventType:      eventType,
		EventJSON:      string(eventJSON),
		PublicKey:      pairingState.offered.PublicKey,
		RawBytesB64:    foundedRaw,
		CesrSignature:  foundedSig,
		Timestamp:      now,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not persist the inception", err.Error())
		return
	}

	// Tell the witnesses this identity just named.
	//
	// Naming them and never sending anything would be worse than naming none:
	// the event would advertise corroboration that does not exist, and anybody
	// who went looking would find nothing rather than a contradiction.
	//
	// In the background, because a slow witness must not hold up founding, and
	// an identity whose receipts have not arrived yet is correctly reported as
	// uncorroborated rather than as invalid.
	if foundedWitnessed && s.WitnessService != nil && foundedSig != "" {
		if raw, derr := base64.StdEncoding.DecodeString(foundedRaw); derr == nil {
			go func(aid string, body []byte, sig string) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if berr := s.WitnessService.BroadcastEvent(ctx, aid, body, sig); berr != nil {
					log.Printf("[pairing] %s named witnesses but they did not accept its "+
						"inception (%v) — its history is uncorroborated until they do", aid, berr)
				}
			}(identityAID, raw, foundedSig)
		}
	}
	if err := s.DataStore.SaveIdentity(store.IdentityState{
		AID:        identityAID,
		PublicKey:  pairingState.offered.PublicKey,
		Created:    now,
		EventCount: 1,
		// Where this key came from, so it can be found again. Generation 0 is
		// inception: the current key is at key-index 0 and the successor this
		// event commits to is at 1.
		DerivationIndex: pairingState.derivationIndex,
		KeyGeneration:   0,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not persist the identity", err.Error())
		return
	}

	// Seal the owner in the same act. An instance that held a delegation but no
	// owner would be adopted and unadministrable — and a later, separate call
	// to name the owner is a window somebody else could step into.
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       req.OwnerAID,
		PublicKey: req.OwnerPublicKey,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not seal the owner", err.Error())
		return
	}

	// Record who this instance seals its backups to, in the same act for the
	// same reason as the owner above.
	//
	// A failure here does not undo the adoption. The instance is legitimately
	// adopted at this point and refusing it now would leave it delegated but
	// ownerless, which is worse than adopted but not yet backing up. It is
	// logged loudly instead, because an agent that cannot back up is a real
	// problem — just not one worth throwing away a valid adoption for.
	if len(req.BackupSealPublicKeysB64) > 0 {
		if err := s.recordBackupSealKeys(req.BackupSealPublicKeysB64); err != nil {
			log.Printf("[pairing] WARNING: adopted, but the recovery keys were refused (%v) — this instance cannot back up until they are set", err)
		}
		// The same keys give the owner a way back into the encrypted volume,
		// and this is the first moment there is an owner to give it to.
		//
		// Until now the volume opened only with a key derived from this
		// software's measurement — which is what keeps the machine's operator
		// out, and also what would lose the data the next time that measurement
		// moves. It moves whenever the image is rebuilt, and the key moves with
		// the processor's firmware level, so an ordinary security patch would
		// otherwise strand everything here permanently.
		//
		// Same treatment as above and for the same reason: a failure is loud
		// but does not undo an adoption that is already valid. An instance that
		// is adopted and has no way back in is a problem to fix; an instance
		// that is delegated and ownerless is worse.
		if err := s.addVolumeRecovery(req.BackupSealPublicKeysB64); err != nil {
			log.Printf("[pairing] WARNING: adopted, but this instance's encrypted volume has no "+
				"owner recovery (%v) — its data would not survive an image or firmware update", err)
		}
	} else {
		log.Printf("[pairing] WARNING: adopted with no recovery key — this instance can only back up by being handed a seed phrase, which is what having a recovery key avoids")
	}

	// The private half has done its work; the identity is persisted and the key
	// is re-derivable from this instance's own seed.
	pairingState.seed = nil

	// Spent. A code that still works after the machine has been claimed is a
	// second owner waiting to happen.
	clearLocalPairingOffer()

	if req.FoundAsRoot {
		log.Printf("[pairing] adopted: AID %s founded as its own root, owner %s",
			identityAID, req.OwnerAID)
	}

	// The identity is named as what it is. One founded as its own root is not
	// delegated, and reporting it under "delegated_aid" would be a caller's
	// first and hardest-to-shake wrong impression of what it just created.
	// Both halves of the relationship, established here in the one exchange
	// that has already proved who both parties are.
	//
	// Nothing did this before. Adoption produced an owner and an instance that
	// had never exchanged encryption keys, so the first time either wanted to
	// reach the other privately it had to go and ask — over the network, from
	// whoever answered. The encrypted transport then refused, correctly, for
	// exactly the pair it exists to serve.
	//
	// A failure here does not undo the adoption, for the same reason as the
	// recovery keys above: the instance is legitimately adopted by this point,
	// and refusing now would leave it delegated and ownerless, which is worse
	// than adopted without a private channel yet.
	response := map[string]interface{}{
		"ok":        true,
		"owner_aid": req.OwnerAID,
	}
	if req.OwnerDID != nil && req.OwnerDID.AID != "" {
		if err := s.rememberPeerFromAdoption(req.OwnerDID, req.OwnerAgentEndpoint); err != nil {
			log.Printf("[pairing] WARNING: adopted, but this instance cannot reach its owner "+
				"privately (%v) — sealed requests between them will be refused until that is fixed", err)
		}
	}
	// This instance's own keys, so the owner can complete the other direction
	// without a fetch of its own.
	if ks, err := s.keySetFor(identityAID); err == nil {
		if did, err := ks.DID(); err == nil {
			response["agent_did"] = did
		}
	}
	response["root_aid"] = identityAID
	writeJSONResponse(w, response)
}

// refuseIfAlreadyPaired stops a second adoption. First pairing wins, and the
// window closes the moment it does — an instance that could be re-adopted is an
// instance somebody else can take.
func (s *CoreServer) refuseIfAlreadyPaired(w http.ResponseWriter) error {
	if s.DataStore == nil {
		writeError(w, http.StatusServiceUnavailable, "No store", "this instance has no data store")
		return fmt.Errorf("no store")
	}
	identity, err := s.DataStore.GetIdentity()
	if err == nil && identity != nil {
		writeError(w, http.StatusConflict, "Already paired",
			"this instance has an identity; pairing is offered only once, before one exists")
		return fmt.Errorf("already paired")
	}
	return nil
}

func writeJSONResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// resetPairingStateForTest clears the key material this process is offering.
//
// EVERYTHING handlePairingBegin sets, not just the offer. That state is
// deliberately process-wide — one agent is one machine, offering one set of
// keys until it is claimed — which makes it shared between tests, and a partial
// reset is worse than none: begin hands a cached offer straight back WITHOUT
// re-deriving the seed behind it, so the next machine is given somebody else's
// public keys and no private half to sign its own inception with. That failed
// only when the tests ran together, and looked like a witness problem.
func resetPairingStateForTest() {
	pairingState.Lock()
	defer pairingState.Unlock()
	pairingState.offered = nil
	pairingState.seed = nil
	pairingState.challenge = ""
	pairingState.derivationIndex = 0
}

// --- the controller side: adopting a box ---

// handlePairingAdopt runs the whole ceremony from the owner's agent.
//
// One call from the owner's side, because every step in between is a place a
// user could be asked to do something they cannot check. The controller fetches
// the box's key material, issues the delegation over it, anchors it in its own
// KEL, and hands the box back the result. The box's private key never leaves
// the box; the root key never leaves here.
//
// Owner-only: adopting hardware on somebody's behalf is exactly the authority
// the owner check exists to protect.
func (s *CoreServer) handlePairingAdopt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BoxURL string `json:"box_url"`
		// AdoptionCode comes from whoever provisioned the box — through the
		// deep link or QR the provisioning page produced. The box will not be
		// adopted without it.
		AdoptionCode string `json:"adoption_code"`
		// Kind says what this person now owns: a computer of their own, or an
		// organisation.
		//
		// The ceremony does not differ. The machine is not told this and does
		// not care — it founds its own root and seals in an owner either way,
		// and nothing in what it publishes says which of the two it is. What
		// differs is only what was ASKED: "be my always-on computer" against
		// "be a signer and owner of this organisation".
		//
		// So this is a label on the owner's side, kept because a list of your
		// machines and a list of the organisations you own are different
		// questions to ask of the same record.
		Kind string `json:"kind,omitempty"`
		// AllowUnattested adopts a machine that cannot prove what it is.
		//
		// Off by default, so the safe direction is the one that happens when
		// nobody thought about it. A machine with no attestation may be
		// perfectly legitimate — a laptop has no such hardware — but it may
		// equally be a sealed machine whose report was stripped by something in
		// between, and those two look identical from here. Saying which one
		// this is has to be a deliberate act.
		AllowUnattested bool `json:"allow_unattested,omitempty"`
		// AcceptedMeasurements is the software this owner will adopt, as hex,
		// for this adoption only. It adds to any standing policy in
		// AGENT_ACCEPTED_MEASUREMENTS rather than replacing it.
		//
		// This route is owner-only, so this is the owner stating their own
		// policy — not the box vouching for itself. That distinction is the
		// whole reason it is safe here and would not be on any route a box or a
		// browser can reach.
		//
		// It does not make the measurement trustworthy. It records which value
		// the owner decided to accept; where that value came from — a published
		// list, a build they ran themselves — is the question this cannot
		// answer and should not appear to.
		AcceptedMeasurements []string `json:"accepted_measurements,omitempty"`
		// OwnerAID and OwnerIndex name an identity minted BEFORE the machine was
		// asked for — see /api/machines/owner-identity. The provisioning host was
		// told this identity may claim the machine, so adoption must use the
		// same one or the machine will refuse it.
		//
		// Only the identifier travels. Where its key came from is remembered on
		// this device and looked up here, so nothing has to trust or re-check an
		// index that came back through a caller.
		OwnerAID string `json:"owner_aid,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BoxURL == "" {
		writeError(w, http.StatusBadRequest, "Missing box_url",
			"send {\"box_url\": \"http://…\", \"adoption_code\": \"…\"}")
		return
	}
	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "No KERI engine",
			"adopting a machine mints an identity for it to answer to, and that needs the local KERI engine — the key comes from this device's own seed, so it cannot be done remotely")
		return
	}
	root, err := s.DataStore.GetIdentity()
	if err != nil || root == nil {
		writeError(w, http.StatusConflict, "No identity",
			"this agent has no identity yet, and a machine has to belong to somebody")
		return
	}

	base := strings.TrimRight(req.BoxURL, "/")
	client := &http.Client{Timeout: 30 * time.Second}

	// 1. Ask the box for the key it generated for itself.
	offer, err := boxPairingBegin(client, base)
	if err != nil {
		writeError(w, http.StatusBadGateway, "The box did not offer key material", err.Error())
		return
	}

	// 2. Establish what the box is BEFORE vouching for it.
	//
	// The order is the entire point. Issuing the delegation is this owner
	// saying, in a log other parties read, that these keys are their machine.
	// If the keys were substituted on the way here, that statement is still
	// cryptographically perfect — it just names somebody else's machine, and
	// everyone who checks it afterwards will agree it is correct. Checking
	// afterwards establishes nothing, because by then the statement exists.
	accept := s.acceptableMeasurement
	if len(req.AcceptedMeasurements) > 0 {
		extra, err := parseMeasurements(req.AcceptedMeasurements)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Unreadable measurement", err.Error())
			return
		}
		accept = func(m []byte) bool {
			if s.acceptableMeasurement(m) {
				return true
			}
			for _, a := range extra {
				if bytes.Equal(a, m) {
					return true
				}
			}
			return false
		}
	}
	if err := checkOfferBeforeDelegating(offer, req.AllowUnattested, accept, s.verifySNPChain); err != nil {
		writeError(w, http.StatusForbidden, "This box was not adopted", err.Error())
		return
	}

	// 3. Mint the identity this machine will answer to.
	//
	// A PAIRWISE identity of this owner's, not their root, and the whole point
	// of the change is what the machine then publishes. A delegated machine
	// names its delegator inside its own inception event, and that event is
	// served to anybody who can reach the machine — so delegating from the root
	// published the one identifier that identifies this person everywhere, to
	// anyone who knew where their machine was. Confirmed on a live machine, not
	// inferred.
	//
	// It bought nothing. No code anywhere fetches the delegator's key event log
	// to check the anchor, and the anchor was discarded by both sides after
	// adoption. So the trade was a permanent public identifier for a
	// verification nobody performs.
	//
	// The machine founds its own root instead and names this identity as its
	// owner in a seal — the same ceremony an organisation already uses, so the
	// two converge rather than the individual gaining a second path.
	//
	// Its own pool, because every pairwise key comes from one root seed and an
	// index: a pool that borrowed another's range would hand the same key to
	// two unrelated relationships, which is the correlation a pairwise
	// identifier exists to prevent.
	// Refused rather than defaulted, because a wrong label here is silent: it
	// puts an organisation in somebody's list of computers, or the reverse, and
	// nothing later disagrees with it.
	kind := req.Kind
	switch kind {
	case "":
		kind = "individual"
	case "individual", "organisation":
	default:
		writeError(w, http.StatusBadRequest, "Unknown kind",
			"a claim says what it is founding — a computer of your own (individual) "+
				"or an organisation — and "+kind+" is neither")
		return
	}

	ownerAID, ownerIdx := req.OwnerAID, 0
	if ownerAID != "" {
		idx, known, lErr := s.DataStore.MachineOwnerIndex(ownerAID)
		if lErr != nil || !known {
			writeError(w, http.StatusBadRequest, "Unknown owner identity",
				"this device did not mint that identity, so it holds no key for it and the machine would answer to nobody")
			return
		}
		ownerIdx = idx
	}
	if ownerAID == "" {
		// Nothing was reserved in advance, so mint one now. This is the path a
		// machine obtained without a provisioning step takes.
		var mErr error
		ownerAID, _, _, ownerIdx, mErr = s.mintPairwiseIn("machines", "machine-"+shortAID(offer.PairwiseAID))
		if mErr != nil {
			writeError(w, http.StatusInternalServerError,
				"Could not mint an identity for this machine", mErr.Error())
			return
		}
	}
	ownerKey, err := s.pairwisePublicKey(ownerIdx)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"Could not read the key for this machine's owner", err.Error())
		return
	}

	// 4. Hand it back, along with who owns the box from now on: us, and the
	// public key it should seal its backups to.
	//
	// Derived here rather than by the app, because the seed this comes from is
	// already on this device and sending only the public half means the box can
	// write archives forever and open none of them. An app that computed it
	// would need the seed in a second place to do so.
	sealKeys, err := s.ownerBackupSealPublicKeys()
	if err != nil {
		// Adopting a box that cannot back up would be handing somebody a
		// machine that quietly accumulates data it can never restore.
		writeError(w, http.StatusInternalServerError, "Could not derive the recovery key",
			"the box would have been adopted with no way to back up: "+err.Error())
		return
	}

	// 5. And who we are to talk to, which is the half that was missing.
	//
	// The box needs the owner's encryption keys to open anything sealed to it
	// and to seal a reply. Without them rememberPeerFromAdoption never runs,
	// the box finishes adoption not knowing how to reach its owner, and every
	// sealed request between the two is refused for want of a peer — after an
	// adoption that reported success.
	//
	// Not fatal if it cannot be built. An agent whose DIDComm keys are not
	// ready can still be adopted, and the alternative is refusing an otherwise
	// complete adoption over the one part that can be repaired afterwards. It
	// is logged rather than passed over, because "adopted, and the two cannot
	// speak privately" is a state somebody has to be able to find.
	var ownerDID *didcomm.DID
	if ks, err := s.keySetFor(ownerAID); err == nil {
		if did, err := ks.DID(); err == nil {
			ownerDID = did
		} else {
			log.Printf("[pairing] adopting %s without owner encryption keys: %v", base, err)
		}
	} else {
		log.Printf("[pairing] adopting %s without owner encryption keys: %v", base, err)
	}

	// Say which identity will claim this machine, before claiming it.
	//
	// On a machine somebody else set up this was already done by whoever
	// provisioned it, and this call is refused as arriving second — correct,
	// and not an error here. On a machine in front of you nobody has said it
	// yet, and presenting the code off its screen is what earns the right to.
	//
	// Either way the machine knows who to expect BEFORE the claim, so there is
	// one shape rather than two.
	if err := boxExpectOwner(client, base, req.AdoptionCode, ownerAID); err != nil {
		writeError(w, http.StatusBadGateway, "This computer would not accept that identity", err.Error())
		return
	}

	// PROVE WE HOLD THE IDENTITY WE ARE CLAIMING AS. Without this the machine
	// refuses, and rightly: everything else in the claim is something a
	// stranger holding the code could also have sent.
	ownerSig, err := s.signClaim(ownerIdx, offer.Challenge, req.AdoptionCode, ownerAID, offer.PublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not sign the claim",
			"this device holds the key for "+ownerAID+" but could not sign with it: "+err.Error())
		return
	}
	ownerKEL := s.kelToPresent(ownerAID)
	if len(ownerKEL) == 0 {
		writeError(w, http.StatusInternalServerError, "No key log to present",
			"the machine checks the signature against "+ownerAID+"'s key log, and this device "+
				"has no log for it to present")
		return
	}

	result, err := boxPairingComplete(client, base, pairingCompleteRequest{
		AdoptionCode:   req.AdoptionCode,
		OwnerKEL:       ownerKEL,
		OwnerSignature: ownerSig,
		// Founded, not delegated: the machine incepts its own root and names
		// this owner in a seal. Nothing here identifies the person outside
		// this one relationship.
		FoundAsRoot: true,
		// No DelegatorAID. Nothing delegates here, the receiving side ignores
		// it on this path, and sending it anyway would tell every reader of this
		// payload that a delegation is what happens.
		OwnerAID:                ownerAID,
		OwnerPublicKey:          ownerKey,
		BackupSealPublicKeysB64: sealKeys,
		OwnerDID:                ownerDID,
		OwnerAgentEndpoint:      s.getPublicURL(r),
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "The box refused to be adopted", err.Error())
		return
	}

	// What the machine founded. Read back from its answer, because it minted
	// the identity itself — this side never computed one.
	identityAID := ""
	if v, ok := result["root_aid"].(string); ok {
		identityAID = v
	}

	// 6. The owner's half of the same exchange.
	//
	// The box returned its own keys in the response, so the private channel can
	// be completed here without fetching anything from anybody — which is the
	// point, because a fetch over a connection somebody else terminates is the
	// one step they could answer themselves. Both sides now hold keys that
	// arrived inside an exchange each had already proved themselves in.
	//
	// Reported but not fatal, for the same reason as the outbound half: an
	// adoption that has otherwise completed should not be undone by the part
	// that can be repaired without redoing it.
	if raw, ok := result["agent_did"]; ok {
		if boxDID, err := didFromResult(raw); err != nil {
			log.Printf("[pairing] adopted %s but could not read its keys, so sealed traffic to it "+
				"will be refused until they are: %v", base, err)
		} else if err := s.rememberPeerFromAdoption(boxDID, base); err != nil {
			log.Printf("[pairing] adopted %s but did not record its keys, so sealed traffic to it "+
				"will be refused until they are: %v", base, err)
		}
	} else {
		log.Printf("[pairing] adopted %s and it returned no keys of its own, so sealed traffic "+
			"between the two is not yet possible", base)
	}

	// 7. Remember it. An owner that cannot list the machines it owns has not
	//    finished adopting one — the machine knows exactly who its owner is,
	//    and until this the owner knew nothing about the machine once the
	//    response scrolled past.
	//
	//    Whether it proved itself is recorded now rather than asked for later.
	//    Asking the machine afterwards means trusting what it says about
	//    itself, which is the thing the check at adoption existed to avoid.
	agent := store.AdoptedAgent{
		AID: offer.PairwiseAID,
		// What the machine signs as. Its own root, minted inside it, rather than
		// an identity issued from here.
		SignsAsAID: identityAID,
		// What this machine signs its backups with, recorded at the one moment
		// the hardware vouched for it. Without this the owner has nothing to
		// check an archive against, and a machine-signed archive proves only
		// that its writer can sign their own work.
		BackupSigningKeyB64: offer.BackupSigningKey,
		URL:                 base,
		Kind:                kind,
		Sealed:              offer.Attestation != "",
		// Which identity of ours it answers to, and where that key comes from.
		// Without the index there is no signing to this machine again, no
		// rotation and no revocation — so losing it is losing the machine.
		OwnerAID:   ownerAID,
		OwnerIndex: ownerIdx,
	}
	if agent.AID == "" {
		// A machine that published no identifier of its own is still adopted;
		// it is keyed by the identity it founded, so it is listed rather than
		// lost.
		agent.AID = identityAID
	}
	if m := measurementOf(offer.Attestation); m != "" {
		agent.Measurement = m
	}
	if err := s.DataStore.SaveAdoptedAgent(agent); err != nil {
		// Not fatal: the delegation is issued and the box is adopted, and
		// undoing that because a local list could not be written would be the
		// worse trade. Said out loud because the visible symptom is a machine
		// that works and does not appear in its owner's list.
		log.Printf("[pairing] adopted %s but could not record it, so it will not be listed: %v",
			base, err)
	}

	log.Printf("[pairing] adopted box at %s: it founded %s, owned by %s", base, identityAID, ownerAID)
	writeJSONResponse(w, map[string]interface{}{
		"ok": true, "box_url": base,
		"root_aid": identityAID, "owner_aid": ownerAID,
		"box_pairwise_aid": offer.PairwiseAID, "box_response": result,
	})
}

// boxExpectOwner tells a machine which identity may claim it.
//
// A 409 means it was already told — by whoever provisioned it — and that is the
// normal case for a machine somebody else set up, not a failure. Anything else
// is: a wrong code means this is not the machine whose screen was read.
func boxExpectOwner(client *http.Client, base, code, ownerAID string) error {
	body, _ := json.Marshal(map[string]string{"claim_token": code, "owner_aid": ownerAID})
	resp, err := client.Post(base+"/api/provisioning/expect", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}

func boxPairingBegin(client *http.Client, base string) (*pairingBeginResponse, error) {
	resp, err := client.Post(base+"/api/pairing/begin", "application/json", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var offer pairingBeginResponse
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return nil, err
	}
	if offer.PublicKey == "" {
		return nil, fmt.Errorf("the box offered no key")
	}
	return &offer, nil
}

func boxPairingComplete(client *http.Client, base string, body pairingCompleteRequest) (map[string]interface{}, error) {
	raw, _ := json.Marshal(body)
	resp, err := client.Post(base+"/api/pairing/complete", "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, nil
}

func shortAID(aid string) string {
	if len(aid) > 8 {
		return aid[:8]
	}
	return aid
}

// didFromResult reads a DID out of a decoded JSON response.
//
// It arrives as a map rather than a typed value because the response is
// whatever the box sent, so it round-trips through JSON to be read as the
// thing it claims to be. A box that sent something else fails here, by name,
// rather than at the first attempt to encrypt to it.
func didFromResult(raw interface{}) (*didcomm.DID, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var did didcomm.DID
	if err := json.Unmarshal(encoded, &did); err != nil {
		return nil, fmt.Errorf("this is not a set of keys: %w", err)
	}
	if did.AID == "" {
		return nil, fmt.Errorf("the keys name no identity")
	}
	return &did, nil
}

// measurementOf reads what a box was running out of the report it offered.
//
// Best effort by design: a box adopted with allow_unattested has no report and
// no measurement, which is a real state rather than a failure. The caller
// records what it has.
func measurementOf(attestationB64 string) string {
	if attestationB64 == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(attestationB64)
	if err != nil {
		return ""
	}
	report, err := secureenclave.ParseSNPReport(raw)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(report.Measurement)
}

// pairwisePublicKey is the verification key for one of this owner's pairwise
// identities, re-derived from the root seed and the index it was minted at.
//
// Re-derived rather than stored. The seed is already on this device and the
// derivation is deterministic, so keeping a copy would add a second place for
// the same fact to live and a second place for it to be wrong. The index is
// what is written down, and it is written down precisely so this works.
// signClaim signs the exchange as the pairwise identity that will own the
// machine.
//
// Signed with the key that identity's own log puts in force, because that is
// the key the machine will check against. Signing with anything else — the
// root, a convenient device key — would produce a signature that verifies here
// and is refused there.
func (s *CoreServer) signClaim(ownerIdx int, challenge, token, ownerAID, offeredPublicKey string) (string, error) {
	seed, err := s.pairwiseSigningSeed(ownerIdx)
	if err != nil {
		return "", err
	}
	return login.SignString(string(claimSigningInput(challenge, token, ownerAID, offeredPublicKey)), seed)
}

// pairwiseSigningSeed re-derives the private half of a pairwise identity.
//
// Held nowhere: the seed is derived when it is needed and goes out of scope
// with the request. The index is the only thing written down, which is why
// losing it means never being able to sign to that machine again.
func (s *CoreServer) pairwiseSigningSeed(idx int) ([]byte, error) {
	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		return nil, err
	}
	return backup.DerivePairwiseSeed(rootSeed, idx, 0)
}

func (s *CoreServer) pairwisePublicKey(idx int) (string, error) {
	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		return "", err
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if err != nil {
		return "", fmt.Errorf("derive the key at index %d: %w", idx, err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return iacrypto.VerkeyQB64(pub), nil
}
