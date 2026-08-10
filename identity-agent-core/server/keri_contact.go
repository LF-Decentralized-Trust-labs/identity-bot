package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"identity-agent-core/iacrypto"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// EnsureKeriContact is the FOUNDATIONAL LAYER under every transaction: when two Identity
// Agents interact for the first time they exchange OOBIs to establish each other's identity
// via KERI, and that exchange yields a contact. This resolves a counterparty's OOBI, validates
// its KEL, and ensures a contact record exists for it.
//
// On first contact it creates a baseline contact: ContactSource="keri",
// ContactCategory="transactional" (the floor tier — every counterparty you transact with is at
// least a transactional/KERI contact), with an HD-derived per-counterparty pairwise relationship
// AID. If a contact for that AID already exists it is returned as-is — the tier is NEVER
// downgraded (an escalated trusted/professional/general contact stays escalated). The KERI
// relationship data is the always-present base; a transaction's `t`-handler runs on top of it
// and may escalate the tier.
//
// Persistence: contacts are kept indefinitely for now (no expiry). Per-action TTLs are future
// work and will ride on the Ask's `t`, letting a repeat interaction skip a fresh OOBI exchange.
func (s *CoreServer) EnsureKeriContact(oobiURL string) (*store.ContactRecord, bool, error) {
	if oobiURL == "" {
		return nil, false, fmt.Errorf("oobi_url is required")
	}
	if identity, _ := s.DataStore.GetIdentity(); identity != nil && strings.Contains(oobiURL, identity.AID) {
		return nil, false, fmt.Errorf("oobi points to our own identity")
	}

	// Resolve the OOBI (KERI identity establishment).
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(oobiURL)
	if err != nil {
		return nil, false, fmt.Errorf("could not reach %s: %w", oobiURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("oobi resolution failed (%d): %s", resp.StatusCode, string(body))
	}
	var oobiData struct {
		AID       string                   `json:"aid"`
		PublicKey string                   `json:"public_key"`
		Alias     string                   `json:"alias"`
		KEL       []map[string]interface{} `json:"kel"`
		JCard     *store.JCard             `json:"jcard,omitempty"`
		Photo     string                   `json:"photo,omitempty"`
		// The backend this contact runs decides whether it can witness at all,
		// and the witness key is what an event names to designate it. Recorded
		// here because neither can be worked out later.
		BackendType string `json:"backend_type"`
		WitnessKey  string `json:"witness_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oobiData); err != nil {
		return nil, false, fmt.Errorf("invalid oobi response: %w", err)
	}
	if s.WitnessService != nil {
		s.WitnessService.RecordContactCapability(oobiData.AID, oobiData.BackendType, oobiData.WitnessKey)
	}
	if oobiData.AID == "" {
		return nil, false, fmt.Errorf("oobi response did not contain an AID")
	}

	// Idempotent: if we already know this counterparty, return it without downgrading its tier.
	if existing, err := s.DataStore.GetContact(oobiData.AID); err == nil && existing != nil && existing.AID != "" {
		return existing, false, nil
	}

	// Check the key log, from the bytes it was published as where they came with
	// it. Parsed events cannot show that the inception derives this identifier
	// or that anything was signed, and a forged log satisfies what is left.
	kelVerified := false
	currentPublicKey := oobiData.PublicKey
	if s.KeriDriver != nil && len(oobiData.KEL) > 0 {
		validate := func() (*drivers.DriverValidateKELResponse, error) {
			if in, ok := drivers.ValidateKELInputFromRecords(oobiData.AID, oobiData.KEL); ok {
				return s.KeriDriver.ValidateKELBytes(in)
			}
			return s.KeriDriver.ValidateKEL(oobiData.AID, oobiData.KEL)
		}
		if valResult, verr := validate(); verr != nil {
			log.Printf("[identity-agent-core] EnsureKeriContact: KEL validation error for %s: %v", oobiData.AID, verr)
		} else {
			kelVerified = valResult.KelVerified
			if valResult.CurrentPublicKey != "" {
				currentPublicKey = valResult.CurrentPublicKey
			}
			_ = s.DataStore.SaveContactKEL(store.ContactKELRecord{
				AID:              oobiData.AID,
				KEL:              oobiData.KEL,
				KelVerified:      kelVerified,
				CurrentPublicKey: currentPublicKey,
				EventsValidated:  len(oobiData.KEL),
				ValidationErrors: valResult.ValidationErrors,
				ValidatedAt:      time.Now().UTC().Format(time.RFC3339),
			})
		}
	}

	alias := oobiData.Alias
	if alias == "" {
		if len(oobiData.AID) >= 12 {
			alias = oobiData.AID[:12] + "..."
		} else {
			alias = oobiData.AID
		}
	}
	jcard := oobiData.JCard
	if jcard == nil {
		jcard = &store.JCard{FullName: alias, XKeriAID: oobiData.AID, XKeriOOBI: oobiURL, XKeriRole: "transactional"}
	}
	// Three states, not two. "unchecked" existed all along and was reported as
	// "verified": on a phone there is no engine to check with, and an address
	// that publishes no history gives nothing to check — neither of which is
	// the same as checking and finding it sound. Saying so was the software
	// asserting a conclusion it had never reached, on the screen where somebody
	// decides whether to trust a stranger.
	status := "unchecked"
	switch {
	case kelVerified:
		status = "verified"
	case s.KeriDriver != nil && len(oobiData.KEL) > 0:
		status = "unverified"
	}

	contact := store.ContactRecord{
		AID:       oobiData.AID,
		Alias:     alias,
		PublicKey: currentPublicKey,
		OobiURL:   oobiURL,
		// Only what was actually established. This used to be true whenever
		// there was no engine to check with, which made "no answer" and "yes"
		// the same value.
		Verified:        kelVerified,
		DiscoveredAt:    time.Now().UTC().Format(time.RFC3339),
		Status:          status,
		ContactSource:   "keri",
		ContactCategory: "transactional", // foundational floor tier; t-handlers may escalate
		IsWitness:       false,
		JCard:           jcard,
		Photo:           oobiData.Photo,
	}

	// Mint our per-counterparty pairwise relationship AID via HD derivation (SLIP-0010 from the
	// root keystore seed) + a real driver inception. Stable monotonic index, persisted; the seed
	// is re-derived on demand from root + index (never stored per-contact).
	if s.KeriDriver != nil {
		rootSeed, rerr := secureenclave.LoadRootSeed(s.DataDir)
		if rerr != nil {
			return nil, false, fmt.Errorf("root keystore seed required for HD pairwise derivation: %w", rerr)
		}
		idx, aerr := s.DataStore.AllocateNextRelationshipIndex("contacts")
		if aerr != nil {
			return nil, false, fmt.Errorf("allocate relationship index: %w", aerr)
		}
		contact.RelationshipIndex = idx
		pwSeed, derr := backup.DerivePairwiseSeed(rootSeed, idx, 0)
		if derr != nil {
			return nil, false, fmt.Errorf("HD-derive pairwise seed: %w", derr)
		}
		nextSeed, _ := backup.DerivePairwiseSeed(rootSeed, idx, 1)
		pub := ed25519.NewKeyFromSeed(pwSeed).Public().(ed25519.PublicKey)
		nextPub := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)
		if icp, ierr := s.KeriDriver.CreateInceptionNamed(
			iacrypto.VerkeyQB64(pub),
			iacrypto.VerkeyQB64(nextPub),
			"rel-"+oobiData.AID,
		); ierr == nil && icp.AID != "" {
			contact.RelationshipAID = icp.AID
			log.Printf("[identity-agent-core] EnsureKeriContact: HD-derived (index %d) pairwise P-AID %s for %s", idx, icp.AID, oobiData.AID)
		} else if ierr != nil {
			return nil, false, fmt.Errorf("mint relationship inception: %w", ierr)
		}
	}

	if err := s.DataStore.SaveContact(contact); err != nil {
		return nil, false, fmt.Errorf("save contact: %w", err)
	}
	if contact.Verified {
		s.notifyBackupEvent(backup.EventContactVerified)
	}
	log.Printf("[identity-agent-core] EnsureKeriContact: established transactional contact %s (AID %s, kel_verified=%v)", alias, oobiData.AID, kelVerified)
	return &contact, true, nil
}
