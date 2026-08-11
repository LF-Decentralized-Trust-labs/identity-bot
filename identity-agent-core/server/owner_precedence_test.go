package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// Which answer wins when the log and the disk disagree.
//
// The anchor was introduced because a file naming the owner "can be replaced
// silently" and a key event log cannot. Then the file was left in front of it:
// ownerAuthority read owner_authority.json first and returned, so an identity
// that named its owner in its own inception could still be overridden by
// anybody able to write next to the database.
//
// That made the anchor decoration. A second signer could replace the first by
// re-sealing, which is the precise failure the anchor exists to remove — and it
// was reachable through a route that still calls SealOwnerAuthority.

// The property, stated once: the log beats the disk.
func TestTheAnchoredOwnerBeatsASealedFile(t *testing.T) {
	s := serverWithIdentity(t, "EORG")

	// An identity whose inception names its real owner.
	keri := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": "EORG",
			"kel": []map[string]interface{}{{
				"t": "icp", "i": "EORG",
				"a": []interface{}{map[string]interface{}{"i": "ETRUE-OWNER", "s": "0", "d": "ETRUE-OWNER"}},
			}},
		})
	}))
	defer keri.Close()
	driver := drivers.NewKeriDriver()
	driver.BaseURL = keri.URL
	s.KeriDriver = driver

	// The real owner's key is on file, as a counterparty's would be.
	if err := s.DataStore.SaveContact(store.ContactRecord{
		AID: "ETRUE-OWNER", Status: "accepted",
		PublicKey: "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
	}); err != nil {
		t.Fatal(err)
	}

	// And somebody writes themselves in as the owner, the way a second signer
	// redeeming an invite would.
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "EIMPOSTER",
		PublicKey: "DEC4FUUdUvgDKk07vt2cJUOaSGVLBGnbeGGjHvJTMUgo",
	}); err != nil {
		t.Fatal(err)
	}

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("no authority could be resolved: %v", err)
	}
	if authority.AID == "EIMPOSTER" {
		t.Fatal("a file overrode the owner named in the identity's own inception event")
	}
	if authority.AID != "ETRUE-OWNER" {
		t.Fatalf("authority is %q, not the anchored owner", authority.AID)
	}
}

// The case every identity founded through pairing is actually in, and the one
// that was missing.
//
// publicKeyOf resolves an owner out of contacts, and at the moment an identity
// is founded its owner is not one — nothing in the pairing flow adds them. So an
// identity came up naming an owner whose key could not be resolved and refused
// every owner-signed request from then on, administrable by nobody, while that
// owner's public key sat in owner_authority.json where pairing had written it
// seconds earlier.
//
// It survived every test above because each of them puts the owner in contacts
// first, which is the one thing founding does not do.
func TestTheOwnerNamedAtFoundingCanActWithoutBeingAContact(t *testing.T) {
	s := serverWithIdentity(t, "ETHING")

	keri := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": "ETHING",
			"kel": []map[string]interface{}{{
				"t": "icp", "i": "ETHING",
				"a": []interface{}{map[string]interface{}{"i": "EFOUNDER", "s": "0", "d": "EFOUNDER"}},
			}},
		})
	}))
	defer keri.Close()
	driver := drivers.NewKeriDriver()
	driver.BaseURL = keri.URL
	s.KeriDriver = driver

	// Exactly what pairing does: the owner's key, sealed, and no contact.
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "EFOUNDER",
		PublicKey: "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
	}); err != nil {
		t.Fatal(err)
	}

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("the owner named at founding could not act on the identity they founded: %v", err)
	}
	if authority.AID != "EFOUNDER" {
		t.Fatalf("authority is %q, not the owner the inception named", authority.AID)
	}
}

// The file may supply the KEY for the owner the log names. It may not supply a
// different OWNER — that is the hole the ordering was introduced to close, and
// falling back must not quietly reopen it.
func TestASealedRecordForADifferentOwnerIsStillRefused(t *testing.T) {
	s := serverWithIdentity(t, "ETHING")

	keri := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": "ETHING",
			"kel": []map[string]interface{}{{
				"t": "icp", "i": "ETHING",
				"a": []interface{}{map[string]interface{}{"i": "EFOUNDER", "s": "0", "d": "EFOUNDER"}},
			}},
		})
	}))
	defer keri.Close()
	driver := drivers.NewKeriDriver()
	driver.BaseURL = keri.URL
	s.KeriDriver = driver

	// Somebody re-seals under their own AID, the way a second signer would.
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "EIMPOSTER",
		PublicKey: "DEC4FUUdUvgDKk07vt2cJUOaSGVLBGnbeGGjHvJTMUgo",
	}); err != nil {
		t.Fatal(err)
	}

	authority, err := s.ownerAuthority()
	if err == nil {
		t.Fatalf("a sealed record for a different identity became the authority: %q", authority.AID)
	}
}

// An identity with no anchor still resolves through the sealed record. This is
// the case the file was written for — hardware the owner does not hold, sealed
// before the box ever reached the network — and removing it would lock an owner
// out of their own box.
func TestAnUnanchoredIdentityStillUsesTheSealedRecord(t *testing.T) {
	s := serverWithIdentity(t, "EPERSONAL")
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "EOWNER",
		PublicKey: "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
	}); err != nil {
		t.Fatal(err)
	}

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("a sealed owner could not act on their own box: %v", err)
	}
	if authority.AID != "EOWNER" {
		t.Errorf("authority is %q, not the sealed owner", authority.AID)
	}
}

// A box with no identity yet is exactly the state provisioning seals it in.
func TestABoxWithNoIdentityUsesTheSealedRecord(t *testing.T) {
	s := newAuthTestServer(t)
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "EOWNER",
		PublicKey: "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
	}); err != nil {
		t.Fatal(err)
	}

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("a provisioned box could not resolve its sealed owner: %v", err)
	}
	if authority.AID != "EOWNER" {
		t.Errorf("authority is %q", authority.AID)
	}
}

// With neither an anchor nor a sealed record, an agent on its owner's own
// machine is its own authority — so signing works there with no setup.
func TestAnAgentOnItsOwnersMachineIsItsOwnAuthority(t *testing.T) {
	s := serverWithIdentity(t, "EMINE")

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("an ordinary agent could not resolve an authority: %v", err)
	}
	if authority.AID != "EMINE" {
		t.Errorf("authority is %q, not the agent's own identity", authority.AID)
	}
}
