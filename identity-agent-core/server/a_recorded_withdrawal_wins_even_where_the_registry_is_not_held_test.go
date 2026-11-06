package server

import (
	"errors"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// This agent's own record of a revocation or withdrawal is read before the
// registry is, so a credential recorded here as revoked or withdrawing whose
// registry this agent does not hold is still refused, and a record that cannot
// be read lets no log decide.

// storeWith is a store whose registry reads and credential reads can be made to
// return what a test needs.
type storeWith struct {
	store.Store
	noRegistry bool
	registryErr,
	credentialErr error
}

func (s storeWith) GetRegistry(said string) (*store.CredentialRegistry, error) {
	if s.registryErr != nil {
		return nil, s.registryErr
	}
	if s.noRegistry {
		return nil, nil
	}
	return s.Store.GetRegistry(said)
}

func (s storeWith) GetCredential(said string) (*store.CredentialRecord, error) {
	if s.credentialErr != nil {
		return nil, s.credentialErr
	}
	return s.Store.GetCredential(said)
}

func TestARecordedWithdrawalWinsWhereThisAgentHoldsNoRegistry(t *testing.T) {
	for _, status := range []string{"revoked", credentialStatusWithdrawing} {
		for name, held := range map[string]storeWith{
			"registry not held":       {noRegistry: true},
			"registry cannot be read": {registryErr: errors.New("disk")},
		} {
			s, said, acdc, _ := issuedThenRevoked(t)
			if err := s.DataStore.UpdateCredentialStatus(said, status); err != nil {
				t.Fatal(err)
			}
			held.Store = s.DataStore
			s.DataStore = held
			cred, err := readCredentialHere(acdc)
			if err != nil {
				t.Fatal(err)
			}
			got := s.localRevocationState(cred)
			if got.status != revocationRevoked || !strings.Contains(got.reason, status) {
				t.Errorf("%s, recorded %s: read %+v", name, status, got)
			}
			if v := verifyHere(t, s, acdc); v.Verified || v.Checks["not_revoked"] != false {
				t.Errorf("%s, recorded %s: verify read %+v", name, status, v)
			}
		}
	}
}

func TestARecordThatCannotBeReadLetsNoLogDecide(t *testing.T) {
	s, _, acdc, _ := issuedThenRevoked(t)
	s.DataStore = storeWith{Store: s.DataStore, credentialErr: errors.New("database is locked")}
	cred, err := readCredentialHere(acdc)
	if err != nil {
		t.Fatal(err)
	}
	got := s.localRevocationState(cred)
	if !strings.HasPrefix(got.status, revocationNotCheckedPrefix) || len(got.log) != 0 {
		t.Fatalf("a database error let a log decide: %+v", got)
	}
	if v := verifyHere(t, s, acdc); v.Verified || v.Checks["not_revoked"] == true {
		t.Fatalf("a database error was read as not revoked: %+v", v)
	}
}
