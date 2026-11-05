package store

import (
	"path/filepath"
	"testing"
)

// Where an identity's keys live is a value somebody wrote down. It survives a
// save and a read, and anything but the two known values is refused.
func TestWhereAnIdentitysKeysLiveIsKeptAndCheckedOnBothStores(t *testing.T) {
	sq := eventStore(t)
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]interface {
		SaveIdentity(IdentityState) error
		GetIdentity() (*IdentityState, error)
	}{"sqlite": sq, "file": fs} {
		if err := st.SaveIdentity(IdentityState{AID: "EA", PublicKey: "Dk", Created: "n", KeysLive: KeysLocal}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := st.GetIdentity()
		if err != nil || got == nil || got.KeysLive != KeysLocal {
			t.Fatalf("%s: keys_live not kept: %+v %v", name, got, err)
		}
		if err := st.SaveIdentity(IdentityState{AID: "EA", PublicKey: "Dk", KeysLive: "cloud"}); err == nil {
			t.Fatalf("%s: an unknown place for the keys was accepted", name)
		}
	}
}

// An identity that existed before the column did is recorded as local by the
// migration, once, rather than read as "unknown" for ever.
func TestAnIdentityFromBeforeTheColumnIsRecordedLocal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE identity SET keys_live = ''`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(IdentityState{AID: "EA", PublicKey: "Dk", Created: "n", KeysLive: KeysLocal}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE identity DROP COLUMN keys_live`); err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`DELETE FROM identity_schema_migrations WHERE version = 47`)
	s.Close()
	s2, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, _ := s2.GetIdentity()
	if got == nil || got.KeysLive != KeysLocal {
		t.Fatalf("migration did not record local: %+v", got)
	}
}
