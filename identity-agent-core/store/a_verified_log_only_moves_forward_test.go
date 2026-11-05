package store

import (
	"errors"
	"testing"
)

func logOf(n int, verified bool) ContactKELRecord {
	kel := make([]map[string]interface{}, n)
	for i := range kel {
		kel[i] = map[string]interface{}{"n": i}
	}
	return ContactKELRecord{AID: "Eowner", KEL: kel, KelVerified: verified, EventsValidated: n,
		CurrentPublicKey: "key" + string(rune('0'+n))}
}

// A replayed K1..K2 log must not replace the K1..K3 log already held, in either
// store; a longer or equal log still replaces.
func TestAVerifiedLogIsNotReplacedByOneThatEndsEarlier(t *testing.T) {
	file, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sqlite, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]interface {
		SaveContactKEL(ContactKELRecord) error
		GetContactKEL(string) (*ContactKELRecord, error)
	}{"file": file, "sqlite": sqlite} {
		t.Run(name, func(t *testing.T) {
			if err := st.SaveContactKEL(logOf(3, true)); err != nil {
				t.Fatal(err)
			}
			err := st.SaveContactKEL(logOf(2, true))
			if !errors.Is(err, ErrLogEndsEarlier) {
				t.Fatalf("a shorter log replaced the held one, err=%v", err)
			}
			if err := st.SaveContactKEL(logOf(1, false)); !errors.Is(err, ErrLogEndsEarlier) {
				t.Fatalf("an unverified shorter record replaced the held log, err=%v", err)
			}
			got, _ := st.GetContactKEL("Eowner")
			if got == nil || got.CurrentPublicKey != "key3" {
				t.Fatalf("held log changed: %+v", got)
			}
			if err := st.SaveContactKEL(logOf(4, true)); err != nil {
				t.Fatalf("a longer log was refused: %v", err)
			}
			if err := st.SaveContactKEL(logOf(4, true)); err != nil {
				t.Fatalf("the same log again was refused: %v", err)
			}
		})
	}
}
