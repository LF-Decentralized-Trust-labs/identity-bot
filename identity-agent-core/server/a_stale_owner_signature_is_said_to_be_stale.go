package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// An owner's signature names the establishment event it was made under
// (ADR-061 section 9).
//
// An owner whose key rotated, and whose app has not yet learned it, signs with
// a key this Identity Agent no longer takes as the owner's. Refused as an
// ordinary bad signature, the app cannot tell that from a forgery, or from a
// commit whose answer it lost; told the key state it named is stale, it reads
// the key state again rather than guessing. The answer says nothing beyond
// what the request claimed.

// headerOwnerKeyState names the owner's establishment event a request was
// signed under: its sequence number, as KERI writes it, a dot, and its digest.
const headerOwnerKeyState = "X-IA-Owner-Key-State"

// ownerKeyStateIsStale reports whether r is owner-signed under an
// establishment event that is not the owner's current one here.
func (s *CoreServer) ownerKeyStateIsStale(r *http.Request) bool {
	named := strings.TrimSpace(r.Header.Get(headerOwnerKeyState))
	if named == "" || r.Header.Get(headerOwnerSig) == "" {
		return false
	}
	authority, err := s.ownerAuthority()
	if err != nil || authority == nil || authority.AID == "" {
		return false
	}
	current, err := s.ownerEstablishment(authority.AID)
	if err != nil {
		return false
	}
	return named != current
}

// ownerEstablishment is the owner's last establishment event as this Identity
// Agent knows it, from the owner's verified key log, or the owner's founding
// where it holds no log of the owner's (the key sealed at pairing).
func (s *CoreServer) ownerEstablishment(owner string) (string, error) {
	if s.DataStore == nil {
		return "0." + owner, nil
	}
	record, err := s.DataStore.GetContactKEL(owner)
	if err != nil || record == nil || !record.KelVerified || len(record.KEL) == 0 {
		return "0." + owner, nil
	}
	place := ""
	for _, ev := range record.KEL {
		switch t, _ := ev["t"].(string); t {
		case "icp", "rot", "dip", "drt":
			s, _ := ev["s"].(string)
			d, _ := ev["d"].(string)
			place = s + "." + d
		}
	}
	if place == "" {
		return "", fmt.Errorf("the owner's log names no establishment event")
	}
	return place, nil
}

// writeStaleKeyState answers a request signed under an owner's earlier key
// state.
func writeStaleKeyState(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "stale_key_state",
		"detail": "this request was signed under a key state of the owner's that is not the one in force here; read the key state again"})
}
