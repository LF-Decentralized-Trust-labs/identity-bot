package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"identity-agent-core/login"
)

// An owner's signature names the establishment event it was made under
// (ADR-061 section 9).
//
// An owner whose key rotated, and whose app has not yet learned it, signs with
// a key this Identity Agent no longer takes as the owner's. Refused as an
// ordinary bad signature, the app cannot tell that from a forgery, or from a
// commit whose answer it lost; told the key state it named is stale, it reads
// the key state again rather than guessing. The answer says nothing beyond
// what the request proved: only a request the owner's earlier key signed is
// told so.

// headerOwnerKeyState names the owner's establishment event a request was
// signed under: its sequence number, as KERI writes it, a dot, and its digest.
const headerOwnerKeyState = "X-IA-Owner-Key-State"

// ownerKeyStateIsStale reports whether r is owner-signed under an earlier key
// state of the owner's: the header names an establishment event in the
// owner's verified log that is not the last one, and the request's signature
// verifies under the key that event named. Only then is the request told it is
// stale; anything else is refused as an unproved request is, so a caller who
// cannot sign as the owner learns nothing about the owner's key state.
func (s *CoreServer) ownerKeyStateIsStale(r *http.Request) bool {
	named := strings.TrimSpace(r.Header.Get(headerOwnerKeyState))
	sig := r.Header.Get(headerOwnerSig)
	stamp := r.Header.Get(headerOwnerTimestamp)
	if named == "" || sig == "" || stamp == "" || s.DataStore == nil {
		return false
	}
	authority, err := s.ownerAuthority()
	if err != nil || authority == nil || authority.AID == "" {
		return false
	}
	record, err := s.DataStore.GetContactKEL(authority.AID)
	if err != nil || record == nil || !record.KelVerified {
		return false
	}
	states := establishmentsOf(record.KEL)
	if len(states) < 2 || named == states[len(states)-1].place {
		return false
	}
	key := ""
	for _, st := range states[:len(states)-1] {
		if st.place == named {
			key = st.key
		}
	}
	if key == "" {
		return false
	}
	pub, err := login.DecodeVerkey(key)
	if err != nil {
		return false
	}
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	target, err := s.theIdentityAgentAnOwnerNames(r)
	if err != nil {
		return false
	}
	ok, err := login.VerifyString(canonicalOwnerRequest(target, r.Method, r.URL.Path, stamp, body), sig, pub)
	return err == nil && ok
}

type keyStatePlace struct {
	place string // sequence number, a dot, digest
	key   string // the first key it names
}

// establishmentsOf are the establishment events of a parsed key log, in order.
func establishmentsOf(kel []map[string]interface{}) []keyStatePlace {
	var out []keyStatePlace
	for _, ev := range kel {
		switch t, _ := ev["t"].(string); t {
		case "icp", "rot", "dip", "drt":
			sn, _ := ev["s"].(string)
			d, _ := ev["d"].(string)
			k, _ := ev["k"].([]interface{})
			first := ""
			if len(k) > 0 {
				first, _ = k[0].(string)
			}
			out = append(out, keyStatePlace{place: sn + "." + d, key: first})
		}
	}
	return out
}

// writeStaleKeyState answers a request signed under an owner's earlier key
// state.
func writeStaleKeyState(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "stale_key_state",
		"detail": "this request was signed under a key state of the owner's that is not the one in force here; read the key state again"})
}
