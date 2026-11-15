package login

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// An installed app's grant ended, told to the app's back end (ADR-072 section 6,
// Amendment 9).
//
// The owner's Identity Agent refuses an ended grant at each use, but a back end
// that holds a session for the key keeps it until its next call to the core. So
// the core tells the back end: it posts a notice to the address the sign-in was
// made for (the audience), at GrantEndedPath, signed with the app's own asset key.
// The back end already knows that key (the app's identifier names it), so no new
// trust is needed. This file fixes the wire shape, the statement the key signs and
// the check; the test vectors in ../login-web/test-vectors/grant-ended.json are
// run by the core's own signer as well, so the two cannot drift.
//
// A notice ends a grant and nothing else, so a replay does no harm beyond what the
// window allows: a notice older than GrantEndedWindow is refused, which stops an
// old one ending a grant the same key was later given again.

// GrantEndedPath is where a back end takes the notice.
const GrantEndedPath = "/identity-agent/grant-ended"

// GrantEndedWindow is how far a notice's time may be from the back end's clock.
const GrantEndedWindow = 5 * time.Minute

const grantEndedBodyLimit = 4096

// GrantEnded is the notice. Signature is unpadded base64url of the Ed25519
// signature over GrantEndedStatement.
type GrantEnded struct {
	V         int    `json:"v"`
	Asset     string `json:"asset"`     // the app's identifier (its asset's pairwise AID)
	Key       string `json:"key"`       // thumbprint of the front end's key
	Person    string `json:"person"`    // the person the grant was for, as the app knows them
	Issued    string `json:"issued"`    // YYYY-MM-DDTHH:MM:SSZ, UTC
	Signature string `json:"signature"` // see above
}

// GrantEndedStatement is what the asset's key signs.
func GrantEndedStatement(asset, key, person, issued string) []byte {
	return []byte("identity-agent grant-ended v1\n" + asset + "\n" + key + "\n" + person + "\n" + issued)
}

// VerifyGrantEnded reads a notice and checks it speaks for asset: the asset it
// names is the app's own, the signature is by siteKey, and it was issued within
// GrantEndedWindow of now.
func VerifyGrantEnded(body []byte, asset string, siteKey ed25519.PublicKey, now time.Time) (GrantEnded, error) {
	var g GrantEnded
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil || dec.More() {
		return GrantEnded{}, errors.New("login: a grant-ended notice is not the notice's shape")
	}
	if g.V != 1 || g.Key == "" || g.Person == "" || g.Asset == "" || g.Issued == "" {
		return GrantEnded{}, errors.New("login: a grant-ended notice names its version, asset, key, person and time")
	}
	if g.Asset != asset {
		return GrantEnded{}, errors.New("login: the notice is for another app")
	}
	if len(siteKey) != ed25519.PublicKeySize {
		return GrantEnded{}, errors.New("login: no key to check the notice with")
	}
	sig, err := base64.RawURLEncoding.DecodeString(g.Signature)
	if err != nil || !ed25519.Verify(siteKey, GrantEndedStatement(g.Asset, g.Key, g.Person, g.Issued), sig) {
		return GrantEnded{}, errors.New("login: the notice's signature does not check")
	}
	at, err := time.Parse("2006-01-02T15:04:05Z", g.Issued)
	if err != nil {
		return GrantEnded{}, errors.New("login: the notice's time is not YYYY-MM-DDTHH:MM:SSZ")
	}
	if d := now.Sub(at); d > GrantEndedWindow || d < -GrantEndedWindow {
		return GrantEnded{}, fmt.Errorf("login: the notice is dated %s, outside %s of now", g.Issued, GrantEndedWindow)
	}
	return g, nil
}

// GrantEndedHandler serves GrantEndedPath for a back end. end is told each
// verified notice with begunBy, the notice's time: it ends every session and
// app-key grant held for that person at that key that was begun at or before
// begunBy, and never one begun after it (a repeated or late notice must not end
// the session of a person who signed in again), answering how many it ended; it
// must be safe to call twice for the same notice. siteKey gives the app's current
// asset key. A notice that does not check is answered 403 and ends nothing.
func GrantEndedHandler(asset string, siteKey func(context.Context) (ed25519.PublicKey, error),
	end func(ctx context.Context, g GrantEnded, begunBy time.Time) (int, error), now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, grantEndedBodyLimit+1))
		if err != nil || len(body) > grantEndedBodyLimit {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		key, err := siteKey(r.Context())
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		g, err := VerifyGrantEnded(body, asset, key, now())
		if err != nil {
			http.Error(w, "not authorized", http.StatusForbidden)
			return
		}
		begunBy, _ := time.Parse("2006-01-02T15:04:05Z", g.Issued) // VerifyGrantEnded has read it
		n, err := end(r.Context(), g, begunBy)
		if err != nil {
			http.Error(w, "could not end it", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ended":%d}`, n)
	})
}
