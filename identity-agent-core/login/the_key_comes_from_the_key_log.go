package login

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
)

// The key a sign-in is checked against comes from the identity's key log, and
// from nothing else.
//
// An identifier here is a digest of its own inception event, so the one thing
// that ties a key to an identifier is a key log whose inception derives it.
// A did.json document is not that: it is a key somebody chose to serve at an
// address, and the address was named by the very assertion being checked, so
// whoever wrote the assertion also chose where its key would be read from.
// Accepting that key let anybody sign in as any identifier they could name.
//
// So every place that needs an identity's key asks one of the two functions
// below, and both answer only from a log that validates: its events chain, its
// inception derives the identifier, and every event is signed by the key it
// declares.

// KeyLog is an identity's key log as it travels: each event exactly as it was
// serialised, and the controller's signature over those bytes.
type KeyLog struct {
	RawEventsB64   []string `json:"raw_events_b64"`
	CesrSignatures []string `json:"cesr_signatures"`
}

// EncodeKeyLog packs a key log into the single string an assertion carries.
func EncodeKeyLog(rawEvents [][]byte, signatures []string) (string, error) {
	if len(rawEvents) == 0 || len(rawEvents) != len(signatures) {
		return "", fmt.Errorf("a key log needs one signature per event (%d events, %d signatures)",
			len(rawEvents), len(signatures))
	}
	kl := KeyLog{CesrSignatures: signatures}
	for _, raw := range rawEvents {
		kl.RawEventsB64 = append(kl.RawEventsB64, base64.StdEncoding.EncodeToString(raw))
	}
	b, err := json.Marshal(kl)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeKeyLog reads a key log in the form EncodeKeyLog writes. It checks
// nothing; KeyFromKeyLog is what says whether the log proves anything.
func DecodeKeyLog(encoded string) (KeyLog, error) {
	var kl KeyLog
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return kl, fmt.Errorf("the key log is not readable: %w", err)
	}
	if err := json.Unmarshal(b, &kl); err != nil {
		return kl, fmt.Errorf("the key log is not readable: %w", err)
	}
	return kl, nil
}

// KeyFromKeyLog returns aid's current signing key from a key log carried with
// a sign-in, or says why the log does not establish one.
//
// It reaches out to nothing: everything it needs is in the log, and the log
// proves itself or it does not.
func KeyFromKeyLog(aid, encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("no key log came with this, so nothing ties a key to %s", aid)
	}
	kl, err := DecodeKeyLog(encoded)
	if err != nil {
		return nil, err
	}
	raws, err := drivers.DecodeRawEvents(kl.RawEventsB64)
	if err != nil {
		return nil, err
	}
	res, err := drivers.ValidateKELFromBytes(drivers.ValidateKELInput{
		AID:            aid,
		RawEvents:      raws,
		CesrSignatures: kl.CesrSignatures,
	})
	if err != nil {
		return nil, err
	}
	return currentKey(aid, res.KelVerified, res.ValidationErrors, res.CurrentPublicKey)
}

// KeyFromOOBI resolves aid's introduction and returns its current signing key,
// only if the key log served there validates and belongs to aid.
//
// Whoever serves the introduction controls every byte of it, which is why the
// address is no part of the trust: a log that derives aid proves itself from
// anywhere, and one that does not proves nothing from anywhere.
func KeyFromOOBI(client *http.Client, oobiURL, aid string) ([]byte, error) {
	var c keriengine.HTTPClient
	if client != nil {
		c = client
	}
	res, err := keriengine.ResolveOobiWith(c, oobiURL)
	if err != nil {
		return nil, err
	}
	if res.CID != aid {
		return nil, fmt.Errorf("the introduction at %s is for %s, not %s", oobiURL, res.CID, aid)
	}
	return currentKey(aid, res.KelVerified, res.ValidationErrors, res.CurrentPublicKey)
}

// OOBIFor is where aid's introduction is published under base, the form every
// introduction in this protocol takes.
func OOBIFor(base, aid string) string {
	if i := strings.Index(base, "/oobi/"); i >= 0 {
		base = base[:i]
	}
	return trimSlash(base) + "/oobi/" + aid
}

func currentKey(aid string, verified bool, problems []string, currentQB64 string) ([]byte, error) {
	if !verified {
		why := "it does not validate"
		if len(problems) > 0 {
			why = strings.Join(problems, "; ")
		}
		return nil, fmt.Errorf("the key log of %s establishes no key: %s", aid, why)
	}
	return iacrypto.KeyFromVerkeyQB64(currentQB64)
}
