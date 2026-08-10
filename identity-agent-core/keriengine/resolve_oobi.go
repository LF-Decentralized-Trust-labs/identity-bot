package keriengine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"identity-agent-core/drivers"
)

// Resolving an out-of-band introduction.
//
// An OOBI is a URL somebody hands over — in a QR code, a link, a message — that
// says "this is where you can learn about me". Resolving it means fetching what
// is there and deciding what, if anything, it establishes.
//
// The answer is: less than it looks. Whoever serves the URL controls every byte
// of the response, so nothing in it can be taken at face value. What CAN be
// established is that the key log served derives the identifier being claimed,
// and that its events are signed by the keys they declare. That is checked here
// before anything is reported, and it is checked from the canonical bytes,
// because a log re-encoded from parsed events digests to something else.
//
// What resolving does NOT establish is that the identifier belongs to the
// person who handed over the link. Nothing at this layer can; that is what a
// credential from an issuer the verifier already trusts is for.

// HTTPClient is how OOBIs are fetched. Replaceable so a test does not need a
// network, and so a deployment can impose its own timeouts and proxying.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// oobiTimeout bounds a fetch. A stranger's server that never answers must not
// hold an agent open indefinitely.
const oobiTimeout = 15 * time.Second

// maxOOBIBody bounds what will be read. Without it, whoever serves the URL
// decides how much memory this agent spends.
const maxOOBIBody = 8 << 20

// ResolveOobi fetches an introduction and reports what it could establish.
func (e *Engine) ResolveOobi(oobiURL string) (*drivers.DriverResolveOobiResponse, error) {
	if oobiURL == "" {
		return nil, fmt.Errorf("no OOBI URL was given")
	}
	parsed, err := url.Parse(oobiURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%q is not a URL that can be fetched", oobiURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%q is not an address this will fetch; an OOBI is retrieved over "+
			"HTTP", parsed.Scheme)
	}

	client := e.http
	if client == nil {
		client = &http.Client{Timeout: oobiTimeout}
	}
	req, err := http.NewRequest(http.MethodGet, oobiURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", oobiURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", oobiURL, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOOBIBody))
	if err != nil {
		return nil, fmt.Errorf("could not read the response from %s: %w", oobiURL, err)
	}

	var doc struct {
		AID          string                   `json:"aid"`
		PublicKey    string                   `json:"public_key"`
		KEL          []map[string]interface{} `json:"kel"`
		RawEventsB64 []string                 `json:"raw_events_b64"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("what %s served is not a readable introduction: %w", oobiURL, err)
	}
	if doc.AID == "" {
		return nil, fmt.Errorf("what %s served names no identity", oobiURL)
	}

	out := &drivers.DriverResolveOobiResponse{
		OobiURL:          oobiURL,
		CID:              doc.AID,
		Endpoints:        []string{endpointBase(oobiURL)},
		KEL:              doc.KEL,
		CurrentPublicKey: doc.PublicKey,
	}

	// Check the log from the bytes it was published as. Everything a caller
	// might do with this — trusting a key, accepting a contact — rests on it.
	in, ok := drivers.ValidateKELInputFromRecords(doc.AID, doc.KEL)
	if !ok && len(doc.RawEventsB64) > 0 {
		if raws, derr := drivers.DecodeRawEvents(doc.RawEventsB64); derr == nil {
			in = drivers.ValidateKELInput{AID: doc.AID, RawEvents: raws}
			ok = true
		}
	}
	if !ok {
		// Served without the bytes it was published as, so its signatures
		// cannot be checked and neither can the claim that this log derives
		// this identifier. Reported as unverified rather than as verified.
		out.ValidationErrors = []string{
			"this introduction carries no canonical event bytes, so its key log can be read " +
				"but not verified: neither the signatures nor the derivation of the identifier " +
				"could be checked",
		}
		out.EventsValidated = len(doc.KEL)
		return out, nil
	}

	res, err := drivers.ValidateKELFromBytes(in)
	if err != nil {
		return nil, err
	}
	out.KelVerified = res.KelVerified
	out.EventsValidated = res.EventsValidated
	out.ValidationErrors = res.ValidationErrors
	if res.CurrentPublicKey != "" {
		out.CurrentPublicKey = res.CurrentPublicKey
	}
	return out, nil
}

// endpointBase is the address an identity is reachable at, taken from the OOBI
// it published rather than from anything the document claims about itself.
func endpointBase(oobiURL string) string {
	if idx := strings.Index(oobiURL, "/public/oobi/"); idx != -1 {
		return strings.TrimRight(oobiURL[:idx], "/")
	}
	return strings.TrimRight(oobiURL, "/")
}
