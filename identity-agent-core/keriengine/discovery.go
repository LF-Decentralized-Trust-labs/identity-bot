package keriengine

import (
	"fmt"
	"time"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// Discovery and presentation.
//
// These three are not KERI event construction, which is why they were the last
// to be built here: resolving an introduction means fetching a document over
// the network and deciding what it establishes, publishing an endpoint means
// producing a reply message rather than a key event, and presenting a
// credential means building a disclosure bound to one holder.
//
// All three are answered now, so nothing an agent does routes to a subprocess.
// Each lives in its own file: resolve_oobi.go, the reply below, and
// presentation.go.

// SupportsDiscovery reports whether this engine can resolve OOBIs, publish
// endpoints and build presentations.
//
// Kept, and now true. A caller that asked before routing work here gets the
// same answer it would get by trying.
func (e *Engine) SupportsDiscovery() bool { return true }

// EndpointLocation states where an identity can currently be reached.
//
// A reply message rather than a key event, deliberately. Where an agent is
// reachable changes for reasons that have nothing to do with its key state — a
// relay is left, an allocation expires, a machine moves — and putting that in
// the key log would grow a record every verifier replays forever with entries
// that are stale almost immediately. A reply stands alone and is superseded by
// a later one.
//
// Returned unsigned, like every other event this engine builds. The controller
// signs the bytes; this holds no keys.
func (e *Engine) EndpointLocation(req *drivers.DriverEndpointLocationRequest) (*drivers.DriverEndpointResponse, error) {
	if req == nil || req.EID == "" {
		return nil, fmt.Errorf("a location statement must name the endpoint it is about")
	}
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	// An empty URL is meaningful rather than missing: it withdraws the address,
	// which is how an identity says "not here any more" instead of leaving one
	// published that no longer answers.
	raw, err := keri.EndpointLocation(req.EID, scheme, req.URL, replyTimestamp())
	if err != nil {
		return nil, fmt.Errorf("building the location statement: %w", err)
	}
	reply, err := keri.VerifyReply(raw)
	if err != nil {
		return nil, fmt.Errorf("the statement this engine built does not verify: %w", err)
	}
	body, err := eventMap(raw)
	if err != nil {
		return nil, err
	}
	return &drivers.DriverEndpointResponse{
		EID:         req.EID,
		URL:         req.URL,
		Scheme:      scheme,
		Route:       reply.Route,
		RpyEvent:    body,
		RawBytesB64: b64(raw),
		SAID:        reply.SAID,
	}, nil
}

// replyTimestamp is when a statement was made, which is what lets a recipient
// tell a newer one from an older one.
func replyTimestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")
}
