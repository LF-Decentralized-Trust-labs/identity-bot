package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"syscall"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// WitnessRequest is the inbound enrollment-request body.
type WitnessRequest struct {
	RequesterAID  string
	RequesterOOBI string
	BackendType   string
	// CoversDelegates asks the witness to witness the identities the
	// requester delegates too. Not assumed: a request that does not ask
	// covers none.
	CoversDelegates bool
	// RequestID names this request: the requester's own record of having asked.
	// The answer repeats it, so an answer is to one request and no other.
	RequestID string
	// Stamp and Signature are the requester's signature, by its current key,
	// over who it is, whether it covers its delegates, and when it asked
	// (RequestStatement). Coverage is changed, either way, only by a request
	// that carries one that holds and is fresh: the route is open, and
	// anybody could otherwise switch it on or off for anyone.
	Stamp     string
	Signature string
}

// RequestStatement is what a requester signs in a witness request: who it
// is, which witness it asks, where the answer is to be sent (its OOBI), the
// backend it runs on, which request this is, whether it covers its delegates,
// and when. Naming the
// witness keeps a request signed for one from being replayed to another;
// binding the OOBI keeps anybody else from pointing the answer, and this
// agent's next call, at an address of their choosing.
func RequestStatement(requester, witnessAID, oobi, backendType, requestID string, covers bool, stamp string) string {
	return fmt.Sprintf("witness-request/v4\n%s\n%s\n%s\n%s\n%s\n%v\n%s", requester, witnessAID, oobi, backendType, requestID, covers, stamp)
}

// configRequestStamps is, by requester, the stamp of the last signed request
// that changed its coverage: an older or equal one is a replay.
const configRequestStamps = "witness.request_stamps"

// requestLifetime is how long a request this agent sent can still be answered:
// an answer after it is refused, so a request nobody answered does not stay
// open for whoever finds the witness's key later.
const requestLifetime = 24 * time.Hour

// requestFreshness is how far a signed witness request's stamp may be from
// now.
const requestFreshness = 5 * time.Minute

// signedByRequester reports whether req carries the requester's own fresh
// signature, checked against its current key: the newest establishment event
// this witness holds for it, or else the key its contact record resolved.
func (s *Service) signedByRequester(req WitnessRequest) bool {
	if req.Signature == "" || req.Stamp == "" {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, req.Stamp)
	if err != nil || time.Since(at) > requestFreshness || time.Until(at) > requestFreshness {
		return false
	}
	if !s.signedBy(req.RequesterAID, RequestStatement(req.RequesterAID, s.ourAID(), req.RequesterOOBI, req.BackendType, req.RequestID, req.CoversDelegates, req.Stamp), req.Signature) {
		return false
	}
	// Newer than the last one acted on for this requester, or a replay.
	s.delegatesMu.Lock()
	defer s.delegatesMu.Unlock()
	stamps := map[string]string{}
	if raw, err := s.Store.GetConfig(configRequestStamps); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &stamps)
	}
	if last, err := time.Parse(time.RFC3339Nano, stamps[req.RequesterAID]); err == nil && !at.After(last) {
		return false
	}
	stamps[req.RequesterAID] = req.Stamp
	raw, _ := json.Marshal(stamps)
	_ = s.Store.SetConfig(configRequestStamps, string(raw))
	return true
}

// currentKeyOf is the key aid signs with now: the newest establishment event
// this Identity Agent holds for it, or else the key its contact record resolved.
func (s *Service) currentKeyOf(aid string) string {
	key := ""
	if held, err := s.Store.GetKelEvents(aid); err == nil {
		for _, e := range held {
			var ev map[string]interface{}
			if json.Unmarshal([]byte(e.EventJSON), &ev) != nil {
				continue
			}
			switch ev["t"] {
			case "icp", "rot", "dip", "drt":
				if keys, ok := ev["k"].([]interface{}); ok && len(keys) > 0 {
					key, _ = keys[0].(string)
				}
			}
		}
	}
	if key == "" {
		if c, _ := s.Contacts.GetContact(aid); c != nil {
			key = c.PublicKey
		}
	}
	return key
}

// signedBy reports whether signature is aid's, by its current key, over
// statement.
func (s *Service) signedBy(aid, statement, signature string) bool {
	if signature == "" {
		return false
	}
	// A verification is always done, against a stand-in key when aid has none we
	// can use, so that an identity this agent holds a log for costs a caller the
	// same as one it does not: otherwise the time taken tells a stranger who is
	// witnessed.
	pub, real := noKeyAtAll, false
	if key := s.currentKeyOf(aid); key != "" {
		if raw, err := login.DecodeVerkey(key); err == nil {
			pub, real = raw, true
		}
	}
	ok, err := login.VerifyString(statement, signature, pub)
	return real && err == nil && ok
}

// noKeyAtAll is a well-formed public key nobody holds the private half of.
var noKeyAtAll = func() []byte {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub
}()

// signedByWitnessKey reports whether signature is over statement by the key a
// non-transferable witness identifier names.
func signedByWitnessKey(witnessKey, statement, signature string) bool {
	if signature == "" {
		return false
	}
	pub, err := iacrypto.KeyFromNonTransferableAID(witnessKey)
	if err != nil {
		return false
	}
	ok, err := login.VerifyString(statement, signature, pub)
	return err == nil && ok
}

// AcceptCallback is the accept POST-back body: a witness's answer to a
// request to witness for the requester.
//
// It is signed with the responder's witness key, the non-transferable
// identifier it receipts under and published with its OOBI, over who asked,
// who answers, the answer and when (AcceptStatement). That is the key the
// requester will rely on for this witness's receipts, every witness holds it,
// and it is checked from the identifier alone, so nothing has to be looked up
// and no rotation of the responder's identity leaves it stale. The route it
// arrives on is open, and acting on it makes the responder a witness for the
// requester, so an answer nobody can show the responder gave changes nothing.
type AcceptCallback struct {
	RequesterAID string `json:"requester_aid"`
	ResponderAID string `json:"responder_aid"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason,omitempty"`
	BackendType  string `json:"backend_type,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
	WitnessKey   string `json:"witness_key,omitempty"`
	// RequestID is the request this answers, as the requester named it.
	RequestID string `json:"request_id,omitempty"`
	Stamp     string `json:"stamp,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// AcceptStatement is what a responder signs in its answer to a witness
// request: who asked, who answers and under which witness key, the answer, the
// reason given for it (which the person is shown), the backend it answers
// from, the request it answers, and when. Naming the requester and the request
// keeps an answer to one from being replayed to another.
func AcceptStatement(requester, responder, witnessKey, decision, reason, backendType, requestID, stamp string) string {
	return fmt.Sprintf("witness-accept/v3\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s", requester, responder, witnessKey, decision, reason, backendType, requestID, stamp)
}

// configAcceptStamps is, by responder, the stamp of the last signed answer
// acted on: an older or equal one is a replay.
const configAcceptStamps = "witness.accept_stamps"

// InboundResult is the outcome of evaluating an inbound enrollment request.
type InboundResult struct {
	Accepted bool
	Reason   string
	TaskID   string
}

// EvaluateInboundRequest applies C7 rules for accepting witnessing FOR the requester.
func (s *Service) EvaluateInboundRequest(req WitnessRequest) (bool, string) {
	if req.RequesterAID == "" {
		return false, "missing_requester"
	}
	contact, _ := s.Contacts.GetContact(req.RequesterAID)
	if contact == nil {
		return false, "unknown_contact"
	}
	if contact.Status != "accepted" {
		return false, "contact_not_accepted"
	}
	if !IsContactWitnessEligible(*contact) {
		return false, "contact_ineligible"
	}
	switch contact.ContactCategory {
	case "trusted", "professional":
	default:
		return false, "contact_category_ineligible"
	}
	if req.BackendType == BackendMobile || strings.EqualFold(req.BackendType, "phone") {
		return false, "mobile_backend"
	}
	if !IsBackendEligible(s.BackendType) {
		return false, "local_backend_ineligible"
	}
	// One already witnessed for, asking again, takes no more capacity.
	if meta, _ := s.Store.GetContactMeta(req.RequesterAID); meta != nil && meta.WitnessingFor {
		return true, ""
	}
	outgoing, _ := s.Store.CountWitnessingFor()
	if outgoing >= MaxOutgoingWitnessing {
		return false, "capacity_full"
	}
	if !s.localWitnessCapacityOK() {
		return false, "local_unhealthy"
	}
	return true, ""
}

func (s *Service) localWitnessCapacityOK() bool {
	outgoing, _ := s.Store.CountWitnessingFor()
	return outgoing < MaxOutgoingWitnessing && IsBackendEligible(s.BackendType)
}

// ProcessInboundRequest handles the inbound enrollment request: evaluate, enroll as witnessing-for, task, POST-back, reciprocal.
//
// The route this arrives on is open, so the requester's signature is the gate,
// and it is checked first, whatever the decision would be: a request that is
// not signed by the requester's key, fresh and newer than the last, bound to
// the OOBI the answer goes to, is refused plainly before anything is created
// or sent. No task is written and no answer is posted, since the address in an
// unsigned request is nobody's to name, and a signed decline carrying
// somebody else's request id would close their real request. An answer, accepted
// or declined, goes only to the OOBI the requester signed.
//
// A requester whose key this agent does not hold (a contact recorded without
// one, and no key history held for it) cannot be checked, so it is refused
// as requester_key_unknown. The requester sees that reason in the response to
// its request and records it against the request.
func (s *Service) ProcessInboundRequest(ctx context.Context, req WitnessRequest) InboundResult {
	if req.RequesterAID == "" {
		return InboundResult{Accepted: false, Reason: "missing_requester"}
	}
	if s.currentKeyOf(req.RequesterAID) == "" {
		return InboundResult{Accepted: false, Reason: "requester_key_unknown"}
	}
	if !s.signedByRequester(req) {
		return InboundResult{Accepted: false, Reason: "unsigned_request"}
	}
	// A contact not yet accepted gets an answer in the response and nothing
	// else: a task per request would let anyone whose key is held fill the
	// task list, one row for every newly stamped request, and nothing is
	// posted to an address nobody has accepted.
	if c, _ := s.Contacts.GetContact(req.RequesterAID); c == nil || c.Status != "accepted" {
		reason := "unknown_contact"
		if c != nil {
			reason = "contact_not_accepted"
		}
		return InboundResult{Accepted: false, Reason: reason}
	}
	accept, reason := s.EvaluateInboundRequest(req)
	taskID := fmt.Sprintf("witness-recv-%s-%d", req.RequesterAID, time.Now().Unix())
	now := NowRFC3339()
	taskStatus := "failed"
	detail := fmt.Sprintf("Declined: %s", reason)

	if accept {
		if err := s.enrollWitnessingFor(req.RequesterAID, req.BackendType); err != nil {
			accept = false
			reason = "enroll_failed"
			detail = err.Error()
		} else {
			s.agreeToDelegates(req.RequesterAID, req.CoversDelegates)
			taskStatus = "completed"
			detail = fmt.Sprintf("Now witnessing key events for %s", req.RequesterAID[:12])
		}
	}

	_ = s.Contacts.SaveTask(store.TaskRecord{
		ID: taskID, Type: "witness_request_received", Status: taskStatus,
		ContactAID: req.RequesterAID, Detail: detail, CreatedAt: now, UpdatedAt: now,
	})

	responder := s.ourAID()
	decision := "declined"
	if accept {
		decision = "accepted"
	}
	cb := AcceptCallback{
		RequesterAID: req.RequesterAID, ResponderAID: responder,
		Decision: decision, Reason: reason, BackendType: s.BackendType, TaskID: taskID, RequestID: req.RequestID,
	}
	if req.RequesterOOBI != "" {
		go func() {
			if err := s.SendAcceptCallback(context.Background(), req.RequesterOOBI, cb); err != nil {
				log.Printf("[witness] accept POST-back failed: %v", err)
			}
		}()
	}

	if accept {
		go s.maybeReciprocalRequest(context.Background(), req)
	}

	return InboundResult{Accepted: accept, Reason: reason, TaskID: taskID}
}

// enrollWitnessingFor records that we witness FOR requester (outgoing direction).
func (s *Service) enrollWitnessingFor(requesterAID, backendType string) error {
	if backendType == "" {
		backendType = BackendDesktop
	}
	now := NowRFC3339()
	meta, _ := s.Store.GetContactMeta(requesterAID)
	if meta == nil {
		meta = &ContactMeta{ContactAID: requesterAID}
	}
	meta.BackendType = backendType
	meta.WitnessStatus = StatusOnline
	meta.WitnessingFor = true
	meta.EnrolledAt = now
	meta.LastHealthCheck = now
	if err := s.Store.SaveContactMeta(*meta); err != nil {
		return err
	}
	c, _ := s.Contacts.GetContact(requesterAID)
	if c != nil {
		return nil
	}
	return s.Contacts.SaveContact(store.ContactRecord{
		AID: requesterAID, Alias: requesterAID[:12] + "…", Status: "accepted",
		ContactCategory: "general", ContactSource: ContactSourceManual,
	})
}

// lookupHost resolves a name for the check on where an answer may go; a
// variable so a test can say what a name resolves to.
var lookupHost = net.LookupIP

// answerAddress is the one place the answer to requester's request may be
// posted: the address in the contact's own recorded OOBI for that AID, and
// nothing the request itself says. signed is the OOBI the request carried
// (it must name the same host as the recorded one, or the request is not from
// where the contact lives); an OOBI that names an AID must name the
// requester's. A name that resolves to a private, loopback or link-local
// address is refused, unless the recorded OOBI is itself such an address (a
// local test agent): this agent is not to be made to call what is on its own
// network by a name somebody else controls.
func (s *Service) answerAddress(requesterAID, signed string) (url string, local bool, err error) {
	c, _ := s.Contacts.GetContact(requesterAID)
	if c == nil || c.OobiURL == "" {
		return "", false, fmt.Errorf("%s has no recorded OOBI to answer at", requesterAID)
	}
	rec, err := OOBIFitsAID(c.OobiURL, requesterAID)
	if err != nil {
		return "", false, fmt.Errorf("the recorded OOBI of %s: %w", requesterAID, err)
	}
	if signed != "" {
		sg, err := neturl.Parse(signed)
		if err != nil || !strings.EqualFold(sg.Host, rec.Host) || sg.Scheme != rec.Scheme {
			return "", false, fmt.Errorf("the request's OOBI is not at the address recorded for %s", requesterAID)
		}
	}
	host := rec.Hostname()
	// A local address is a local test agent only where the owner is the one who
	// recorded it; one a stranger's request left behind is not.
	if LiteralIsLocal(host) && c.ContactSource != ContactSourceInbound {
		return witnessAcceptURL(c.OobiURL), true, nil
	}
	ips, err := lookupHost(host)
	if err != nil || len(ips) == 0 {
		return "", false, fmt.Errorf("%s does not resolve", host)
	}
	for _, ip := range ips {
		if ipIsInternal(ip) {
			return "", false, fmt.Errorf("%s resolves to an internal address, and is not called", host)
		}
	}
	return witnessAcceptURL(c.OobiURL), false, nil
}

// OOBIFitsAID checks that oobi is an http(s) address that names aid, and
// returns it parsed: aid must be one of its path segments, and where it has
// an /oobi/ segment, the one right after it.
func OOBIFitsAID(oobi, aid string) (*neturl.URL, error) {
	u, err := neturl.Parse(oobi)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("is not a web address")
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	named := false
	for i, seg := range segs {
		if seg == "oobi" && i+1 < len(segs) && strings.TrimSpace(segs[i+1]) != aid {
			return nil, fmt.Errorf("names %q, not %s", segs[i+1], aid)
		}
		if seg == aid {
			named = true
		}
	}
	if !named {
		return nil, fmt.Errorf("does not name %s", aid)
	}
	return u, nil
}

// LiteralIsLocal is whether host is itself "localhost" or a private, loopback,
// link-local or shared-address-space address, written out.
func LiteralIsLocal(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ipIsInternal(ip)
}

var (
	cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	// "This network", the benchmarking range, and the reserved and broadcast
	// block: none of them is a place a peer lives.
	reservedV4 = []*net.IPNet{
		{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)},
		{IP: net.IPv4(240, 0, 0, 0), Mask: net.CIDRMask(4, 32)},
	}
	// NAT64 (RFC 6052): the last 32 bits are an IPv4 address the gateway will
	// dial on the sender's behalf.
	nat64 = &net.IPNet{IP: net.ParseIP("64:ff9b::"), Mask: net.CIDRMask(96, 128)}
)

func ipIsInternal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || cgnat.Contains(ip) {
		return true
	}
	for _, n := range reservedV4 {
		if n.Contains(ip) {
			return true
		}
	}
	if ip.To4() == nil && nat64.Contains(ip) {
		if v6 := ip.To16(); v6 != nil {
			return ipIsInternal(net.IPv4(v6[12], v6[13], v6[14], v6[15]))
		}
	}
	return false
}

// ResolvesInternal is whether host, a name, resolves to an internal address
// (or cannot be resolved, so cannot be shown not to).
func ResolvesInternal(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ipIsInternal(ip)
	}
	ips, err := lookupHost(host)
	if err != nil || len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		if ipIsInternal(ip) {
			return true
		}
	}
	return false
}

// dialResolve turns a name into the addresses that are dialled. It is a
// variable so a test can make a name answer differently when dialled than
// when it was checked.
var dialResolve = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// guardedClient is an HTTP client for the answer: it follows no redirect, uses
// no proxy, and refuses to connect to an internal address (the one actually
// dialled, so a name that changes what it resolves to between the check and
// the call gains nothing) unless local, which is only for a contact whose
// recorded address is itself a local one the owner set.
func guardedClient(timeout time.Duration, local bool) *http.Client {
	d := &net.Dialer{Timeout: timeout, Control: func(network, address string, _ syscall.RawConn) error {
		if local {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || ipIsInternal(ip) {
			return fmt.Errorf("%s is an internal address, and is not called", host)
		}
		return nil
	}}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return d.DialContext(ctx, network, addr)
		}
		addrs, err := dialResolve(ctx, host)
		if err != nil {
			return nil, err
		}
		last := fmt.Errorf("%s does not resolve", host)
		for _, a := range addrs {
			c, err := d.DialContext(ctx, network, net.JoinHostPort(a, port))
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{Proxy: nil, DialContext: dial, TLSHandshakeTimeout: timeout},
		CheckRedirect: refuseRedirects,
	}
}

func refuseRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

type guardKey struct{}

// SendAcceptCallback sends the accept POST-back to the requester's agent, at
// the address recorded for the requester and no other (see answerAddress).
// requesterOOBI is the one the request was signed with.
func (s *Service) SendAcceptCallback(ctx context.Context, requesterOOBI string, cb AcceptCallback) error {
	url, local, err := s.answerAddress(cb.RequesterAID, requesterOOBI)
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, guardKey{}, local)
	if cb.ResponderAID == "" {
		cb.ResponderAID = s.ourAID()
	}
	// An unsigned answer is refused by the requester, so one that cannot be
	// signed here is not sent.
	if s.SignReceipt == nil || s.OurWitnessAID == nil {
		return fmt.Errorf("this Identity Agent holds no witness key, so it cannot answer")
	}
	key, err := s.OurWitnessAID()
	if err != nil {
		return fmt.Errorf("the witness key: %w", err)
	}
	cb.WitnessKey = key
	cb.Stamp = time.Now().UTC().Format(time.RFC3339Nano)
	signer, sig, err := s.SignReceipt(AcceptStatement(cb.RequesterAID, cb.ResponderAID, cb.WitnessKey, cb.Decision, cb.Reason, cb.BackendType, cb.RequestID, cb.Stamp))
	if err != nil {
		return fmt.Errorf("sign the answer: %w", err)
	}
	if signer != key {
		return fmt.Errorf("the answer was signed as %s, not the witness key %s", signer, key)
	}
	cb.Signature = sig
	body, err := json.Marshal(cb)
	if err != nil {
		return err
	}
	_, err = s.PostEvent(ctx, url, body)
	return err
}

// ApplyAcceptCallback acts on a witness's answer to a request this Identity Agent sent.
//
// Before anything is written, the answer must be signed by the responder's
// current key, fresh, newer than the last answer acted on from it, and answer
// a request still pending to that responder. An answer nobody asked for, or
// one that cannot be shown to be the responder's, changes nothing: acting on
// it would make whoever sent it a witness this identity never chose.
func (s *Service) ApplyAcceptCallback(cb AcceptCallback) error {
	if cb.RequesterAID == "" || cb.ResponderAID == "" {
		return fmt.Errorf("missing aids")
	}
	if cb.RequesterAID != s.ourAID() {
		return fmt.Errorf("requester_aid mismatch")
	}
	if cb.Decision != "accepted" && cb.Decision != "declined" {
		return fmt.Errorf("an answer is accepted or declined, not %q", cb.Decision)
	}
	at, err := time.Parse(time.RFC3339Nano, cb.Stamp)
	if err != nil || time.Since(at) > requestFreshness || time.Until(at) > requestFreshness {
		return fmt.Errorf("the answer carries no fresh stamp")
	}
	// The witness key the responder published with its OOBI, and nothing the
	// answer says about itself.
	meta, _ := s.Store.GetContactMeta(cb.ResponderAID)
	if meta == nil || meta.WitnessKey == "" {
		return fmt.Errorf("%s has published no witness key, so its answer cannot be checked", cb.ResponderAID)
	}
	if cb.WitnessKey != meta.WitnessKey {
		return fmt.Errorf("the answer names witness key %q, and %s published %q", cb.WitnessKey, cb.ResponderAID, meta.WitnessKey)
	}
	if !signedByWitnessKey(meta.WitnessKey, AcceptStatement(cb.RequesterAID, cb.ResponderAID, cb.WitnessKey, cb.Decision, cb.Reason, cb.BackendType, cb.RequestID, cb.Stamp), cb.Signature) {
		return fmt.Errorf("the answer is not signed by %s's witness key", cb.ResponderAID)
	}

	s.acceptMu.Lock()
	defer s.acceptMu.Unlock()
	stamps := map[string]string{}
	if raw, err := s.Store.GetConfig(configAcceptStamps); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &stamps)
	}
	if last, err := time.Parse(time.RFC3339Nano, stamps[cb.ResponderAID]); err == nil && !at.After(last) {
		return fmt.Errorf("the answer has already been acted on")
	}
	task, err := s.pendingSentTask(cb.ResponderAID, cb.RequestID)
	if err != nil {
		return err
	}
	if task == nil {
		return fmt.Errorf("no witness request %q to %s is waiting for an answer", cb.RequestID, cb.ResponderAID)
	}

	// The enrolment and the request's completion stand or fall together: the
	// request is what makes the answer usable once, so if it cannot be marked
	// done the enrolment is undone and the answer can be tried again.
	accepted := cb.Decision == "accepted"
	var undo func() error
	if accepted {
		var err error
		if undo, err = s.enrollWitnessForUsUndoably(cb.ResponderAID, cb.BackendType); err != nil {
			return err
		}
		if err := s.completeTask(*task, "completed",
			fmt.Sprintf("Witness enrollment accepted by %s", cb.ResponderAID[:12])); err != nil {
			if uerr := undo(); uerr != nil {
				return fmt.Errorf("%w, and the enrolment could not be put back: %v", err, uerr)
			}
			return err
		}
	} else if err := s.completeTask(*task, "failed", fmt.Sprintf("Declined: %s", cb.Reason)); err != nil {
		return err
	}
	// The request is no longer pending, so the answer cannot be used twice
	// even if this record is not kept.
	stamps[cb.ResponderAID] = cb.Stamp
	raw, _ := json.Marshal(stamps)
	if err := s.Store.SetConfig(configAcceptStamps, string(raw)); err != nil {
		log.Printf("[witness] could not record the stamp of the answer from %s: %v", cb.ResponderAID, err)
	}
	if accepted {
		_ = s.refreshMutual(cb.ResponderAID)
	}
	if s.OnEvent != nil {
		s.OnEvent("witness_accept_received", map[string]interface{}{
			"responder_aid": cb.ResponderAID, "decision": cb.Decision, "reason": cb.Reason,
		})
	}
	return nil
}

// enrollWitnessForUsUndoably is enrollWitnessForUs, and the way to put back
// what it changed: the earlier records as they were, and where there were
// none, no record. It returns the first thing it could not put back.
func (s *Service) enrollWitnessForUsUndoably(responderAID, backendType string) (func() error, error) {
	prevContact, _ := s.Contacts.GetContact(responderAID)
	prevMeta, _ := s.Store.GetContactMeta(responderAID)
	if err := s.enrollWitnessForUs(responderAID, backendType); err != nil {
		return nil, err
	}
	return func() error {
		var first error
		if prevContact != nil {
			if err := s.Contacts.SaveContact(*prevContact); err != nil {
				first = err
			}
		}
		var err error
		if prevMeta != nil {
			err = s.Store.SaveContactMeta(*prevMeta)
		} else {
			err = s.Store.DeleteContactMeta(responderAID)
		}
		if err != nil && first == nil {
			first = err
		}
		return first
	}, nil
}

// enrollWitnessForUs marks responder as a witness FOR our AID (broadcast pool).
func (s *Service) enrollWitnessForUs(responderAID, backendType string) error {
	c, err := s.Contacts.GetContact(responderAID)
	if err != nil {
		return err
	}
	// A request is only ever sent to a contact, so an answer from anybody
	// else is not one to act on, and is never a reason to make them a contact.
	if c == nil {
		return fmt.Errorf("%s is not a contact", responderAID)
	}
	c.IsWitness = true
	if err := s.Contacts.SaveContact(*c); err != nil {
		return err
	}
	if backendType == "" {
		backendType = BackendDesktop
	}
	now := NowRFC3339()
	meta, _ := s.Store.GetContactMeta(responderAID)
	if meta == nil {
		meta = &ContactMeta{ContactAID: responderAID}
	}
	meta.BackendType = backendType
	meta.WitnessStatus = StatusOnline
	meta.EnrolledAt = now
	meta.LastHealthCheck = now
	return s.Store.SaveContactMeta(*meta)
}

// pendingSentTask is the witness request requestID to contactAID still waiting
// for an answer, or nil.
func (s *Service) pendingSentTask(contactAID, requestID string) (*store.TaskRecord, error) {
	tasks, err := s.Contacts.GetTasks()
	if err != nil {
		return nil, err
	}
	for i := range tasks {
		t := tasks[i]
		if requestID != "" && t.ID == requestID && t.Type == "witness_request_sent" && t.ContactAID == contactAID && t.Status == "pending" {
			// A request nobody answered in time is not answered late.
			if at, err := time.Parse(time.RFC3339Nano, t.CreatedAt); err != nil || time.Since(at) > requestLifetime {
				return nil, nil
			}
			return &t, nil
		}
	}
	return nil, nil
}

func (s *Service) completeTask(t store.TaskRecord, status, detail string) error {
	t.Status = status
	t.Detail = detail
	t.UpdatedAt = NowRFC3339()
	return s.Contacts.SaveTask(t)
}

func (s *Service) refreshMutual(contactAID string) error {
	c, _ := s.Contacts.GetContact(contactAID)
	if c == nil || !c.IsWitness {
		return nil
	}
	meta, _ := s.Store.GetContactMeta(contactAID)
	if meta == nil || !meta.WitnessingFor {
		return nil
	}
	meta.IsMutual = true
	return s.Store.SaveContactMeta(*meta)
}

func (s *Service) maybeReciprocalRequest(ctx context.Context, req WitnessRequest) {
	if s.ActiveWitnessCount() >= TargetContactWitnesses {
		return
	}
	if !IsBackendEligible(req.BackendType) && req.BackendType != "" {
		return
	}
	c, _ := s.Contacts.GetContact(req.RequesterAID)
	if c == nil || c.IsWitness {
		return
	}
	if c.ContactCategory != "trusted" && c.ContactCategory != "professional" {
		return
	}
	_ = s.SendWitnessRequest(ctx, req.RequesterAID)
}

func witnessAcceptURL(oobi string) string {
	base := oobi
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		base = oobi[:idx]
	}
	return strings.TrimRight(base, "/") + "/api/witness/accept"
}

// SetHostLookup replaces the lookup used to check where a name points, and
// returns what restores it. For tests in other packages, which cannot reach
// the lookup itself.
func SetHostLookup(f func(string) ([]net.IP, error)) (restore func()) {
	old := lookupHost
	lookupHost = f
	return func() { lookupHost = old }
}
