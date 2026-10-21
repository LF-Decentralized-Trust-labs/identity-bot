// Package relaytest runs a relay in-process for tests. It speaks the protocol
// of ADR-048 as a real relay does: the session through relayproto, the
// discovery descriptor, and signed control requests (§8).
//
// Like a real deployment, it has two front doors: the caller-facing one, which
// in production may sit behind a TLS-terminating proxy, and a connect host
// where Identity Agents are admitted and send control requests. The
// caller-facing door refuses both, and counts anybody who tries.
//
// A private address is a path, https://<relay>/<label>/...: the label is
// stripped and named in X-Forwarded-Prefix before a request is forwarded. A
// public name is a host, https://<name>.<relay>/..., forwarded unchanged.
package relaytest

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/relay"
)

// Relay is a running test relay.
type Relay struct {
	Mode relayproto.Mode
	// Server is the caller-facing door; Connect is the connect host.
	Server  *httptest.Server
	Connect *httptest.Server
	// ConnectHostOverride, when set, is the connect host the descriptor
	// advertises instead of the real one: a descriptor somebody rewrote.
	ConnectHostOverride string
	// Misdirected counts sessions and control requests that came to the
	// caller-facing door.
	Misdirected int

	service string
	cfg     *relayproto.ServiceConfig

	mu       sync.Mutex
	enrolled map[string][]byte // aid -> key log
	keys     map[string]string // aid -> current key, qb64
	// Stored, as a relay keeps them: a private label and the commitment to
	// its secret (never whose it is), and a public name and its holder.
	commitments map[string]string
	names       map[string]string
	// In memory only: which identifier serves each private label.
	bound  map[string]string
	nonces map[string]bool
	// ClaimMode, when set, is the mode written in every preamble instead of
	// the one the relay serves: a relay that lies about an address.
	ClaimMode relayproto.Mode
	aliases   map[string]string
	down      bool
	// domains maps a requested domain to its holder, and verified to whether
	// its DNS has proved it; txt is the DNS this relay sees.
	domains  map[string]string
	verified map[string]bool
	txt      map[string]string
	// Binds counts bind requests answered, and Claims claim-name requests.
	Binds  int
	Claims int
}

// New starts a relay serving mode.
func New(mode relayproto.Mode) *Relay {
	r := &Relay{Mode: mode, enrolled: map[string][]byte{}, keys: map[string]string{},
		commitments: map[string]string{}, names: map[string]string{}, bound: map[string]string{},
		nonces: map[string]bool{}, aliases: map[string]string{},
		domains: map[string]string{}, verified: map[string]bool{}, txt: map[string]string{}}
	r.Server = httptest.NewUnstartedServer(http.HandlerFunc(r.handleCaller))
	r.Server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	r.Server.StartTLS()
	r.Connect = httptest.NewUnstartedServer(http.HandlerFunc(r.handle))
	r.Connect.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	r.Connect.StartTLS()
	host := strings.TrimPrefix(r.Server.URL, "https://")
	r.service = host[:strings.LastIndex(host, ":")]
	r.cfg = &relayproto.ServiceConfig{
		Verifier: &relayproto.Verifier{Service: r.service, Enrolled: func(aid string) ([]byte, bool) {
			r.mu.Lock()
			defer r.mu.Unlock()
			k, ok := r.enrolled[aid]
			return k, ok
		}},
		Registry: relayproto.NewRegistry(),
		OnAdmit:  r.remember,
		OnRenew:  r.remember,
		Logf:     func(string, ...any) {},
	}
	return r
}

func (r *Relay) remember(v *relayproto.Verified) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enrolled[v.AID] = v.KEL
	r.keys[v.AID] = v.Key
	return nil
}

// URL is the relay's https:// root.
func (r *Relay) URL() string { return r.Server.URL }

// TLS trusts this relay's certificate.
func (r *Relay) TLS() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(r.Server.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
}

// Client is an HTTP client that trusts this relay.
func (r *Relay) Client() *http.Client { return r.Server.Client() }

// Close stops the relay and every session.
func (r *Relay) Close() {
	r.Server.CloseClientConnections()
	r.Server.Close()
	r.Connect.CloseClientConnections()
	r.Connect.Close()
}

// MisdirectedCount is how many sessions and control requests came to the
// caller-facing door.
func (r *Relay) MisdirectedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Misdirected
}

// handleCaller is the caller-facing door: the descriptor and the addresses,
// and nothing an Identity Agent connects or signs through.
func (r *Relay) handleCaller(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/tunnel", "/allocate", "/bind", "/release", "/names/claim", "/names/release",
		"/domains/request", "/domains/verify", "/domains/release":
		r.mu.Lock()
		r.Misdirected++
		r.mu.Unlock()
		http.Error(w, "connect at the connect host", http.StatusMisdirectedRequest)
		return
	}
	r.handle(w, req)
}

// Drop ends aid's live session, as a dropped network would.
func (r *Relay) Drop(aid string) { r.cfg.Registry.Revoke(aid) }

// Restart forgets everything a relay keeps only in memory (which session
// serves which private address) and drops every session, as a relay process
// that restarted would. Stored records survive.
func (r *Relay) Restart() {
	r.mu.Lock()
	r.bound = map[string]string{}
	aids := make([]string, 0, len(r.keys))
	for aid := range r.keys {
		aids = append(aids, aid)
	}
	r.mu.Unlock()
	for _, aid := range aids {
		r.cfg.Registry.Revoke(aid)
	}
}

// Down makes the relay answer nothing but 503, until called with false.
func (r *Relay) Down(down bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down = down
}

// Alias routes requests for label to the identifier serving target, and names
// label in the preamble: a relay that mixed two addresses up.
func (r *Relay) Alias(label, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aliases[label] = target
}

// Holds reports whether the relay still has label allocated.
func (r *Relay) Holds(label string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.commitments[label]
	_, named := r.names[label]
	return ok || named
}

// Connected reports whether aid holds a live session.
func (r *Relay) Connected(aid string) bool {
	_, ok := r.cfg.Registry.Get(aid)
	return ok
}

// BindCount is how many bind requests the relay has answered.
func (r *Relay) BindCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Binds
}

func (r *Relay) handle(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	down := r.down
	r.mu.Unlock()
	if down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	switch req.URL.Path {
	case "/.well-known/url-relay-service.json":
		connect := strings.TrimPrefix(r.Connect.URL, "https://")
		r.mu.Lock()
		if r.ConnectHostOverride != "" {
			connect = r.ConnectHostOverride
		}
		r.mu.Unlock()
		eps := map[string]string{}
		for op, path := range map[string]string{relay.OpAllocate: "/allocate", relay.OpBind: "/bind",
			relay.OpRelease: "/release", relay.OpClaimName: "/names/claim", relay.OpReleaseName: "/names/release",
			relay.OpRequestDomain: "/domains/request", relay.OpVerifyDomain: "/domains/verify",
			relay.OpReleaseDomain: "/domains/release"} {
			eps[op] = "https://" + connect + path
		}
		json.NewEncoder(w).Encode(relay.ServiceDescriptor{
			Protocol: relayproto.ProtocolVersion, Service: r.service, Mode: r.Mode, ConnectHost: connect,
			TunnelEndpoint: "wss://" + connect + "/tunnel", Endpoints: eps,
		})
		return
	case "/tunnel":
		relayproto.Accept(w, req, r.cfg)
		return
	case "/allocate":
		r.control(w, req, relay.OpAllocate, r.allocate)
		return
	case "/bind":
		r.control(w, req, relay.OpBind, r.bind)
		return
	case "/release":
		r.control(w, req, relay.OpRelease, r.release)
		return
	case "/names/claim":
		r.control(w, req, relay.OpClaimName, r.claimName)
		return
	case "/names/release":
		r.control(w, req, relay.OpReleaseName, r.releaseName)
		return
	case "/domains/request":
		r.control(w, req, relay.OpRequestDomain, r.requestDomain)
		return
	case "/domains/verify":
		r.control(w, req, relay.OpVerifyDomain, r.verifyDomain)
		return
	}
	r.forward(w, req)
}

func (r *Relay) forward(w http.ResponseWriter, req *http.Request) {
	if r.Mode == relayproto.ModePublic {
		r.forwardName(w, req)
		return
	}
	seg, tail, _ := strings.Cut(strings.TrimPrefix(req.URL.Path, "/"), "/")
	r.mu.Lock()
	target := seg
	if t, ok := r.aliases[seg]; ok {
		target = t
	}
	aid := r.bound[target]
	mode := r.Mode
	if r.ClaimMode != "" {
		mode = r.ClaimMode
	}
	r.mu.Unlock()
	if aid == "" {
		http.NotFound(w, req)
		return
	}
	sess, ok := r.cfg.Registry.Get(aid)
	if !ok {
		http.Error(w, "the Identity Agent is not connected", http.StatusBadGateway)
		return
	}
	out := req.Clone(req.Context())
	out.URL.Path, out.URL.RawPath = "/"+tail, ""
	out.RequestURI = ""
	out.Header.Set("X-Forwarded-Prefix", "/"+seg)
	sess.Forward(w, out, relayproto.Preamble{Allocation: seg, Mode: mode, Host: req.Host})
}

// forwardName carries a request for https://<name>.<relay>/... to the holder
// of the name, unchanged.
func (r *Relay) forwardName(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	name, ok := strings.CutSuffix(host, "."+r.service)
	r.mu.Lock()
	target := name
	if t, aliased := r.aliases[name]; aliased {
		target = t
	}
	aid := r.names[target]
	if !ok && r.verified[host] {
		name, ok, aid = host, true, r.domains[host]
	}
	mode := r.Mode
	if r.ClaimMode != "" {
		mode = r.ClaimMode
	}
	r.mu.Unlock()
	if !ok || aid == "" {
		http.NotFound(w, req)
		return
	}
	sess, connected := r.cfg.Registry.Get(aid)
	if !connected {
		http.Error(w, "the Identity Agent is not connected", http.StatusBadGateway)
		return
	}
	out := req.Clone(req.Context())
	out.Header.Del("X-Forwarded-Prefix")
	out.RequestURI = ""
	sess.Forward(w, out, relayproto.Preamble{Allocation: name, Mode: mode, Host: req.Host})
}

// Caller is an HTTP client for somebody on the internet reaching an address
// at this relay: every host name, the name subdomains included, reaches the
// relay. It does not check the relay's certificate, which a test certificate
// cannot issue for those names.
func (r *Relay) Caller() *http.Client {
	addr := r.Server.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

type controlFn func(w http.ResponseWriter, aid string, f map[string]string)

// control checks a signed control request as a relay does: op, relay name,
// freshness, a nonce used once, a live session, and the key its log names now.
func (r *Relay) control(w http.ResponseWriter, req *http.Request, op string, fn controlFn) {
	var body map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f := map[string]string{}
	for k, v := range body {
		s, ok := v.(string)
		if !ok {
			http.Error(w, "every field is a string", http.StatusBadRequest)
			return
		}
		f[k] = s
	}
	aid := f["signed_by"]
	at, err := time.Parse(time.RFC3339, f["t"])
	if f["op"] != op || f["relay"] != r.service || err != nil || time.Since(at) > 2*time.Minute || len(f["nonce"]) < 16 {
		http.Error(w, "malformed control request", http.StatusBadRequest)
		return
	}
	if !r.Connected(aid) {
		http.Error(w, "connect first", http.StatusForbidden)
		return
	}
	r.mu.Lock()
	key := r.keys[aid]
	r.mu.Unlock()
	raw, err := base64.RawURLEncoding.DecodeString("A" + key[1:])
	sig, serr := base64.RawURLEncoding.DecodeString(f["signature"])
	canon, cerr := relay.CanonicalBody(body)
	if err != nil || serr != nil || cerr != nil || len(raw) != 33 || !ed25519.Verify(ed25519.PublicKey(raw[1:]), canon, sig) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	r.mu.Lock()
	seen := r.nonces[aid+" "+f["nonce"]]
	r.nonces[aid+" "+f["nonce"]] = true
	r.mu.Unlock()
	if seen {
		http.Error(w, "seen before", http.StatusConflict)
		return
	}
	fn(w, aid, f)
}

func (r *Relay) allocate(w http.ResponseWriter, aid string, f map[string]string) {
	label := relayproto.NewAllocationToken()
	r.mu.Lock()
	r.commitments[label] = f["commitment"]
	r.bound[label] = aid
	r.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"allocation": label, "public_url": r.Server.URL + "/" + label})
}

func (r *Relay) secretHolds(label, secret string) (int, string) {
	r.mu.Lock()
	commitment, ok := r.commitments[label]
	r.mu.Unlock()
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	switch {
	case !ok:
		return http.StatusNotFound, "no such allocation"
	case err != nil || relay.Commitment(raw) != commitment:
		return http.StatusForbidden, "the secret does not match"
	}
	return 0, ""
}

func (r *Relay) bind(w http.ResponseWriter, aid string, f map[string]string) {
	if code, msg := r.secretHolds(f["allocation"], f["secret"]); code != 0 {
		http.Error(w, msg, code)
		return
	}
	r.mu.Lock()
	r.bound[f["allocation"]] = aid
	r.Binds++
	r.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"allocation": f["allocation"], "public_url": r.Server.URL + "/" + f["allocation"]})
}

func (r *Relay) release(w http.ResponseWriter, _ string, f map[string]string) {
	if code, msg := r.secretHolds(f["allocation"], f["secret"]); code != 0 {
		http.Error(w, msg, code)
		return
	}
	r.mu.Lock()
	delete(r.commitments, f["allocation"])
	delete(r.bound, f["allocation"])
	r.mu.Unlock()
	w.Write([]byte(`{"released":true}`))
}

// reserved are names nobody may claim, as a relay keeps them.
var reserved = map[string]bool{"login": true, "support": true, "admin": true, "www": true, "api": true}

// quota is how many names one identity may hold.
const quota = 3

func refuse(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func (r *Relay) claimName(w http.ResponseWriter, aid string, f map[string]string) {
	name := f["name"]
	r.mu.Lock()
	r.Claims++
	r.mu.Unlock()
	if reserved[name] {
		refuse(w, http.StatusForbidden, "reserved", "that name is reserved")
		return
	}
	r.mu.Lock()
	holder, held := r.names[name]
	count := 0
	for _, a := range r.names {
		if a == aid {
			count++
		}
	}
	switch {
	case held && holder != aid:
		r.mu.Unlock()
		refuse(w, http.StatusConflict, "taken", "that name is held by another identity")
		return
	case !held && count >= quota:
		r.mu.Unlock()
		refuse(w, http.StatusForbidden, "quota", "an identity may hold 3 names here")
		return
	case !held:
		r.names[name] = aid
	}
	r.mu.Unlock()
	port := r.Server.URL[strings.LastIndex(r.Server.URL, ":"):]
	json.NewEncoder(w).Encode(map[string]string{"name": name, "public_url": fmt.Sprintf("https://%s.%s%s/", name, r.service, port)})
}

// ClaimCount is how many claim-name requests the relay has answered.
func (r *Relay) ClaimCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Claims
}

// HoldName gives name to another identity, as if it had claimed it first.
func (r *Relay) HoldName(name, aid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names[name] = aid
}

func (r *Relay) releaseName(w http.ResponseWriter, aid string, f map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[f["name"]] != aid {
		http.Error(w, "not yours", http.StatusForbidden)
		return
	}
	delete(r.names, f["name"])
	w.Write([]byte(`{"released":true}`))
}

// PublishTXT puts a TXT record in the DNS this relay sees.
func (r *Relay) PublishTXT(name, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txt[name] = value
}

func (r *Relay) requestDomain(w http.ResponseWriter, aid string, f map[string]string) {
	d := strings.ToLower(f["domain"])
	r.mu.Lock()
	holder, held := r.domains[d]
	if !held {
		r.domains[d] = aid
	}
	r.mu.Unlock()
	if held && holder != aid {
		refuse(w, http.StatusConflict, "taken", "another identity has asked for that domain")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"domain": d, "verified": false,
		"txt_name": "_iarelay." + d, "txt_value": "iarelay-aid=" + aid})
}

func (r *Relay) verifyDomain(w http.ResponseWriter, aid string, f map[string]string) {
	d := strings.ToLower(f["domain"])
	r.mu.Lock()
	holder := r.domains[d]
	proved := r.txt["_iarelay."+d] == "iarelay-aid="+aid
	if holder == aid && proved {
		r.verified[d] = true
	}
	r.mu.Unlock()
	switch {
	case holder == "":
		refuse(w, http.StatusNotFound, "not_found", "request the domain first")
	case holder != aid:
		refuse(w, http.StatusForbidden, "not_yours", "another identity asked for that domain")
	case !proved:
		refuse(w, http.StatusForbidden, "unproven", "the TXT record is not there yet")
	default:
		json.NewEncoder(w).Encode(map[string]any{"domain": d, "verified": true, "public_url": "https://" + d + "/"})
	}
}
