package server

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

// Publishing what the machine can prove about itself, to anyone who asks.
//
// A client verifies a machine IN ORDER TO DECIDE whether to trust it. At that
// moment it is not the owner and holds no owner key, so requiring the owner key
// to read the evidence means that by the time you can ask, you have already
// trusted the thing you wanted to check. That is circular, and it is why this
// endpoint is open.
//
// It also fixes a second problem with the same change: the evidence used to be
// available only on the pairing offer, which correctly stops answering once an
// agent has an owner — so an owned agent could no longer prove anything about
// its own hardware, including to the person who owns it.
//
// WHAT THIS DISCLOSES, and why it is publishable:
//
//   - The launch measurement is identical for every instance of an image. It
//     says which software is running, which is published anyway so that anyone
//     can rebuild the image and check it.
//   - The chip identifier names the physical processor, which every tenant on
//     that machine shares. It says which machine answered, never which tenant.
//   - REPORT_DATA is one-way, and nothing beside it gives the pre-image away.
//     That second clause is not a detail: this response once described the
//     binding as blake3-256(...<the value>...), which handed over on an open
//     endpoint exactly what the one-way function was protecting. The scheme is
//     published; the value is not. A verifier already holds what the binding is
//     over and recomputes it.
//
// That last one is a confirmation oracle, and calling it harmless because "you
// would have to know the identifier already" is weaker than it sounds — an
// adversary who collects identifiers elsewhere can ask this question of every
// instance cheaply. The fix is to bind reports to the transport key rather than
// to an identity, since a transport key is already visible to anyone who
// connects and so confirms nothing new. Until that lands, the oracle is real
// and is written down rather than explained away.
//
// Deliberately NOT the whole enclave status. That carries key backing,
// genuineness and trust-gate state, which are the owner's business and are not
// needed to decide whether a machine is sealed.

// publicAttestation is the evidence a stranger needs, and nothing else.
type publicAttestation struct {
	Platform    string `json:"platform"`
	Measurement string `json:"measurement"`
	ChipID      string `json:"chip_id"`

	// DebugAllowed reports a guest whose memory the host may read. A report can
	// be genuine, chain correctly, and describe a machine that is sealed in name
	// only, so this is published beside the rest rather than left to be inferred.
	DebugAllowed bool   `json:"debug_allowed"`
	ReportedTCB  uint64 `json:"reported_tcb"`

	// Report is the signed report, base64, exactly as the hardware produced it.
	Report string `json:"report"`

	// CertificateChain is what makes the report checkable: the certificate for
	// this processor, then the intermediate, then the root, each base64 DER.
	// Without it the report is an assertion rather than evidence.
	CertificateChain []string `json:"certificate_chain,omitempty"`

	// BoundTo describes how REPORT_DATA was computed, so a verifier recomputes
	// it rather than trusting this description of it.
	BoundTo string `json:"bound_to"`

	// Note says plainly what has and has not been established, so a reader who
	// stops here is not left with a more favourable impression than the
	// evidence supports.
	Note string `json:"note,omitempty"`
}

// handlePublicAttestation serves the evidence, or explains why it cannot.
func (s *CoreServer) handlePublicAttestation(w http.ResponseWriter, r *http.Request) {
	if !s.attestationLimiter.allow(callerIP(r)) {
		w.Header().Set("Retry-After", "1")
		writeAttestationError(w, http.StatusTooManyRequests, "rate_limited",
			"too many attestation requests from this address")
		return
	}

	info := s.cachedAttestation()
	if info == nil {
		writeAttestationError(w, http.StatusNotFound, "not_sealed_hardware",
			"this agent does not run on sealed hardware, so it has no attestation to give. "+
				"That is the ordinary case for an agent on a machine its user owns.")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// The report changes only when the binding does, and it is public, so a
	// short shared cache is safe and takes load off the firmware call.
	w.Header().Set("Cache-Control", "public, max-age=30")
	_ = json.NewEncoder(w).Encode(info)
}

// cachedAttestation produces the evidence at most once every few seconds.
//
// Producing a report is a firmware call, and this endpoint is open to anyone.
// Without this, an unauthenticated caller could drive firmware work at whatever
// rate they liked, on a machine whose whole purpose is to serve one tenant.
func (s *CoreServer) cachedAttestation() *publicAttestation {
	const ttl = 5 * time.Second

	s.attestationMu.Lock()
	defer s.attestationMu.Unlock()
	if s.attestationCached != nil && time.Now().Before(s.attestationExpires) {
		return s.attestationCached
	}

	sh := sealedHardwareStatus(s.attestationBinding(), s.bindingOver(), s.snpCertificates)
	if sh == nil {
		s.attestationCached = nil
		s.attestationExpires = time.Now().Add(ttl)
		return nil
	}

	out := &publicAttestation{
		Platform:         sh.Platform,
		Measurement:      sh.Measurement,
		ChipID:           sh.ChipID,
		DebugAllowed:     sh.DebugAllowed,
		ReportedTCB:      sh.ReportedTCB,
		Report:           sh.Report,
		CertificateChain: sh.CertificateChain,
		BoundTo:          sh.BoundTo,
		Note:             sh.ChainNote,
	}
	s.attestationCached = out
	s.attestationExpires = time.Now().Add(ttl)
	return out
}

// attestationRateLimiter bounds how often one address may ask.
//
// Deliberately crude. The point is not to stop a determined adversary — they
// have many addresses — but to keep one caller from turning an open endpoint
// into firmware load or, once certificates are fetched rather than bundled,
// into requests against somebody else's service.
type attestationRateLimiter struct {
	mu      sync.Mutex
	seen    map[string]*rateBucket
	perMin  int
	lastGC  time.Time
	maxKeys int
}

type rateBucket struct {
	count int
	start time.Time
}

func newAttestationRateLimiter(perMinute int) *attestationRateLimiter {
	return &attestationRateLimiter{
		seen:    map[string]*rateBucket{},
		perMin:  perMinute,
		lastGC:  time.Now(),
		maxKeys: 10000,
	}
}

func (l *attestationRateLimiter) allow(key string) bool {
	if l == nil {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Forget old callers. Without this the map is a slow leak an
	// unauthenticated caller controls the size of.
	if now.Sub(l.lastGC) > time.Minute || len(l.seen) > l.maxKeys {
		for k, b := range l.seen {
			if now.Sub(b.start) > time.Minute {
				delete(l.seen, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.seen[key]
	if !ok || now.Sub(b.start) > time.Minute {
		l.seen[key] = &rateBucket{count: 1, start: now}
		return true
	}
	if b.count >= l.perMin {
		return false
	}
	b.count++
	return true
}

// callerIP identifies the caller for rate limiting only.
//
// Not used for any access decision, so a forged forwarding header costs the
// forger their own quota and buys nothing.
func callerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeAttestationError(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "detail": detail})
}
