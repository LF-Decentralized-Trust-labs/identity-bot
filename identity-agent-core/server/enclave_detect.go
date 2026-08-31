package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
	"identity-agent-core/update"
)

// KeyProtectionInfo is what this machine can protect a key with, and why we
// believe it. Mirrors secureenclave.Capability rather than embedding it, so the
// wire shape stays this package's to change.
type KeyProtectionInfo struct {
	Status string `json:"status"`
	Kind   string `json:"kind,omitempty"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`

	// RootKeyPermitted is the question everything downstream actually asks, so
	// it is answered here rather than left to each caller to re-derive from the
	// status and get subtly wrong.
	RootKeyPermitted bool `json:"rootKeyPermitted"`

	// SeedWrapped is whether THIS BUILD actually uses that hardware to protect
	// the root seed, which is a different question from whether the hardware
	// could — and the one that decides whether the seed on this disk is a file
	// anybody can copy.
	//
	// Reported beside RootKeyPermitted because the two disagree on most
	// platforms today, and reading the first as though it implied the second is
	// the mistake this field exists to make impossible. A machine can answer
	// usable, be permitted a root key, and store that seed in the clear.
	SeedWrapped bool `json:"seedWrapped"`

	// SeedWrapScheme names what protects it, and reads "none" when nothing
	// does — not empty, which is why omitempty never fires on it.
	SeedWrapScheme string `json:"seedWrapScheme,omitempty"`
}

// EnclaveStatusResponse describes the hardware security backing available on this device.
type EnclaveStatusResponse struct {
	HardwareBacked bool             `json:"hardwareBacked"`
	BackingType    string           `json:"backingType"`  // "tpm2", "secure_enclave", "dpapi", "keychain_software", "software"
	BackingLabel   string           `json:"backingLabel"` // Human-readable, e.g. "Apple Secure Enclave"
	TpmPresent     *bool            `json:"tpmPresent"`   // Windows/Linux only: TPM chip detected
	TpmEnabled     *bool            `json:"tpmEnabled"`   // Windows/Linux only: TPM accessible to OS
	Genuineness    *GenuinenessInfo `json:"genuineness,omitempty"`
	Freshness      *FreshnessInfo   `json:"freshness,omitempty"`
	Currency       *CurrencyInfo    `json:"currency,omitempty"`
	TrustAllowed   *bool            `json:"trustAllowed,omitempty"`

	// KeyProtection is what DetectCapability established about this machine's
	// ability to hold a key, which is a different question from the signer
	// fields above and was previously not reported anywhere.
	//
	// The two disagree on purpose. BackingType names the signer this build
	// happens to be using — on a phone that is the software fallback, because
	// the identity's keys live in the on-device KERI engine and not in that
	// signer. KeyProtection names what the HARDWARE can do, which is what
	// decides whether a root key may live here. A phone reporting a software
	// signer and StrongBox key protection is not a contradiction; it is those
	// two facts.
	KeyProtection *KeyProtectionInfo `json:"keyProtection,omitempty"`

	// SealedHardware is the bottom rung of the chain, and it is present only
	// where there is one — a machine whose memory the operator cannot read.
	//
	// The rest of this response is the same everywhere: which key store backs
	// the identity, whether the running binary matches what was signed, whether
	// it is current. An agent on somebody's desk answers those and stops. An
	// agent on hardware somebody else owns has one more thing to prove, and it
	// is the thing that matters most there — that the machine it runs on cannot
	// be looked into by whoever runs it.
	//
	// Absent is a real answer, not a gap. It means this agent makes no such
	// claim, which is correct for a laptop and is a red flag for anything
	// advertised as sealed.
	SealedHardware *SealedHardwareInfo `json:"sealedHardware,omitempty"`
}

// SealedHardwareInfo is what a sealed machine can prove about itself.
//
// Everything here comes from a report the CPU produced and signed. The agent
// reads it and passes it on; it cannot forge it and does not try to interpret
// it favourably — a reader gets the raw report and the fields that decide
// whether it means anything.
type SealedHardwareInfo struct {
	// Platform names the confidential-computing technology, e.g. "sev-snp".
	Platform string `json:"platform"`

	// Measurement is the launch measurement: a digest over the image, the
	// kernel, the initrd and the command line that were actually started. It is
	// what "running the right software" means here, and it is computed by the
	// hardware rather than claimed by the software.
	Measurement string `json:"measurement"`

	// ChipID identifies the physical processor. A report proves a genuine part
	// ran a given image; it never proves WHICH part somebody meant, so this is
	// the value an enrolment ceremony pins.
	ChipID string `json:"chip_id"`

	// DebugAllowed is the field a reader should look at first. A guest whose
	// policy permits debug can be inspected by the hypervisor — so a report can
	// be entirely valid and still describe a machine its operator can see into.
	DebugAllowed bool `json:"debug_allowed"`

	// SignerUnsigned reports a report signed by nothing, which is what a
	// software emulator produces.
	SignerUnsigned bool `json:"signer_unsigned"`

	// ReportedTCB is the firmware and microcode version the platform reports.
	// It moves when AMD ships an update, and it is part of the measurement's
	// meaning.
	ReportedTCB uint64 `json:"reported_tcb"`

	// CertificateChain is what lets a reader check the report's signature: the
	// certificate for this processor, then the intermediate, then the root,
	// each base64 DER.
	//
	// Served alongside the report so verification needs nothing but this
	// response and a root the reader already trusts. A reader that fetched the
	// certificate itself would tell its issuer — and anyone watching that
	// reader's network — which machine it is talking to.
	CertificateChain []string `json:"certificate_chain,omitempty"`

	// Report is the whole thing, base64, exactly as the hardware produced it.
	// Included so a verifier can check the signature itself rather than trust
	// the fields above, which this agent could in principle have made up.
	Report string `json:"report"`

	// BoundTo describes what REPORT_DATA covers, so a verifier can recompute it
	// rather than take the binding on trust.
	BoundTo string `json:"bound_to"`

	// ChainVerified says whether the report's signature has been checked back to
	// AMD's key distribution service.
	//
	// FALSE TODAY, always, and it is stated rather than omitted because its
	// absence is the difference between "this machine is sealed" and "this
	// machine says it is sealed". Without it, a report with the right shape and
	// the right measurement passes, and a party who controls the image controls
	// both.
	ChainVerified bool `json:"chain_verified"`

	// ChainNote explains the above in a sentence a person can read.
	ChainNote string `json:"chain_note,omitempty"`
}

// GenuinenessInfo reports running-binary attestation against the signed manifest.
// Trust gates on blake3_256; sha256 fields are interop-only.
type GenuinenessInfo struct {
	Status             string `json:"status"`
	RunningBlake3_256  string `json:"running_blake3_256,omitempty"`
	ExpectedBlake3_256 string `json:"expected_blake3_256,omitempty"`
	RunningSHA256      string `json:"running_sha256,omitempty"`
	ExpectedSHA256     string `json:"expected_sha256,omitempty"`
	InstalledVersion   string `json:"installed_version,omitempty"`
	ChainHash          string `json:"chain_hash,omitempty"`
	SignedChainHash    string `json:"signed_chain_hash,omitempty"`
	Message            string `json:"message,omitempty"`
}

// FreshnessInfo reports secure-enclave self-attestation cadence state.
type FreshnessInfo struct {
	Status         string `json:"status"`
	LastAttestedAt string `json:"last_attested_at,omitempty"`
	NextDueAt      string `json:"next_due_at,omitempty"`
	CadenceHours   int    `json:"cadence_hours,omitempty"`
	Message        string `json:"message,omitempty"`
}

// CurrencyInfo reports version currency (warn-only).
type CurrencyInfo struct {
	Status           string `json:"status"`
	InstalledVersion string `json:"installed_version,omitempty"`
	LatestVersion    string `json:"latest_version,omitempty"`
	Message          string `json:"message,omitempty"`
}

// detectEnclave is implemented per-platform in enclave_windows.go / enclave_linux.go / enclave_darwin.go

func (s *CoreServer) handleSecurityEnclave(w http.ResponseWriter, r *http.Request) {
	result := detectEnclave()

	// What the hardware can do, as established by asking it. Reported alongside
	// the signer rather than instead of it, because they answer different
	// questions and both are needed to explain a refusal to somebody.
	cap := secureenclave.DetectCapability()
	result.KeyProtection = &KeyProtectionInfo{
		Status:           string(cap.Status),
		Kind:             string(cap.Kind),
		Reason:           cap.Reason,
		Detail:           cap.Detail,
		RootKeyPermitted: cap.RootKeyPermitted(),
		SeedWrapped:      secureenclave.SeedWrapAvailable(),
		SeedWrapScheme:   secureenclave.SeedWrapScheme(),
	}

	if s.AttestationRunner != nil {
		// Only let a USABLE signer refine the platform detection. An
		// uninitializable signer (e.g. the Security-framework key create failing
		// in a mobile app context) must not downgrade the device's hardware
		// capability — on mobile the keys live in the on-device KERI engine, not
		// this signer, and reporting "no secure enclave" on an iPhone that has
		// one blocks onboarding with a falsehood.
		if signer := s.AttestationRunner.Signer(); signer != nil && signer.Available() {
			result.HardwareBacked = signer.Platform() != "software"
			result.BackingType = signer.Platform()
			result.BackingLabel = signer.Label()
		}
	}
	if s.TrustGate != nil {
		st := s.TrustGate.State()
		allowed := st.TrustAllowed
		result.TrustAllowed = &allowed
		result.Genuineness = genuinenessFromState(st)
		result.Freshness = freshnessFromState(st.Freshness)
		result.Currency = currencyFromState(st.Currency)
	} else if s.UpdateService != nil {
		g := s.UpdateService.Genuineness()
		result.Genuineness = &GenuinenessInfo{
			Status:             g.Status,
			RunningBlake3_256:  g.RunningBlake3_256,
			ExpectedBlake3_256: g.ExpectedBlake3_256,
			RunningSHA256:      g.RunningSHA256,
			ExpectedSHA256:     g.ExpectedSHA256,
			InstalledVersion:   g.InstalledVersion,
			Message:            g.Message,
		}
		c := s.UpdateService.Currency()
		result.Currency = &CurrencyInfo{
			Status:           c.Status,
			InstalledVersion: c.InstalledVersion,
			LatestVersion:    c.LatestVersion,
			Message:          c.Message,
		}
	}
	result.SealedHardware = sealedHardwareStatus(s.attestationBinding(), s.bindingOver(), s.snpCertificates)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// attestationBinding is what this agent asks the hardware to cover in
// REPORT_DATA, so a report cannot be lifted from one machine and presented by
// another.
//
// The agent's own identity where it has one, and its pairing identity before it
// does. Either way it is a value a verifier already holds, which is what makes
// the binding checkable rather than decorative.
func (s *CoreServer) attestationBinding() string {
	// The key this agent is reached over, where it has one.
	//
	// Preferred over any identifier, and not only because it is more useful. A
	// report bound to an identifier is a public oracle: anyone holding a list of
	// candidate identifiers can ask "is it this one?" of every instance, at one
	// query each. Saying that is safe because "you would have to know the
	// identifier already" is weaker than it sounds, since identifiers leak
	// through other channels and the list only grows.
	//
	// A transport fingerprint confirms nothing new, because it is already
	// visible to anyone who connects. It is also the thing a client actually
	// needs bound: it proves the sealed machine holds the key on THIS
	// connection, which is what stops a genuine report being replayed onto a
	// connection somebody else terminates.
	// The machine's own encryption keys, where it has an identity of its own.
	//
	// Preferred over the transport fingerprint now, because the fingerprint
	// cannot be checked by the party that needs to check it: a proxy in front
	// of this machine terminates the connection by design, so the certificate a
	// client sees is the proxy's and the two can never match. Binding the keys
	// instead says the private half of these keys is inside this sealed
	// machine, which a proxy cannot produce and does not need to be able to
	// terminate anything for the client to rely on.
	if s.boxIdentity != nil {
		if x, kem, err := iacrypto.AnchoredAgreementKeys(s.boxIdentity.InceptionEvent); err == nil {
			if binding, err := iacrypto.BoxKeyBinding(x, kem); err == nil {
				return binding
			}
		}
	}
	if s.transportIdentity != nil && s.transportIdentity.FingerprintB64 != "" {
		return s.transportIdentity.FingerprintB64
	}
	if s.DataStore != nil {
		if id, err := s.DataStore.GetIdentity(); err == nil && id != nil && id.AID != "" {
			return id.AID
		}
	}
	pairingOnce.Lock()
	defer pairingOnce.Unlock()
	if pairingOnce.offer != nil {
		return pairingOnce.offer.AID
	}
	return ""
}

// sealedHardwareStatus asks the hardware to attest to itself, and reports what
// came back without editorialising.
//
// Returns nil where there is no sealed hardware, which is the ordinary case for
// a desktop or a phone and is a real answer rather than a missing one.
//
// Every failure is reported as a note rather than swallowed. An agent that
// cannot produce a report when it is running on hardware that should be able to
// is exactly the case somebody needs to see — it is the difference between "not
// sealed" and "sealed but cannot prove it", and those call for different
// reactions.
// bindingScheme says how REPORT_DATA was computed without saying what over.
//
// Named separately so the distinction is visible: the construction is public
// and must be, or nothing could check it; the value is the thing being bound
// and is not ours to publish.
func bindingScheme(binding, over string) string {
	if binding == "" {
		return ""
	}
	if over == "" {
		over = "<the fingerprint of the certificate on this connection>"
	}
	return "blake3-256(IA-SNP-BIND-V1\n" + over + ")"
}

// bindingOver names what this agent bound, in the same terms a verifier would
// use to recompute it — and never the value itself.
//
// Said the wrong thing once already: the description was fixed text naming the
// transport certificate, so when the binding became something else the field
// described a construction the report did not use. A verifier following it
// would compute a value that could not match and read the mismatch as tampering.
func (s *CoreServer) bindingOver() string {
	if s.boxIdentity != nil {
		return "blake3-256(IA-BOX-KEYS-V1 || the agreement and encapsulation keys " +
			"this identifier commits to at inception)"
	}
	return ""
}

func sealedHardwareStatus(binding, over string, certs *snpCertificateChain) *SealedHardwareInfo {
	if !secureenclave.SNPAvailable() {
		return nil
	}
	info := &SealedHardwareInfo{
		Platform: "sev-snp",
		// The SCHEME, never the value.
		//
		// This said blake3-256(IA-SNP-BIND-V1\n<the value>) — with the value
		// itself in it. REPORT_DATA is one-way, so the report gives nothing
		// away; this field handed over the pre-image beside it, on an endpoint
		// open to anyone. Where the binding was an identity rather than a
		// transport key, that published the tenant's identifier.
		//
		// A verifier does not need to be told the value. It already holds what
		// the binding is over — the certificate on the connection it is using —
		// so it recomputes and compares. Being told would only help somebody
		// who does not have it.
		BoundTo:       bindingScheme(binding, over),
		ChainVerified: false,
		ChainNote: "the report's signature has not been checked against AMD's key " +
			"distribution service, so this attests what the machine says about itself. " +
			"Verify the report yourself against AMD's VCEK chain before relying on it.",
	}
	report, err := secureenclave.GetSNPReport(binding)
	if err != nil {
		info.ChainNote = "this machine reports sealed hardware but could not produce an " +
			"attestation report, so it cannot currently prove it: " + err.Error()
		return info
	}
	info.Report = base64.StdEncoding.EncodeToString(report.Raw)
	parsed, perr := secureenclave.ParseSNPReport(report.Raw)
	if perr != nil {
		info.ChainNote = "an attestation report was produced but could not be read: " + perr.Error()
		return info
	}
	info.Measurement = hex.EncodeToString(parsed.Measurement)
	info.ChipID = parsed.ChipIDHex()
	info.DebugAllowed = parsed.DebugAllowed()
	info.SignerUnsigned = parsed.Unsigned()
	info.ReportedTCB = parsed.ReportedTCB

	// The certificates that make the report checkable. Their absence is
	// reported rather than treated as a failure: the report is still the
	// machine's own account of itself, and saying so plainly is more useful
	// than withholding it.
	if certs != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		chain, cerr := certs.forReport(ctx, parsed.ChipID, parsed.ReportedTCB)
		if cerr != nil {
			info.ChainNote = "this machine could not obtain the certificates that vouch " +
				"for its report, so the report cannot yet be checked against the " +
				"manufacturer: " + cerr.Error()
			return info
		}
		for _, der := range chain {
			info.CertificateChain = append(info.CertificateChain, base64.StdEncoding.EncodeToString(der))
		}
		info.ChainNote = "the certificates that vouch for this report are included. " +
			"Check the report's signature against them, and check them against the " +
			"manufacturer root you already trust — do not take this machine's word for it."
	}
	return info
}

func genuinenessFromState(st secureenclave.State) *GenuinenessInfo {
	g := st.CodeGenuineness
	info := &GenuinenessInfo{
		Status:             g.Status,
		RunningBlake3_256:  g.RunningBlake3_256,
		ExpectedBlake3_256: g.ExpectedBlake3_256,
		RunningSHA256:      g.RunningSHA256,
		ExpectedSHA256:     g.ExpectedSHA256,
		InstalledVersion:   g.InstalledVersion,
		Message:            g.Message,
	}
	if st.EnclaveGenuineness.Status != "" {
		if info.Message != "" && st.EnclaveGenuineness.Message != "" {
			info.Message = info.Message + "; " + st.EnclaveGenuineness.Message
		} else if st.EnclaveGenuineness.Message != "" {
			info.Message = st.EnclaveGenuineness.Message
		}
		info.ChainHash = st.EnclaveGenuineness.ChainHash
		info.SignedChainHash = st.EnclaveGenuineness.SignedChain
		if st.EnclaveGenuineness.Status != "verified" {
			info.Status = st.EnclaveGenuineness.Status
		}
	}
	return info
}

func freshnessFromState(f secureenclave.FreshnessAxis) *FreshnessInfo {
	return &FreshnessInfo{
		Status:         f.Status,
		LastAttestedAt: f.LastAttestedAt,
		NextDueAt:      f.NextDueAt,
		CadenceHours:   f.CadenceHours,
		Message:        f.Message,
	}
}

func currencyFromState(c update.CurrencyAxis) *CurrencyInfo {
	return &CurrencyInfo{
		Status:           c.Status,
		InstalledVersion: c.InstalledVersion,
		LatestVersion:    c.LatestVersion,
		Message:          c.Message,
	}
}
