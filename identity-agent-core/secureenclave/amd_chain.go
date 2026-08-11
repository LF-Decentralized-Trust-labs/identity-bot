package secureenclave

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Proving a report came from a genuine AMD part.
//
// Without this, an attestation says "some machine ran the expected image" and
// stops. Anything can produce those bytes — the measurement is a value the
// producer chooses, and a software emulator producing a well-formed report with
// the right measurement passes every other check in this package. The signature
// is the only thing that makes a report evidence rather than an assertion, and
// checking it back to AMD's root is what turns "this machine says it is sealed"
// into "this machine is sealed".
//
// WHO SHOULD RUN THIS. Whoever is deciding to trust the machine. An operator
// verifying its own hardware proves nothing to anybody else: it is the party
// the sealed-VM model exists to exclude, vouching for itself. The check belongs
// on the side of whoever is about to hand something over — an owner adopting an
// instance, a counterparty relying on one — and this lives here, in the agent
// core, so that side can run it without trusting anyone's summary of it.
//
// The facts below were established against real hardware and AMD's live
// service rather than from documentation, because two of them are not what the
// documentation leads you to expect.

// kdsBase is AMD's key distribution service.
const kdsBase = "https://kdsintf.amd.com/vcek/v1"

// ErrChainUnavailable means the check could not be run — not that it failed.
//
// The distinction matters more than it looks. A report whose signature does not
// verify is evidence of a forgery and the instance must not be trusted. A report
// that could not be checked because AMD was unreachable, or DNS was down, or the
// product name in the configuration is wrong, is evidence of nothing at all.
//
// Collapsing the two makes a third party's outage indistinguishable from an
// attack, and the response to an attack — stop the instance — is then triggered
// by someone else's bad morning. Callers decide what to do about not knowing;
// they cannot decide well if the error does not tell them which case they are in.
var ErrChainUnavailable = errors.New("AMD's certificate service could not be reached, so provenance is unknown rather than bad")

// Signature layout inside an SEV-SNP report.
const (
	reportTCBOffset       = 0x180 // uint64, little-endian
	reportChipIDOffset    = 0x1A0 // 64 bytes
	reportSignatureOffset = 0x2A0 // r then s, 72 bytes each
	reportSignedLength    = 0x2A0 // everything before the signature is signed
	ecdsaComponentLength  = 72
)

// AMDKDSVerifier checks a report's signature against AMD's certificate chain.
type AMDKDSVerifier struct {
	// Product is the name AMD's service knows this CPU family by.
	//
	// It is NOT the marketing name of the part, and that is the trap. Probed
	// directly against the live service:
	//
	//   Milan    200        Bergamo  404
	//   Genoa    200        Siena    404
	//   Turin    200
	//
	// The host here is an EPYC 8534P, which is Siena — and Siena is not a
	// product AMD's service knows. Siena and Bergamo are Zen 4c parts in the
	// Genoa family and are served by the Genoa chain. Verified end to end: a
	// VCEK fetched from the Genoa endpoint for this machine's chip id verifies
	// against the Genoa root.
	//
	// So the default is Genoa, and a host on Milan or Turin sets it.
	Product string

	// HTTPClient is injectable so tests never reach AMD.
	HTTPClient *http.Client

	// BaseURL overrides AMD's service. Empty means the real one; tests point it
	// at a local server serving recorded responses, so the suite neither depends
	// on AMD being reachable nor adds load to it.
	BaseURL string

	mu    sync.Mutex
	roots *x509.CertPool
	vceks map[string]*x509.Certificate
}

// NewAMDKDSVerifier builds a verifier with a sensible default product.
// base is where certificates are fetched from.
func (v *AMDKDSVerifier) base() string {
	if v.BaseURL != "" {
		return v.BaseURL
	}
	return kdsBase
}

func NewAMDKDSVerifier(product string) *AMDKDSVerifier {
	if product == "" {
		product = "Genoa"
	}
	return &AMDKDSVerifier{
		Product:    product,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		vceks:      map[string]*x509.Certificate{},
	}
}

// VerifyChain returns nil when the report was signed by a genuine AMD part.
func (v *AMDKDSVerifier) VerifyChain(ctx context.Context, report []byte) error {
	if len(report) < ReportSize {
		return fmt.Errorf("report is %d bytes, an SNP report is %d", len(report), ReportSize)
	}

	chipID := hex.EncodeToString(report[reportChipIDOffset : reportChipIDOffset+64])
	bl, tee, snp, ucode := decodeTCB(report[reportTCBOffset : reportTCBOffset+8])

	vcek, err := v.vcek(ctx, chipID, bl, tee, snp, ucode)
	if err != nil {
		return err
	}

	roots, err := v.rootPool(ctx)
	if err != nil {
		return err
	}
	// The certificate must chain to AMD's root before its key is worth using.
	// Verifying the signature against an unverified certificate would prove
	// only that whoever produced the report also produced the certificate.
	if _, err := vcek.Verify(x509.VerifyOptions{
		Roots: roots,
		// AMD's intermediate and root carry no extended key usage, and the
		// certificate is not for TLS. Constraining to a usage AMD does not
		// assert would reject every valid chain.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("the report's certificate does not chain to AMD's root: %w", err)
	}

	pub, ok := vcek.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("the certificate's key is %T, not the ECDSA key an SNP report is signed with", vcek.PublicKey)
	}

	r, s := reportSignature(report)
	// SHA-384, because the curve is P-384. Pairing a P-384 key with SHA-256
	// would verify nothing while appearing to work.
	digest := sha512.Sum384(report[:reportSignedLength])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return fmt.Errorf("the report's signature does not verify against the certificate AMD issued for chip %s… — it was not produced by that part", chipID[:16])
	}
	return nil
}

// reportSignature reads r and s out of a report.
//
// THE TRAP: they are stored LITTLE-endian, in fixed 72-byte fields, and Go's
// big.Int reads big-endian. Feeding the bytes in as they lie produces two
// enormous wrong integers, ecdsa.Verify returns false, and the failure looks
// exactly like a forged report. Nothing about the symptom points at byte order.
func reportSignature(report []byte) (r, s *big.Int) {
	raw := report[reportSignatureOffset:]
	return beFromLE(raw[:ecdsaComponentLength]),
		beFromLE(raw[ecdsaComponentLength : 2*ecdsaComponentLength])
}

func beFromLE(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i, b := range le {
		be[len(le)-1-i] = b
	}
	return new(big.Int).SetBytes(be)
}

// decodeTCB reads the four security patch levels the certificate is issued
// against. A report is signed by a key specific to this exact firmware state, so
// asking for the wrong one returns a certificate that will not verify.
//
// Confirmed against this machine: 0900000000001515 decodes to bl=9, tee=0,
// snp=21, ucode=21, and that query returned a certificate.
func decodeTCB(tcb []byte) (bl, tee, snp, ucode uint8) {
	return tcb[0], tcb[1], tcb[6], tcb[7]
}

// vcek fetches, and remembers, the certificate for one chip at one TCB.
//
// Cached because it is stable for a given chip and firmware state, and because
// resuming a host full of instances would otherwise hit AMD once per instance
// in a burst — which is both rude and a reason for the service to start
// refusing.
func (v *AMDKDSVerifier) vcek(ctx context.Context, chipID string, bl, tee, snp, ucode uint8) (*x509.Certificate, error) {
	key := fmt.Sprintf("%s/%d.%d.%d.%d", chipID, bl, tee, snp, ucode)

	v.mu.Lock()
	if c, ok := v.vceks[key]; ok {
		v.mu.Unlock()
		return c, nil
	}
	v.mu.Unlock()

	url := fmt.Sprintf("%s/%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d",
		v.base(), v.Product, chipID, bl, tee, snp, ucode)
	der, err := v.fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: could not obtain AMD's certificate for this part: %v", ErrChainUnavailable, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		// Unusable rather than damning: something answered and it was not a
		// certificate, which says nothing about the report.
		return nil, fmt.Errorf("%w: AMD returned something that is not a certificate: %v", ErrChainUnavailable, err)
	}

	v.mu.Lock()
	v.vceks[key] = cert
	v.mu.Unlock()
	return cert, nil
}

// rootPool fetches AMD's certificate chain for this product and keeps it.
func (v *AMDKDSVerifier) rootPool(ctx context.Context) (*x509.CertPool, error) {
	v.mu.Lock()
	if v.roots != nil {
		defer v.mu.Unlock()
		return v.roots, nil
	}
	v.mu.Unlock()

	raw, err := v.fetch(ctx, fmt.Sprintf("%s/%s/cert_chain", v.base(), v.Product))
	if err != nil {
		return nil, fmt.Errorf("%w: could not obtain AMD's certificate chain for %s: %v", ErrChainUnavailable, v.Product, err)
	}
	pool := x509.NewCertPool()
	// The chain is PEM: the intermediate (SEV-<product>) then the root
	// (ARK-<product>). Both go in the pool — the intermediate is needed to
	// build a path from the VCEK, and x509.Verify will not fetch it.
	rest := raw
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("%w: AMD's chain contains something unparseable: %v", ErrChainUnavailable, perr)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: AMD's chain for %s contained no certificates", ErrChainUnavailable, v.Product)
	}

	v.mu.Lock()
	v.roots = pool
	v.mu.Unlock()
	return pool, nil
}

func (v *AMDKDSVerifier) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := v.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// 404 is the one worth naming, because it is almost always the product
		// name rather than the chip: AMD serves Milan, Genoa and Turin, and
		// does NOT serve Bergamo or Siena — those parts are covered by Genoa.
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("AMD has no certificate at %s (404). If this host is Siena or Bergamo, the product is \"Genoa\"", url)
		}
		return nil, fmt.Errorf("AMD returned %d for %s: %s", resp.StatusCode, url, bytes.TrimSpace(body))
	}
	return body, nil
}
