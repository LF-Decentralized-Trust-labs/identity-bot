package server

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Obtaining the certificates that let somebody else check this machine's
// attestation report.
//
// A report is signed by a key derived inside the processor, and the certificate
// vouching for that key is issued by the manufacturer. Without it a report is
// unverifiable: a reader can see what the machine claims and has no way to tell
// it apart from bytes anyone assembled.
//
// The agent fetches its own certificate and serves it alongside the report, so
// a reader verifies everything offline against a manufacturer root it already
// trusts. The alternative — the reader fetching the certificate itself — works
// and is worse: it tells the manufacturer, and anyone watching the reader's
// network, exactly which machine that reader is talking to. Asking on our own
// behalf reveals only that this processor exists, which its maker already knows.

// The manufacturer's key distribution service.
const amdKDSBase = "https://kdsintf.amd.com/vcek/v1"

// amdKDSBaseForTest points the fetches at a local server in tests, so the suite
// neither depends on the real service being reachable nor adds load to it.
var amdKDSBaseForTest = amdKDSBase

// snpCertificateChain fetches and remembers the chain for one processor.
//
// Cached on disk as well as in memory: the certificate is fixed for a given
// processor at a given firmware level, and an agent that asked again on every
// restart would be making a request it already knows the answer to.
type snpCertificateChain struct {
	// Product is the processor family name the service indexes by.
	//
	// NOT the marketing name of the part, which is the trap here. The service
	// serves Milan, Genoa and Turin. Parts sold as Siena and Bergamo are
	// covered by the Genoa chain and 404 under their own names, so a host on
	// one of those must still ask for Genoa.
	Product string

	// CacheDir is where the fetched certificates are kept.
	CacheDir string

	// HTTPClient is injectable so tests never reach the network.
	HTTPClient *http.Client

	mu    sync.Mutex
	chain [][]byte
}

func newSNPCertificateChain(product, cacheDir string) *snpCertificateChain {
	if product == "" {
		product = "Genoa"
	}
	return &snpCertificateChain{
		Product:    product,
		CacheDir:   cacheDir,
		HTTPClient: &http.Client{Timeout: 20 * time.Second},
	}
}

// forReport returns the chain that vouches for a report, leaf first.
//
// The leaf is specific to this processor AND its current firmware level, so a
// firmware update legitimately changes which certificate is needed. The cache
// is keyed on both for that reason: keying on the processor alone would serve a
// stale certificate after an update, and the symptom — every signature failing
// — looks nothing like its cause.
func (c *snpCertificateChain) forReport(ctx context.Context, chipID []byte, reportedTCB uint64) ([][]byte, error) {
	bl, tee, snp, ucode := decodeTCBParts(reportedTCB)
	key := fmt.Sprintf("%s-%s-%d.%d.%d.%d", c.Product, hex.EncodeToString(chipID)[:16], bl, tee, snp, ucode)

	c.mu.Lock()
	if c.chain != nil {
		defer c.mu.Unlock()
		return c.chain, nil
	}
	c.mu.Unlock()

	if cached, err := c.readCache(key); err == nil && len(cached) > 0 {
		c.mu.Lock()
		c.chain = cached
		c.mu.Unlock()
		return cached, nil
	}

	leaf, err := c.fetch(ctx, fmt.Sprintf("%s/%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d",
		amdKDSBaseForTest, c.Product, hex.EncodeToString(chipID), bl, tee, snp, ucode))
	if err != nil {
		return nil, fmt.Errorf("could not obtain this processor's certificate: %w", err)
	}
	rest, err := c.fetch(ctx, fmt.Sprintf("%s/%s/cert_chain", amdKDSBaseForTest, c.Product))
	if err != nil {
		return nil, fmt.Errorf("could not obtain the manufacturer's certificate chain: %w", err)
	}

	chain := [][]byte{leaf}
	for block, remaining := pem.Decode(rest); block != nil; block, remaining = pem.Decode(remaining) {
		chain = append(chain, block.Bytes)
	}
	if len(chain) < 3 {
		return nil, fmt.Errorf("the chain has %d certificates; a processor certificate, an "+
			"intermediate and a root are all needed", len(chain))
	}

	c.writeCache(key, chain)
	c.mu.Lock()
	c.chain = chain
	c.mu.Unlock()
	return chain, nil
}

func (c *snpCertificateChain) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
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
		// 404 is worth naming, because it is almost always the product name
		// rather than the processor.
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("no certificate at %s (404) — if this part is sold as "+
				"Siena or Bergamo, the family to ask for is Genoa", url)
		}
		return nil, fmt.Errorf("the certificate service returned %d", resp.StatusCode)
	}
	return body, nil
}

func (c *snpCertificateChain) cachePath(key string) string {
	return filepath.Join(c.CacheDir, "snp-certificates", key+".pem")
}

func (c *snpCertificateChain) readCache(key string) ([][]byte, error) {
	if c.CacheDir == "" {
		return nil, fmt.Errorf("no cache directory")
	}
	raw, err := os.ReadFile(c.cachePath(key))
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		out = append(out, block.Bytes)
	}
	return out, nil
}

// writeCache is best effort. A cache that cannot be written costs a request on
// the next start; failing the attestation over it would trade something that
// matters for something that does not.
func (c *snpCertificateChain) writeCache(key string, chain [][]byte) {
	if c.CacheDir == "" {
		return
	}
	path := c.cachePath(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	var buf []byte
	for _, der := range chain {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// decodeTCBParts splits the reported firmware level into the four fields the
// certificate is indexed by.
//
// Asking for the wrong one returns a certificate that will not verify the
// report, which reads as tampering rather than as a lookup mistake.
func decodeTCBParts(tcb uint64) (bl, tee, snp, ucode uint8) {
	return uint8(tcb), uint8(tcb >> 8), uint8(tcb >> 48), uint8(tcb >> 56)
}
