package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// The single gate for the dumb-router scanner. The scanner forwards the raw scanned URL here;
// Go fetches the Ask, reads its action `t`, and dispatches to the hardcoded handler. No
// per-transaction logic lives in the scanner.
//   POST /api/scan/decode  {url}                  -> GenericPreview (what is being asked)
//   POST /api/scan/execute {url, approved, tier}  -> result
func (s *CoreServer) mountScanRoutes(r chi.Router) {
	r.Post("/api/scan/decode", s.handleScanDecode)
	r.Post("/api/scan/execute", s.handleScanExecute)
}

// buildAskContext parses a scanned Ask pointer (.../i/{token}), fetches the signed Ask, and
// reads its action `t`. The base is the URL minus the trailing /i/{token} WITH the path prefix
// preserved (so path-based relay tunnels like https://host/green-oak-87 work).
func (s *CoreServer) buildAskContext(rawURL string) (AskContext, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return AskContext{}, fmt.Errorf("bad url: %w", err)
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 2 || segs[len(segs)-2] != "i" {
		return AskContext{}, fmt.Errorf("not an Ask pointer (expected .../i/{token})")
	}
	token := segs[len(segs)-1]
	basePath := strings.Join(segs[:len(segs)-2], "/")
	base := u.Scheme + "://" + u.Host
	if basePath != "" {
		base += "/" + basePath
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return AskContext{}, fmt.Errorf("fetch Ask: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return AskContext{}, fmt.Errorf("fetch Ask: status %d", resp.StatusCode)
	}
	askBytes, _ := io.ReadAll(resp.Body)
	t, err := askActionType(askBytes)
	if err != nil {
		return AskContext{}, fmt.Errorf("read action t: %w", err)
	}
	return AskContext{URL: rawURL, Base: base, Token: token, AskBytes: askBytes, T: t}, nil
}

func (s *CoreServer) handleScanDecode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	ctx, err := s.buildAskContext(body.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Base-layer verification: a base-layer-signed Ask must have a valid signature.
	if verr := s.verifyAskSignature(ctx.AskBytes); verr != nil {
		http.Error(w, verr.Error(), http.StatusUnauthorized)
		return
	}
	h, ok := lookupAsk(ctx.T)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown Ask action t=%d", ctx.T), http.StatusNotImplemented)
		return
	}
	preview, err := h.Preview(s, ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Bind this preview to the exact bytes it describes. The client echoes this
	// back on execute so we can prove we are acting on the approved document.
	preview.AskDigest = askDigest(ctx.AskBytes)
	scanWriteJSON(w, preview)
}

func (s *CoreServer) handleScanExecute(w http.ResponseWriter, r *http.Request) {
	// Surface handler panics as a readable 500 body (mobile has no attached
	// console; the recovered stack is the only way to see what broke).
	defer func() {
		if rec := recover(); rec != nil {
			msg := fmt.Sprintf("scan execute panic: %v\n%s", rec, debug.Stack())
			log.Printf("[identity-agent-core] %s", msg)
			http.Error(w, msg, http.StatusInternalServerError)
		}
	}()
	var body struct {
		URL       string `json:"url"`
		Approved  bool   `json:"approved"`
		Tier      string `json:"tier"`
		AskDigest string `json:"ask_digest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	ctx, err := s.buildAskContext(body.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Base-layer verification: a base-layer-signed Ask must have a valid signature.
	if verr := s.verifyAskSignature(ctx.AskBytes); verr != nil {
		http.Error(w, verr.Error(), http.StatusUnauthorized)
		return
	}
	// Consent integrity: refuse unless these are the bytes the user approved.
	// A valid signature is not enough — the same minter can sign two different
	// Asks and serve one at decode and another at execute.
	if cerr := bindConsent(body.AskDigest, ctx.AskBytes); cerr != nil {
		http.Error(w, cerr.Error(), http.StatusConflict)
		return
	}
	h, ok := lookupAsk(ctx.T)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown Ask action t=%d", ctx.T), http.StatusNotImplemented)
		return
	}
	result, err := h.Execute(s, ctx, ScanDecision{Approved: body.Approved, Tier: body.Tier})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	scanWriteJSON(w, result)
}

func scanWriteJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
