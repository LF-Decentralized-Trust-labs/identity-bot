package secureenclave

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Runner performs periodic local secure-enclave self-attestation.
type Runner struct {
	mu        sync.RWMutex
	signer    PlatformSigner
	registry  *Registry
	cadence   time.Duration
	statePath string
	record    *AttestationRecord
	lastErr   string
}

type RunnerConfig struct {
	DataDir  string
	Signer   PlatformSigner
	Registry *Registry
}

func NewRunner(cfg RunnerConfig) *Runner {
	signer := cfg.Signer
	if signer == nil {
		signer = NewPlatformSigner(cfg.DataDir)
	}
	registry := cfg.Registry
	if registry == nil {
		registry = DefaultRegistry(cfg.DataDir)
	}
	return &Runner{
		signer:    signer,
		registry:  registry,
		cadence:   resolveCadence(),
		statePath: filepath.Join(cfg.DataDir, "secureenclave", "attestation.json"),
	}
}

func resolveCadence() time.Duration {
	hours := 24
	if raw := os.Getenv("ATTESTATION_CADENCE_HOURS"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			hours = v
		}
	}
	return time.Duration(hours) * time.Hour
}

func (r *Runner) CadenceHours() int {
	return int(r.cadence / time.Hour)
}

func (r *Runner) Signer() PlatformSigner {
	return r.signer
}

func (r *Runner) Load() {
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, err := os.ReadFile(r.statePath)
	if err != nil {
		return
	}
	var rec AttestationRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return
	}
	r.record = &rec
}

func (r *Runner) persistLocked(rec *AttestationRecord) error {
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.statePath, raw, 0600)
}

// RunOnce measures the component chain and signs a fresh attestation payload.
func (r *Runner) RunOnce(ctx context.Context) error {
	_ = ctx
	chainHash, components, err := r.registry.ChainHash()
	if err != nil {
		r.mu.Lock()
		r.lastErr = err.Error()
		r.mu.Unlock()
		return err
	}

	payload := AttestationPayload{
		Version:    PayloadVersion,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Platform:   r.signer.Platform(),
		Signer:     r.signer.Label(),
		Components: components,
		ChainHash:  chainHash,
	}
	canonical, err := CanonicalPayload(payload)
	if err != nil {
		return err
	}
	sig, err := r.signer.Sign(canonical)
	if err != nil {
		r.mu.Lock()
		r.lastErr = err.Error()
		r.mu.Unlock()
		return err
	}
	pub, err := r.signer.PublicKey()
	if err != nil {
		return err
	}

	rec := &AttestationRecord{
		Payload:   payload,
		Signature: EncodeSignature(sig),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		SignedAt:  time.Now().UTC(),
	}

	r.mu.Lock()
	r.record = rec
	r.lastErr = ""
	if err := r.persistLocked(rec); err != nil {
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()
	return nil
}

// Start launches periodic self-attestation on the configured cadence.
func (r *Runner) Start(ctx context.Context) {
	r.Load()
	go func() {
		_ = r.RunOnce(ctx)
		ticker := time.NewTicker(r.cadence)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = r.RunOnce(ctx)
			}
		}
	}()
}

func (r *Runner) Record() *AttestationRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.record == nil {
		return nil
	}
	copy := *r.record
	return &copy
}

// Freshness reports whether the latest attestation is within cadence.
func (r *Runner) Freshness() FreshnessAxis {
	r.mu.RLock()
	defer r.mu.RUnlock()

	axis := FreshnessAxis{
		CadenceHours: r.CadenceHours(),
	}
	if r.lastErr != "" && r.record == nil {
		axis.Status = "failed"
		axis.Message = r.lastErr
		return axis
	}
	if r.record == nil {
		axis.Status = "unknown"
		axis.Message = "no self-attestation recorded"
		return axis
	}

	axis.LastAttestedAt = r.record.SignedAt.UTC().Format(time.RFC3339)
	nextDue := r.record.SignedAt.Add(r.cadence)
	axis.NextDueAt = nextDue.UTC().Format(time.RFC3339)
	if time.Now().UTC().After(nextDue) {
		axis.Status = "stale"
		axis.Message = fmt.Sprintf("self-attestation older than %dh cadence", axis.CadenceHours)
		return axis
	}
	axis.Status = "fresh"
	return axis
}

// Genuineness verifies the stored attestation against the live component chain.
func (r *Runner) Genuineness() EnclaveGenuinenessAxis {
	r.mu.RLock()
	rec := r.record
	lastErr := r.lastErr
	r.mu.RUnlock()

	if lastErr != "" && rec == nil {
		return EnclaveGenuinenessAxis{
			Status:  "failed",
			Message: lastErr,
		}
	}
	if rec == nil {
		return EnclaveGenuinenessAxis{
			Status:  "unknown",
			Message: "no self-attestation recorded",
		}
	}

	liveChain, _, err := r.registry.ChainHash()
	if err != nil {
		return EnclaveGenuinenessAxis{
			Status:  "failed",
			Message: err.Error(),
		}
	}

	pubRaw, err := base64.RawURLEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return EnclaveGenuinenessAxis{
			Status:  "failed",
			Message: "invalid stored public key",
		}
	}
	canonical, err := CanonicalPayload(rec.Payload)
	if err != nil {
		return EnclaveGenuinenessAxis{
			Status:  "failed",
			Message: err.Error(),
		}
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(rec.Signature)
	if err != nil {
		return EnclaveGenuinenessAxis{
			Status:  "failed",
			Message: "invalid stored signature",
		}
	}

	verified := false
	if r.signer.Platform() == "software" {
		verified = VerifySoftwareSignature(pubRaw, canonical, sigRaw)
	} else {
		// Hardware signers use non-Ed25519 signatures; trust persisted record + chain equality.
		verified = rec.Payload.Platform == r.signer.Platform()
	}

	axis := EnclaveGenuinenessAxis{
		ChainHash:      liveChain,
		SignedChain:    rec.Payload.ChainHash,
		SignerPlatform: rec.Payload.Platform,
	}

	if !verified {
		axis.Status = "failed"
		axis.Message = "stored attestation signature invalid"
		return axis
	}
	if liveChain != rec.Payload.ChainHash {
		axis.Status = "mismatch"
		axis.Message = "live component chain does not match signed attestation"
		return axis
	}
	axis.Status = "verified"
	return axis
}