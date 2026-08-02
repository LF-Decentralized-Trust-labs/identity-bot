package sandbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"identity-agent-core/backup"
)

// vaultFileName is the encrypted-at-rest credential store. It deliberately does
// NOT reuse "credentials.json": that filename belongs to the verifiable-credential
// (ACDC) store in the same data directory, and the previous plaintext vault could
// clobber it. The vault now owns its own file, sealed with AES-256-GCM under a
// key derived from the identity's root seed (never stored on disk).
const vaultFileName = "service_credentials.enc"

// vaultEnvelope is the on-disk format of the encrypted vault.
type vaultEnvelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// VaultKeyProvider returns the 32-byte vault encryption key. It is supplied by
// the host server (derived from the identity root seed) so this package stays
// decoupled from key storage. It may fail until identity setup has completed.
type VaultKeyProvider func() ([]byte, error)

type CredentialEntry struct {
	Service      string            `json:"service"`
	MatchDomains []string          `json:"match_domains"`
	Headers      map[string]string `json:"headers"`
}

type CredentialVault struct {
	dataDir     string
	entries     []CredentialEntry // decrypted vault entries (authoritative)
	fallback    []CredentialEntry // read-only entries extracted from settings.json
	keyProvider VaultKeyProvider
	key         []byte // cached vault key once successfully provided
	loaded      bool
	loadErr     error // set when the vault exists but cannot be opened — fail closed
	tracer      *Tracer
	mu          sync.Mutex
}

func NewCredentialVault(dataDir string) *CredentialVault {
	return &CredentialVault{dataDir: dataDir}
}

// SetKeyProvider installs the vault key source. Entries load lazily on first
// access, so the provider may be set any time before the vault is used.
func (cv *CredentialVault) SetKeyProvider(p VaultKeyProvider) {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.keyProvider = p
	cv.loaded = false
	cv.loadErr = nil
}

// Reload drops cached state; the next access re-reads from disk.
func (cv *CredentialVault) Reload() {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.loaded = false
	cv.loadErr = nil
}

func (cv *CredentialVault) vaultPath() string {
	return filepath.Join(cv.dataDir, vaultFileName)
}

func (cv *CredentialVault) legacyPath() string {
	return filepath.Join(cv.dataDir, "credentials.json")
}

// vaultKeyLocked returns the vault key, asking the provider on first use.
func (cv *CredentialVault) vaultKeyLocked() ([]byte, error) {
	if cv.key != nil {
		return cv.key, nil
	}
	if cv.keyProvider == nil {
		return nil, fmt.Errorf("no vault key provider configured")
	}
	key, err := cv.keyProvider()
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must be 32 bytes, got %d", len(key))
	}
	cv.key = key
	return key, nil
}

// ensureLoadedLocked populates entries from the encrypted vault, migrating any
// legacy plaintext store the first time a key is available.
func (cv *CredentialVault) ensureLoadedLocked() {
	if cv.loaded {
		return
	}
	cv.loaded = true
	cv.loadErr = nil
	cv.entries = nil
	cv.fallback = cv.loadSettingsFallback()

	key, keyErr := cv.vaultKeyLocked()

	if data, err := os.ReadFile(cv.vaultPath()); err == nil {
		if keyErr != nil {
			cv.loadErr = fmt.Errorf("credential vault is locked (vault key unavailable): %w", keyErr)
			log.Printf("[credentials] %v", cv.loadErr)
			return
		}
		entries, derr := decryptVault(key, data)
		if derr != nil {
			// Fail closed: refuse writes so a bad key or corrupt file never
			// silently clobbers the stored credentials.
			cv.loadErr = fmt.Errorf("credential vault cannot be opened: %w", derr)
			log.Printf("[credentials] %v", cv.loadErr)
			return
		}
		cv.entries = entries
		return
	}

	// No encrypted vault yet. A legacy plaintext store only counts if it parses
	// as a vault entry array — an object here is the ACDC credential store and
	// must be left alone.
	legacy := cv.loadLegacyPlaintext()
	cv.entries = legacy
	if keyErr != nil {
		return // read-only until a key exists; writes are refused elsewhere
	}
	if legacy != nil {
		if perr := cv.persistLocked(key); perr != nil {
			cv.loadErr = fmt.Errorf("credential vault migration failed: %w", perr)
			log.Printf("[credentials] %v", cv.loadErr)
			return
		}
		if rerr := os.Remove(cv.legacyPath()); rerr != nil {
			log.Printf("[credentials] migrated plaintext store but could not remove it: %v", rerr)
		} else {
			log.Printf("[credentials] migrated %d plaintext credential(s) into the encrypted vault", len(legacy))
		}
	}
}

// loadLegacyPlaintext returns entries from a pre-encryption credentials.json,
// or nil when the file is absent or is not a vault entry array.
func (cv *CredentialVault) loadLegacyPlaintext() []CredentialEntry {
	data, err := os.ReadFile(cv.legacyPath())
	if err != nil {
		return nil
	}
	var entries []CredentialEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	return entries
}

func (cv *CredentialVault) loadSettingsFallback() []CredentialEntry {
	data, err := os.ReadFile(filepath.Join(cv.dataDir, "settings.json"))
	if err != nil {
		return nil
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil
	}
	return cv.extractFromSettings(settings)
}

func (cv *CredentialVault) extractFromSettings(settings map[string]interface{}) []CredentialEntry {
	var entries []CredentialEntry

	if apiKey, ok := settings["openrouter_api_key"].(string); ok && apiKey != "" {
		entries = append(entries, CredentialEntry{
			Service:      "openrouter",
			MatchDomains: []string{"*.openrouter.ai", "openrouter.ai"},
			Headers: map[string]string{
				"Authorization": "Bearer " + apiKey,
			},
		})
	}

	if apiKey, ok := settings["openai_api_key"].(string); ok && apiKey != "" {
		entries = append(entries, CredentialEntry{
			Service:      "openai",
			MatchDomains: []string{"*.openai.com", "api.openai.com"},
			Headers: map[string]string{
				"Authorization": "Bearer " + apiKey,
			},
		})
	}

	return entries
}

// effectiveEntriesLocked returns vault entries plus settings-derived fallbacks
// for services the vault does not hold (the vault wins on conflict).
func (cv *CredentialVault) effectiveEntriesLocked() []CredentialEntry {
	if len(cv.fallback) == 0 {
		return cv.entries
	}
	out := append([]CredentialEntry(nil), cv.entries...)
	for _, fb := range cv.fallback {
		seen := false
		for _, e := range cv.entries {
			if e.Service == fb.Service {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, fb)
		}
	}
	return out
}

// InjectCredentialsScoped is InjectCredentials narrowed to a set of services.
//
// The unscoped form answers "is there a credential for this destination", which
// is only half the question. It cannot answer "may this caller use it", because
// nothing about an HTTP request says who is asking. Callers that can establish
// identity should use this form and pass what that caller was granted.
//
// An empty services list injects NOTHING. Treating empty as "no restriction"
// would mean a caller receives every stored credential precisely when nobody
// remembered to restrict it — the wrong default for the component whose entire
// job is holding secrets.
func (cv *CredentialVault) InjectCredentialsScoped(req *http.Request, services []string) bool {
	if len(services) == 0 {
		return false
	}
	allowed := make(map[string]bool, len(services))
	for _, s := range services {
		allowed[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return cv.injectMatching(req, func(entry CredentialEntry) bool {
		return allowed[strings.ToLower(entry.Service)]
	})
}

// InjectCredentials matches on destination host alone. Prefer the scoped form
// wherever the caller's identity can be established: host matching answers "is
// this credential for that destination" and cannot answer "should this caller be
// reaching it with this credential".
func (cv *CredentialVault) InjectCredentials(req *http.Request) bool {
	return cv.injectMatching(req, func(CredentialEntry) bool { return true })
}

// injectMatching is the one place a stored credential is written onto a request.
// eligible narrows which entries may be considered at all; host matching then
// decides which of those applies.
func (cv *CredentialVault) injectMatching(req *http.Request, eligible func(CredentialEntry) bool) bool {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.ensureLoadedLocked()

	domain := req.URL.Hostname()
	if domain == "" {
		domain = req.Host
	}
	if idx := strings.Index(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}

	entries := cv.effectiveEntriesLocked()
	for _, entry := range entries {
		if !eligible(entry) {
			continue
		}
		for _, pattern := range entry.MatchDomains {
			if MatchDomain(pattern, domain) {
				injectedHeaders := make([]string, 0, len(entry.Headers))
				for key, value := range entry.Headers {
					if req.Header.Get(key) == "" {
						req.Header.Set(key, value)
						injectedHeaders = append(injectedHeaders, key)
					}
				}
				log.Printf("[credentials] Injected %s credentials for domain %s", entry.Service, domain)
				if cv.tracer != nil && cv.tracer.IsEnabled() {
					cv.tracer.Emit("credentials", "inject", "egress", "", "",
						fmt.Sprintf("Injected %s credentials for %s", entry.Service, domain),
						map[string]interface{}{"service": entry.Service, "domain": domain, "pattern": pattern, "headers_injected": injectedHeaders})
				}
				return true
			}
		}
	}
	return false
}

func (cv *CredentialVault) SetCredential(service string, domains []string, headers map[string]string) error {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.ensureLoadedLocked()
	if cv.loadErr != nil {
		return cv.loadErr
	}
	key, err := cv.vaultKeyLocked()
	if err != nil {
		return fmt.Errorf("credential vault is locked — complete identity setup first (vault key unavailable): %w", err)
	}

	updated := false
	for i, e := range cv.entries {
		if e.Service == service {
			cv.entries[i].MatchDomains = domains
			cv.entries[i].Headers = headers
			updated = true
			break
		}
	}
	if !updated {
		cv.entries = append(cv.entries, CredentialEntry{
			Service:      service,
			MatchDomains: domains,
			Headers:      headers,
		})
	}
	return cv.persistLocked(key)
}

func (cv *CredentialVault) RemoveCredential(service string) error {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.ensureLoadedLocked()
	if cv.loadErr != nil {
		return cv.loadErr
	}

	for i, e := range cv.entries {
		if e.Service == service {
			key, err := cv.vaultKeyLocked()
			if err != nil {
				return fmt.Errorf("credential vault is locked — complete identity setup first (vault key unavailable): %w", err)
			}
			cv.entries = append(cv.entries[:i], cv.entries[i+1:]...)
			return cv.persistLocked(key)
		}
	}
	return nil
}

func (cv *CredentialVault) GetAPIKey(service string) string {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.ensureLoadedLocked()

	for _, e := range cv.effectiveEntriesLocked() {
		if e.Service == service {
			if auth, ok := e.Headers["Authorization"]; ok {
				return strings.TrimPrefix(auth, "Bearer ")
			}
		}
	}
	return ""
}

func (cv *CredentialVault) ListServices() []string {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.ensureLoadedLocked()

	var services []string
	for _, e := range cv.effectiveEntriesLocked() {
		services = append(services, e.Service)
	}
	return services
}

// persistLocked seals the entries with AES-256-GCM and writes the envelope.
// The vault never writes plaintext.
func (cv *CredentialVault) persistLocked(key []byte) error {
	entries := cv.entries
	if entries == nil {
		entries = []CredentialEntry{}
	}
	plain, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := backup.EncryptPayload(key, plain)
	if err != nil {
		return fmt.Errorf("vault encrypt: %w", err)
	}
	env := vaultEnvelope{
		Version:    1,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cv.vaultPath(), data, 0600)
}

func decryptVault(key, data []byte) ([]CredentialEntry, error) {
	var env vaultEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("unsupported vault version %d", env.Version)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	plain, err := backup.DecryptPayload(key, ciphertext, nonce)
	if err != nil {
		return nil, err
	}
	var entries []CredentialEntry
	if err := json.Unmarshal(plain, &entries); err != nil {
		return nil, fmt.Errorf("parse entries: %w", err)
	}
	return entries, nil
}
