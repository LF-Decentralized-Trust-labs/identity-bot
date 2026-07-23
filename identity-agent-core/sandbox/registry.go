package sandbox

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/zeebo/blake3"
)

// The capability registry is the runtime store of the agent's capability objects.
// A CapabilityRecord is the persisted form of one capability. Records here are
// "registry-native": capabilities the agent
// serves itself (governed calls to external third-party APIs) rather than capabilities
// provided by a running sandbox plug-in. Both kinds surface through the same discovery
// and the same governed invoke path.

// EgressSpec declares how an external_api capability maps to an outbound HTTP call.
// The record never holds a secret: CredentialService names the CredentialVault entry
// whose headers are injected at egress, after authorization.
type EgressSpec struct {
	BaseURL           string `json:"base_url"`
	Method            string `json:"method"`
	PathTemplate      string `json:"path_template"` // "{name}" tokens are filled from args
	CredentialService string `json:"credential_service"`
}

// CapabilityRecord is one registry entry. `search` filters on Domain + text, `execute`
// routes on ExecutorType, and the gateway enforces RequiredCred* + Impact — one record,
// three consumers.
type CapabilityRecord struct {
	SAID               string          `json:"said"`
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Domain             string          `json:"domain"`
	ExecutorType       string          `json:"executor_type"` // internal_api | external_api | ai_agent | host_control
	InputSchema        json.RawMessage `json:"input_schema,omitempty"`
	Impact             string          `json:"impact"` // read | mutating
	RequiredCredSchema string          `json:"required_cred_schema,omitempty"`
	RequiredCredIssuer string          `json:"required_cred_issuer,omitempty"`
	Egress             *EgressSpec     `json:"egress,omitempty"`
	Provider           string          `json:"provider"` // "registry-native" | plug-in id | agent AID
	Enabled            bool            `json:"enabled"`
}

// asProvidedCapability projects a registry record into the manifest capability shape so
// the Authorizer seam governs both kinds of capability through one interface.
func (r *CapabilityRecord) asProvidedCapability() ProvidedCapability {
	return ProvidedCapability{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		ACDCScope:   r.RequiredCredSchema,
		HostControl: r.ExecutorType == "host_control",
	}
}

// computeCapabilitySAID content-addresses a record (D17): the digest is taken over the
// record's canonical JSON with the said field empty. Prefixed with the algorithm; a
// CESR-encoded SAID via the KERI driver can replace this without a schema change.
func computeCapabilitySAID(r CapabilityRecord) string {
	r.SAID = ""
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	sum := blake3.Sum256(b)
	return "blake3:" + hex.EncodeToString(sum[:])
}

// UpsertCapabilityRecord writes a record, computing its SAID from content.
func (s *SandboxStore) UpsertCapabilityRecord(r CapabilityRecord) error {
	r.SAID = computeCapabilitySAID(r)
	var egressJSON []byte
	if r.Egress != nil {
		egressJSON, _ = json.Marshal(r.Egress)
	}
	_, err := s.db.Exec(`
		INSERT INTO capability_registry (id, said, name, description, domain, executor_type,
			input_schema, impact, required_cred_schema, required_cred_issuer, egress_json,
			provider, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET said=excluded.said, name=excluded.name,
			description=excluded.description, domain=excluded.domain,
			executor_type=excluded.executor_type, input_schema=excluded.input_schema,
			impact=excluded.impact, required_cred_schema=excluded.required_cred_schema,
			required_cred_issuer=excluded.required_cred_issuer, egress_json=excluded.egress_json,
			provider=excluded.provider, enabled=excluded.enabled, updated_at=CURRENT_TIMESTAMP`,
		r.ID, r.SAID, r.Name, r.Description, r.Domain, r.ExecutorType,
		string(r.InputSchema), r.Impact, r.RequiredCredSchema, r.RequiredCredIssuer,
		string(egressJSON), r.Provider, boolToInt(r.Enabled))
	return err
}

// GetCapabilityRecord loads one record by id; nil if absent.
func (s *SandboxStore) GetCapabilityRecord(id string) (*CapabilityRecord, error) {
	row := s.db.QueryRow(`SELECT id, said, name, description, domain, executor_type,
		input_schema, impact, required_cred_schema, required_cred_issuer, egress_json,
		provider, enabled FROM capability_registry WHERE id = ?`, id)
	return scanCapabilityRecord(row)
}

// ListCapabilityRecords returns every enabled record, ordered by id.
func (s *SandboxStore) ListCapabilityRecords() ([]CapabilityRecord, error) {
	rows, err := s.db.Query(`SELECT id, said, name, description, domain, executor_type,
		input_schema, impact, required_cred_schema, required_cred_issuer, egress_json,
		provider, enabled FROM capability_registry WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CapabilityRecord
	for rows.Next() {
		rec, err := scanCapabilityRecord(rows)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			out = append(out, *rec)
		}
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(dest ...any) error }

func scanCapabilityRecord(row rowScanner) (*CapabilityRecord, error) {
	var r CapabilityRecord
	var inputSchema, egressJSON string
	var enabled int
	err := row.Scan(&r.ID, &r.SAID, &r.Name, &r.Description, &r.Domain, &r.ExecutorType,
		&inputSchema, &r.Impact, &r.RequiredCredSchema, &r.RequiredCredIssuer, &egressJSON,
		&r.Provider, &enabled)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if inputSchema != "" {
		r.InputSchema = json.RawMessage(inputSchema)
	}
	if egressJSON != "" {
		var eg EgressSpec
		if json.Unmarshal([]byte(egressJSON), &eg) == nil {
			r.Egress = &eg
		}
	}
	r.Enabled = enabled != 0
	return &r, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// registryRecord resolves an enabled registry-native record for the governed invoke
// path. Plug-in-provided capabilities resolve via findProvider first; this is the
// fallback for capabilities the agent serves itself.
func (m *Manager) registryRecord(capabilityID string) *CapabilityRecord {
	if m.store == nil {
		return nil
	}
	rec, err := m.store.GetCapabilityRecord(capabilityID)
	if err != nil {
		log.Printf("[registry] lookup %q: %v", capabilityID, err)
		return nil
	}
	if rec == nil || !rec.Enabled {
		return nil
	}
	return rec
}

// SeedDefaultCapabilities registers the built-in registry-native records (idempotent
// upsert, so edits to the seed set roll forward). First slice: the Cloudflare API.
// The Cloudflare API token lives ONCE in the CredentialVault
// (service "cloudflare", matched on api.cloudflare.com) — union-scoped at the
// provider, per-caller governance at the gateway.
func (s *SandboxStore) SeedDefaultCapabilities() error {
	const cfBase = "https://api.cloudflare.com/client/v4"
	schema := func(props string, required ...string) json.RawMessage {
		req, _ := json.Marshal(required)
		return json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{%s},"required":%s}`, props, req))
	}
	zoneID := `"zone_id":{"type":"string","description":"Cloudflare zone id"}`
	recordID := `"record_id":{"type":"string","description":"DNS record id"}`
	dnsBody := `"type":{"type":"string","description":"A|AAAA|CNAME|TXT|MX|..."},"name":{"type":"string"},"content":{"type":"string"},"ttl":{"type":"integer"},"proxied":{"type":"boolean"}`

	seeds := []CapabilityRecord{
		{
			ID: "cloudflare.zone.list", Name: "List Cloudflare zones",
			Description: "List the zones (domains) on the Cloudflare account.",
			Domain:      "dev", ExecutorType: "external_api", Impact: "read",
			InputSchema: schema(`"name":{"type":"string","description":"optional zone name filter"}`),
			Egress:      &EgressSpec{BaseURL: cfBase, Method: "GET", PathTemplate: "/zones", CredentialService: "cloudflare"},
			Provider:    "registry-native", Enabled: true,
		},
		{
			ID: "cloudflare.dns.list", Name: "List DNS records",
			Description: "List DNS records in a Cloudflare zone.",
			Domain:      "dev", ExecutorType: "external_api", Impact: "read",
			InputSchema: schema(zoneID, "zone_id"),
			Egress:      &EgressSpec{BaseURL: cfBase, Method: "GET", PathTemplate: "/zones/{zone_id}/dns_records", CredentialService: "cloudflare"},
			Provider:    "registry-native", Enabled: true,
		},
		{
			ID: "cloudflare.dns.create", Name: "Create a DNS record",
			Description: "Create a DNS record in a Cloudflare zone.",
			Domain:      "dev", ExecutorType: "external_api", Impact: "mutating",
			InputSchema: schema(zoneID+","+dnsBody, "zone_id", "type", "name", "content"),
			Egress:      &EgressSpec{BaseURL: cfBase, Method: "POST", PathTemplate: "/zones/{zone_id}/dns_records", CredentialService: "cloudflare"},
			Provider:    "registry-native", Enabled: true,
		},
		{
			ID: "cloudflare.dns.update", Name: "Update a DNS record",
			Description: "Overwrite an existing DNS record in a Cloudflare zone.",
			Domain:      "dev", ExecutorType: "external_api", Impact: "mutating",
			InputSchema: schema(zoneID+","+recordID+","+dnsBody, "zone_id", "record_id", "type", "name", "content"),
			Egress:      &EgressSpec{BaseURL: cfBase, Method: "PUT", PathTemplate: "/zones/{zone_id}/dns_records/{record_id}", CredentialService: "cloudflare"},
			Provider:    "registry-native", Enabled: true,
		},
		{
			ID: "cloudflare.dns.delete", Name: "Delete a DNS record",
			Description: "Delete a DNS record from a Cloudflare zone.",
			Domain:      "dev", ExecutorType: "external_api", Impact: "mutating",
			InputSchema: schema(zoneID+","+recordID, "zone_id", "record_id"),
			Egress:      &EgressSpec{BaseURL: cfBase, Method: "DELETE", PathTemplate: "/zones/{zone_id}/dns_records/{record_id}", CredentialService: "cloudflare"},
			Provider:    "registry-native", Enabled: true,
		},
	}
	for _, rec := range seeds {
		if err := s.UpsertCapabilityRecord(rec); err != nil {
			return fmt.Errorf("seed capability %s: %w", rec.ID, err)
		}
	}
	return nil
}
