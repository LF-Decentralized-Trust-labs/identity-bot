package sandbox

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	// BodyTemplate, when set, shapes the outbound JSON body: "{name}" placeholders
	// are filled from args ("{name|default}" makes one optional) on the decoded
	// JSON tree, so values are inserted safely regardless of quoting. With a
	// template, args map ONLY through placeholders — leftovers are an error.
	BodyTemplate json.RawMessage `json:"body_template,omitempty"`
	// ResponseExtract, when set, projects a successful JSON response down to the
	// named fields: output field -> dotted path (e.g. "choices.0.message.content").
	// A path ending in "!" is required — a response missing it is an error.
	ResponseExtract map[string]string `json:"response_extract,omitempty"`
	// TimeoutSeconds bounds the outbound call (0 = the transport default). Slow
	// capabilities (e.g. image generation) declare their own budget here.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
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
	ExecutorType       string          `json:"executor_type"` // built-in, or a type a deployment registered
	InputSchema        json.RawMessage `json:"input_schema,omitempty"`
	Impact             string          `json:"impact"` // read | mutating
	RequiredCredSchema string          `json:"required_cred_schema,omitempty"`
	RequiredCredIssuer string          `json:"required_cred_issuer,omitempty"`
	Egress             *EgressSpec     `json:"egress,omitempty"`
	// ExecutorConfig is the executor's own configuration, opaque to the engine.
	// A registered Executor is the only thing that interprets it, so a new kind of
	// capability needs no schema change here.
	ExecutorConfig json.RawMessage `json:"executor_config,omitempty"`
	Provider       string          `json:"provider"` // "registry-native" | plug-in id | agent AID
	Enabled        bool            `json:"enabled"`
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
			executor_config_json, provider, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET said=excluded.said, name=excluded.name,
			description=excluded.description, domain=excluded.domain,
			executor_type=excluded.executor_type, input_schema=excluded.input_schema,
			impact=excluded.impact, required_cred_schema=excluded.required_cred_schema,
			required_cred_issuer=excluded.required_cred_issuer, egress_json=excluded.egress_json,
			executor_config_json=excluded.executor_config_json, provider=excluded.provider, enabled=excluded.enabled, updated_at=CURRENT_TIMESTAMP`,
		r.ID, r.SAID, r.Name, r.Description, r.Domain, r.ExecutorType,
		string(r.InputSchema), r.Impact, r.RequiredCredSchema, r.RequiredCredIssuer,
		string(egressJSON), string(r.ExecutorConfig), r.Provider, boolToInt(r.Enabled))
	return err
}

// GetCapabilityRecord loads one record by id; nil if absent.
func (s *SandboxStore) GetCapabilityRecord(id string) (*CapabilityRecord, error) {
	row := s.db.QueryRow(`SELECT id, said, name, description, domain, executor_type,
		input_schema, impact, required_cred_schema, required_cred_issuer, egress_json,
		executor_config_json, provider, enabled FROM capability_registry WHERE id = ?`, id)
	return scanCapabilityRecord(row)
}

// ListCapabilityRecords returns every enabled record, ordered by id.
func (s *SandboxStore) ListCapabilityRecords() ([]CapabilityRecord, error) {
	rows, err := s.db.Query(`SELECT id, said, name, description, domain, executor_type,
		input_schema, impact, required_cred_schema, required_cred_issuer, egress_json,
		executor_config_json, provider, enabled FROM capability_registry WHERE enabled = 1 ORDER BY id`)
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

// ListAllCapabilityRecords returns every record including disabled ones — the
// management view (the invoke/discovery paths use ListCapabilityRecords).
func (s *SandboxStore) ListAllCapabilityRecords() ([]CapabilityRecord, error) {
	rows, err := s.db.Query(`SELECT id, said, name, description, domain, executor_type,
		input_schema, impact, required_cred_schema, required_cred_issuer, egress_json,
		executor_config_json, provider, enabled FROM capability_registry ORDER BY id`)
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

// SetCapabilityEnabled toggles a record without touching its content (or SAID).
// Returns false when no such record exists.
func (s *SandboxStore) SetCapabilityEnabled(id string, enabled bool) (bool, error) {
	res, err := s.db.Exec(`UPDATE capability_registry SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		boolToInt(enabled), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteCapabilityRecord removes a record. Returns false when no such record exists.
// (Invocation-log events referencing it are history and remain.)
func (s *SandboxStore) DeleteCapabilityRecord(id string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM capability_registry WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanCapabilityRecord(row rowScanner) (*CapabilityRecord, error) {
	var r CapabilityRecord
	var inputSchema, egressJSON string
	var execConfig sql.NullString
	var enabled int
	err := row.Scan(&r.ID, &r.SAID, &r.Name, &r.Description, &r.Domain, &r.ExecutorType,
		&inputSchema, &r.Impact, &r.RequiredCredSchema, &r.RequiredCredIssuer, &egressJSON,
		&execConfig, &r.Provider, &enabled)
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
	if execConfig.Valid && execConfig.String != "" {
		r.ExecutorConfig = json.RawMessage(execConfig.String)
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
