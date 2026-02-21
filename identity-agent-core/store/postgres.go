package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	_ "github.com/lib/pq"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	ps := &PostgresStore{db: db}
	if err := ps.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Printf("[store] Connected to PostgreSQL")
	return ps, nil
}

func (s *PostgresStore) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS apps (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			language TEXT DEFAULT 'unknown',
			entry_point TEXT DEFAULT '',
			status TEXT DEFAULT 'stopped',
			policy_id TEXT DEFAULT '',
			registered_at TEXT NOT NULL,
			last_launched_at TEXT DEFAULT '',
			metadata JSONB DEFAULT '{}'
		)`,
		`CREATE TABLE IF NOT EXISTS policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			allowed_domains JSONB DEFAULT '[]',
			blocked_domains JSONB DEFAULT '[]',
			max_spend DOUBLE PRECISION DEFAULT 0,
			allow_file_write BOOLEAN DEFAULT FALSE,
			allow_net_access BOOLEAN DEFAULT FALSE,
			created_at TEXT NOT NULL,
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			app_id TEXT DEFAULT '',
			app_name TEXT DEFAULT '',
			event_type TEXT DEFAULT '',
			direction TEXT DEFAULT '',
			target TEXT DEFAULT '',
			details TEXT DEFAULT '',
			action TEXT DEFAULT '',
			timestamp TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_app_id ON audit_log(app_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC)`,
		`CREATE TABLE IF NOT EXISTS syscall_events (
			id TEXT PRIMARY KEY,
			app_id TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			pid INTEGER DEFAULT 0,
			tid INTEGER DEFAULT 0,
			syscall_num INTEGER DEFAULT 0,
			syscall_name TEXT DEFAULT '',
			args TEXT DEFAULT '',
			return_value INTEGER DEFAULT 0,
			comm TEXT DEFAULT '',
			success BOOLEAN DEFAULT TRUE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_syscall_app_id ON syscall_events(app_id)`,
		`CREATE INDEX IF NOT EXISTS idx_syscall_timestamp ON syscall_events(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_syscall_name ON syscall_events(syscall_name)`,
		`CREATE TABLE IF NOT EXISTS network_events (
			id TEXT PRIMARY KEY,
			app_id TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			direction TEXT DEFAULT '',
			protocol TEXT DEFAULT '',
			src_ip TEXT DEFAULT '',
			src_port INTEGER DEFAULT 0,
			dst_ip TEXT DEFAULT '',
			dst_port INTEGER DEFAULT 0,
			dns_query TEXT DEFAULT '',
			bytes_sent BIGINT DEFAULT 0,
			bytes_recv BIGINT DEFAULT 0,
			action TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_network_app_id ON network_events(app_id)`,
		`CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_events(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_network_dst_ip ON network_events(dst_ip)`,
		`CREATE TABLE IF NOT EXISTS file_access_events (
			id TEXT PRIMARY KEY,
			app_id TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			pid INTEGER DEFAULT 0,
			path TEXT DEFAULT '',
			operation TEXT DEFAULT '',
			flags TEXT DEFAULT '',
			success BOOLEAN DEFAULT TRUE,
			comm TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_file_app_id ON file_access_events(app_id)`,
		`CREATE INDEX IF NOT EXISTS idx_file_timestamp ON file_access_events(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_file_path ON file_access_events(path)`,
		`CREATE TABLE IF NOT EXISTS rego_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			module TEXT DEFAULT '',
			rego TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS keri_events (
			id SERIAL PRIMARY KEY,
			aid TEXT DEFAULT '',
			sequence_number INTEGER DEFAULT 0,
			event_type TEXT DEFAULT '',
			event_json TEXT DEFAULT '',
			public_key TEXT DEFAULT '',
			next_key_digest TEXT DEFAULT '',
			timestamp TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS identity (
			aid TEXT PRIMARY KEY,
			public_key TEXT DEFAULT '',
			next_key_digest TEXT DEFAULT '',
			created TEXT NOT NULL,
			event_count INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS contacts (
			aid TEXT PRIMARY KEY,
			alias TEXT DEFAULT '',
			public_key TEXT DEFAULT '',
			oobi_url TEXT DEFAULT '',
			verified BOOLEAN DEFAULT FALSE,
			discovered_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT DEFAULT ''
		)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %s: %w", m[:60], err)
		}
	}
	return nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) SaveEvent(record EventRecord) error {
	_, err := s.db.Exec(
		`INSERT INTO keri_events (aid, sequence_number, event_type, event_json, public_key, next_key_digest, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		record.AID, record.SequenceNumber, record.EventType, record.EventJSON,
		record.PublicKey, record.NextKeyDigest, record.Timestamp,
	)
	return err
}

func (s *PostgresStore) GetEvents(aid string) ([]EventRecord, error) {
	rows, err := s.db.Query(
		`SELECT aid, sequence_number, event_type, event_json, public_key, next_key_digest, timestamp
		FROM keri_events WHERE aid = $1 ORDER BY sequence_number`, aid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []EventRecord
	for rows.Next() {
		var e EventRecord
		if err := rows.Scan(&e.AID, &e.SequenceNumber, &e.EventType, &e.EventJSON,
			&e.PublicKey, &e.NextKeyDigest, &e.Timestamp); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if events == nil {
		events = []EventRecord{}
	}
	return events, nil
}

func (s *PostgresStore) GetIdentity() (*IdentityState, error) {
	var state IdentityState
	err := s.db.QueryRow(`SELECT aid, public_key, next_key_digest, created, event_count FROM identity LIMIT 1`).
		Scan(&state.AID, &state.PublicKey, &state.NextKeyDigest, &state.Created, &state.EventCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func (s *PostgresStore) SaveIdentity(state IdentityState) error {
	_, err := s.db.Exec(
		`INSERT INTO identity (aid, public_key, next_key_digest, created, event_count)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (aid) DO UPDATE SET public_key=$2, next_key_digest=$3, event_count=$5`,
		state.AID, state.PublicKey, state.NextKeyDigest, state.Created, state.EventCount,
	)
	return err
}

func (s *PostgresStore) SaveContact(contact ContactRecord) error {
	_, err := s.db.Exec(
		`INSERT INTO contacts (aid, alias, public_key, oobi_url, verified, discovered_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (aid) DO UPDATE SET alias=$2, public_key=$3, oobi_url=$4, verified=$5, discovered_at=$6`,
		contact.AID, contact.Alias, contact.PublicKey, contact.OobiURL, contact.Verified, contact.DiscoveredAt,
	)
	return err
}

func (s *PostgresStore) GetContacts() ([]ContactRecord, error) {
	rows, err := s.db.Query(`SELECT aid, alias, public_key, oobi_url, verified, discovered_at FROM contacts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []ContactRecord
	for rows.Next() {
		var c ContactRecord
		if err := rows.Scan(&c.AID, &c.Alias, &c.PublicKey, &c.OobiURL, &c.Verified, &c.DiscoveredAt); err != nil {
			return nil, err
		}
		contacts = append(contacts, c)
	}
	if contacts == nil {
		contacts = []ContactRecord{}
	}
	return contacts, nil
}

func (s *PostgresStore) GetContact(aid string) (*ContactRecord, error) {
	var c ContactRecord
	err := s.db.QueryRow(`SELECT aid, alias, public_key, oobi_url, verified, discovered_at FROM contacts WHERE aid=$1`, aid).
		Scan(&c.AID, &c.Alias, &c.PublicKey, &c.OobiURL, &c.Verified, &c.DiscoveredAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *PostgresStore) DeleteContact(aid string) error {
	_, err := s.db.Exec(`DELETE FROM contacts WHERE aid=$1`, aid)
	return err
}

func (s *PostgresStore) GetSettings() (*SettingsData, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := &SettingsData{}
	found := false
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		found = true
		switch key {
		case "tunnel_provider":
			settings.TunnelProvider = value
		case "ngrok_auth_token":
			settings.NgrokAuthToken = value
		case "cloudflare_tunnel_token":
			settings.CloudflareTunnelToken = value
		}
	}
	if !found {
		return nil, nil
	}
	return settings, nil
}

func (s *PostgresStore) SaveSettings(settings SettingsData) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	pairs := map[string]string{
		"tunnel_provider":        settings.TunnelProvider,
		"ngrok_auth_token":       settings.NgrokAuthToken,
		"cloudflare_tunnel_token": settings.CloudflareTunnelToken,
	}
	for k, v := range pairs {
		_, err := tx.Exec(
			`INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value=$2`, k, v,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) SaveApp(app AppRecord) error {
	metaJSON, _ := json.Marshal(app.Metadata)
	if app.Metadata == nil {
		metaJSON = []byte("{}")
	}
	_, err := s.db.Exec(
		`INSERT INTO apps (id, name, description, language, entry_point, status, policy_id, registered_at, last_launched_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET name=$2, description=$3, language=$4, entry_point=$5,
			status=$6, policy_id=$7, last_launched_at=$9, metadata=$10`,
		app.ID, app.Name, app.Description, app.Language, app.EntryPoint,
		app.Status, app.PolicyID, app.RegisteredAt, app.LastLaunchedAt, metaJSON,
	)
	return err
}

func (s *PostgresStore) GetApps() ([]AppRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, name, description, language, entry_point, status, policy_id, registered_at, last_launched_at, metadata
		FROM apps ORDER BY registered_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []AppRecord
	for rows.Next() {
		var a AppRecord
		var metaJSON []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.Language, &a.EntryPoint,
			&a.Status, &a.PolicyID, &a.RegisteredAt, &a.LastLaunchedAt, &metaJSON); err != nil {
			return nil, err
		}
		if len(metaJSON) > 0 {
			json.Unmarshal(metaJSON, &a.Metadata)
		}
		apps = append(apps, a)
	}
	if apps == nil {
		apps = []AppRecord{}
	}
	return apps, nil
}

func (s *PostgresStore) GetApp(id string) (*AppRecord, error) {
	var a AppRecord
	var metaJSON []byte
	err := s.db.QueryRow(
		`SELECT id, name, description, language, entry_point, status, policy_id, registered_at, last_launched_at, metadata
		FROM apps WHERE id=$1`, id,
	).Scan(&a.ID, &a.Name, &a.Description, &a.Language, &a.EntryPoint,
		&a.Status, &a.PolicyID, &a.RegisteredAt, &a.LastLaunchedAt, &metaJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(metaJSON) > 0 {
		json.Unmarshal(metaJSON, &a.Metadata)
	}
	return &a, nil
}

func (s *PostgresStore) DeleteApp(id string) error {
	_, err := s.db.Exec(`DELETE FROM apps WHERE id=$1`, id)
	return err
}

func (s *PostgresStore) SavePolicy(policy PolicyRecord) error {
	allowedJSON, _ := json.Marshal(policy.AllowedDomains)
	blockedJSON, _ := json.Marshal(policy.BlockedDomains)
	_, err := s.db.Exec(
		`INSERT INTO policies (id, name, description, allowed_domains, blocked_domains, max_spend, allow_file_write, allow_net_access, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET name=$2, description=$3, allowed_domains=$4, blocked_domains=$5,
			max_spend=$6, allow_file_write=$7, allow_net_access=$8, updated_at=$10`,
		policy.ID, policy.Name, policy.Description, allowedJSON, blockedJSON,
		policy.MaxSpend, policy.AllowFileWrite, policy.AllowNetAccess, policy.CreatedAt, policy.UpdatedAt,
	)
	return err
}

func (s *PostgresStore) GetPolicies() ([]PolicyRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, name, description, allowed_domains, blocked_domains, max_spend, allow_file_write, allow_net_access, created_at, updated_at
		FROM policies ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []PolicyRecord
	for rows.Next() {
		var p PolicyRecord
		var allowedJSON, blockedJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &allowedJSON, &blockedJSON,
			&p.MaxSpend, &p.AllowFileWrite, &p.AllowNetAccess, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal(allowedJSON, &p.AllowedDomains)
		json.Unmarshal(blockedJSON, &p.BlockedDomains)
		if p.AllowedDomains == nil {
			p.AllowedDomains = []string{}
		}
		if p.BlockedDomains == nil {
			p.BlockedDomains = []string{}
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []PolicyRecord{}
	}
	return policies, nil
}

func (s *PostgresStore) GetPolicy(id string) (*PolicyRecord, error) {
	var p PolicyRecord
	var allowedJSON, blockedJSON []byte
	err := s.db.QueryRow(
		`SELECT id, name, description, allowed_domains, blocked_domains, max_spend, allow_file_write, allow_net_access, created_at, updated_at
		FROM policies WHERE id=$1`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &allowedJSON, &blockedJSON,
		&p.MaxSpend, &p.AllowFileWrite, &p.AllowNetAccess, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(allowedJSON, &p.AllowedDomains)
	json.Unmarshal(blockedJSON, &p.BlockedDomains)
	if p.AllowedDomains == nil {
		p.AllowedDomains = []string{}
	}
	if p.BlockedDomains == nil {
		p.BlockedDomains = []string{}
	}
	return &p, nil
}

func (s *PostgresStore) DeletePolicy(id string) error {
	_, err := s.db.Exec(`DELETE FROM policies WHERE id=$1`, id)
	return err
}

func (s *PostgresStore) AppendAuditLog(entry AuditLogEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log (id, app_id, app_name, event_type, direction, target, details, action, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.ID, entry.AppID, entry.AppName, entry.EventType, entry.Direction,
		entry.Target, entry.Details, entry.Action, entry.Timestamp,
	)
	return err
}

func (s *PostgresStore) GetAuditLog(appID string, limit int) ([]AuditLogEntry, error) {
	var rows *sql.Rows
	var err error

	if limit <= 0 {
		limit = 100
	}

	if appID != "" {
		rows, err = s.db.Query(
			`SELECT id, app_id, app_name, event_type, direction, target, details, action, timestamp
			FROM audit_log WHERE app_id=$1 ORDER BY timestamp ASC LIMIT $2`, appID, limit,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT id, app_id, app_name, event_type, direction, target, details, action, timestamp
			FROM audit_log ORDER BY timestamp ASC LIMIT $1`, limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditLogEntry
	for rows.Next() {
		var e AuditLogEntry
		if err := rows.Scan(&e.ID, &e.AppID, &e.AppName, &e.EventType, &e.Direction,
			&e.Target, &e.Details, &e.Action, &e.Timestamp); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []AuditLogEntry{}
	}
	return entries, nil
}

func (s *PostgresStore) SaveSyscallEvents(events []SyscallEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO syscall_events (id, app_id, timestamp, pid, tid, syscall_num, syscall_name, args, return_value, comm, success)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO NOTHING`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		_, err := stmt.Exec(e.ID, e.AppID, e.Timestamp, e.PID, e.TID, e.SyscallNum,
			e.SyscallName, e.Args, e.ReturnValue, e.Comm, e.Success)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) SaveNetworkEvents(events []NetworkEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO network_events (id, app_id, timestamp, direction, protocol, src_ip, src_port, dst_ip, dst_port, dns_query, bytes_sent, bytes_recv, action)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO NOTHING`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		_, err := stmt.Exec(e.ID, e.AppID, e.Timestamp, e.Direction, e.Protocol,
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.DNSQuery, e.BytesSent, e.BytesRecv, e.Action)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) SaveFileAccessEvents(events []FileAccessEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO file_access_events (id, app_id, timestamp, pid, path, operation, flags, success, comm)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		_, err := stmt.Exec(e.ID, e.AppID, e.Timestamp, e.PID, e.Path, e.Operation, e.Flags, e.Success, e.Comm)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) GetNetworkEvents(appID string, limit int) ([]NetworkEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, app_id, timestamp, direction, protocol, src_ip, src_port, dst_ip, dst_port, dns_query, bytes_sent, bytes_recv, action
		FROM network_events`
	var args []interface{}
	if appID != "" {
		query += ` WHERE app_id=$1 ORDER BY timestamp DESC LIMIT $2`
		args = append(args, appID, limit)
	} else {
		query += ` ORDER BY timestamp DESC LIMIT $1`
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []NetworkEvent
	for rows.Next() {
		var e NetworkEvent
		if err := rows.Scan(&e.ID, &e.AppID, &e.Timestamp, &e.Direction, &e.Protocol,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.DNSQuery, &e.BytesSent, &e.BytesRecv, &e.Action); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if events == nil {
		events = []NetworkEvent{}
	}
	return events, nil
}

func (s *PostgresStore) GetSyscallEvents(appID string, limit int) ([]SyscallEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, app_id, timestamp, pid, tid, syscall_num, syscall_name, args, return_value, comm, success
		FROM syscall_events`
	var args []interface{}
	if appID != "" {
		query += ` WHERE app_id=$1 ORDER BY timestamp DESC LIMIT $2`
		args = append(args, appID, limit)
	} else {
		query += ` ORDER BY timestamp DESC LIMIT $1`
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SyscallEvent
	for rows.Next() {
		var e SyscallEvent
		if err := rows.Scan(&e.ID, &e.AppID, &e.Timestamp, &e.PID, &e.TID, &e.SyscallNum,
			&e.SyscallName, &e.Args, &e.ReturnValue, &e.Comm, &e.Success); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if events == nil {
		events = []SyscallEvent{}
	}
	return events, nil
}

func (s *PostgresStore) GetFileAccessEvents(appID string, limit int) ([]FileAccessEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, app_id, timestamp, pid, path, operation, flags, success, comm
		FROM file_access_events`
	var args []interface{}
	if appID != "" {
		query += ` WHERE app_id=$1 ORDER BY timestamp DESC LIMIT $2`
		args = append(args, appID, limit)
	} else {
		query += ` ORDER BY timestamp DESC LIMIT $1`
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []FileAccessEvent
	for rows.Next() {
		var e FileAccessEvent
		if err := rows.Scan(&e.ID, &e.AppID, &e.Timestamp, &e.PID, &e.Path, &e.Operation, &e.Flags, &e.Success, &e.Comm); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if events == nil {
		events = []FileAccessEvent{}
	}
	return events, nil
}

func (s *PostgresStore) GetTelemetrySummary(appID string) (*TelemetrySummary, error) {
	summary := &TelemetrySummary{AppID: appID}

	whereClause := ""
	var args []interface{}
	if appID != "" {
		whereClause = " WHERE app_id=$1"
		args = append(args, appID)
	}

	s.db.QueryRow(`SELECT COUNT(*) FROM syscall_events`+whereClause, args...).Scan(&summary.TotalSyscalls)
	s.db.QueryRow(`SELECT COUNT(*) FROM network_events`+whereClause, args...).Scan(&summary.TotalNetworkEvents)
	s.db.QueryRow(`SELECT COUNT(*) FROM file_access_events`+whereClause, args...).Scan(&summary.TotalFileEvents)

	summary.TopSyscalls = s.queryNameCounts(`SELECT syscall_name, COUNT(*) as cnt FROM syscall_events`+whereClause+` GROUP BY syscall_name ORDER BY cnt DESC LIMIT 10`, args...)
	summary.TopDestinations = s.queryNameCounts(`SELECT COALESCE(NULLIF(dns_query,''), dst_ip) as dest, COUNT(*) as cnt FROM network_events`+whereClause+` GROUP BY dest ORDER BY cnt DESC LIMIT 10`, args...)
	summary.TopFilePaths = s.queryNameCounts(`SELECT path, COUNT(*) as cnt FROM file_access_events`+whereClause+` GROUP BY path ORDER BY cnt DESC LIMIT 10`, args...)
	summary.ProtocolBreakdown = s.queryNameCounts(`SELECT protocol, COUNT(*) as cnt FROM network_events`+whereClause+` GROUP BY protocol ORDER BY cnt DESC`, args...)
	summary.DirectionBreakdown = s.queryNameCounts(`SELECT direction, COUNT(*) as cnt FROM network_events`+whereClause+` GROUP BY direction ORDER BY cnt DESC`, args...)

	var tr TimeRange
	tables := []string{"syscall_events", "network_events", "file_access_events"}
	for _, t := range tables {
		var minT, maxT sql.NullString
		s.db.QueryRow(fmt.Sprintf(`SELECT MIN(timestamp), MAX(timestamp) FROM %s%s`, t, whereClause), args...).Scan(&minT, &maxT)
		if minT.Valid && (tr.Start == "" || minT.String < tr.Start) {
			tr.Start = minT.String
		}
		if maxT.Valid && (tr.End == "" || maxT.String > tr.End) {
			tr.End = maxT.String
		}
	}
	if tr.Start != "" {
		summary.TimeRange = &tr
	}

	return summary, nil
}

func (s *PostgresStore) queryNameCounts(query string, args ...interface{}) []NameCount {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return []NameCount{}
	}
	defer rows.Close()

	var results []NameCount
	for rows.Next() {
		var nc NameCount
		if err := rows.Scan(&nc.Name, &nc.Count); err != nil {
			continue
		}
		if nc.Name == "" {
			continue
		}
		results = append(results, nc)
	}
	if results == nil {
		results = []NameCount{}
	}
	return results
}

func (s *PostgresStore) SaveRegoPolicy(policy RegoPolicy) error {
	_, err := s.db.Exec(
		`INSERT INTO rego_policies (id, name, description, module, rego, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET name=$2, description=$3, module=$4, rego=$5, updated_at=$7`,
		policy.ID, policy.Name, policy.Description, policy.Module, policy.Rego, policy.CreatedAt, policy.UpdatedAt,
	)
	return err
}

func (s *PostgresStore) GetRegoPolicies() ([]RegoPolicy, error) {
	rows, err := s.db.Query(`SELECT id, name, description, module, rego, created_at, updated_at FROM rego_policies ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []RegoPolicy
	for rows.Next() {
		var p RegoPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Module, &p.Rego, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []RegoPolicy{}
	}
	return policies, nil
}

func (s *PostgresStore) GetRegoPolicy(id string) (*RegoPolicy, error) {
	var p RegoPolicy
	err := s.db.QueryRow(`SELECT id, name, description, module, rego, created_at, updated_at FROM rego_policies WHERE id=$1`, id).
		Scan(&p.ID, &p.Name, &p.Description, &p.Module, &p.Rego, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *PostgresStore) DeleteRegoPolicy(id string) error {
	_, err := s.db.Exec(`DELETE FROM rego_policies WHERE id=$1`, id)
	return err
}

func (s *PostgresStore) GetTelemetryStats() (map[string]int, error) {
	stats := map[string]int{}
	tables := map[string]string{
		"syscall_events":     "syscalls",
		"network_events":     "network",
		"file_access_events": "file_access",
	}
	for table, key := range tables {
		var count int
		s.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, table)).Scan(&count)
		stats[key] = count
	}
	return stats, nil
}

func (s *PostgresStore) SearchAuditLog(appID, eventType, action string, limit int) ([]AuditLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if appID != "" {
		conditions = append(conditions, fmt.Sprintf("app_id=$%d", argIdx))
		args = append(args, appID)
		argIdx++
	}
	if eventType != "" {
		conditions = append(conditions, fmt.Sprintf("event_type=$%d", argIdx))
		args = append(args, eventType)
		argIdx++
	}
	if action != "" {
		conditions = append(conditions, fmt.Sprintf("action=$%d", argIdx))
		args = append(args, action)
		argIdx++
	}

	query := `SELECT id, app_id, app_name, event_type, direction, target, details, action, timestamp FROM audit_log`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditLogEntry
	for rows.Next() {
		var e AuditLogEntry
		if err := rows.Scan(&e.ID, &e.AppID, &e.AppName, &e.EventType, &e.Direction,
			&e.Target, &e.Details, &e.Action, &e.Timestamp); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []AuditLogEntry{}
	}
	return entries, nil
}
