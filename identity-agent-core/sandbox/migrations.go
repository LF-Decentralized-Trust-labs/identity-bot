package sandbox

import (
        "database/sql"
        "fmt"
        "log"
)

type migration struct {
        Version     int
        Description string
        SQL         string
        PreCheck    func(db *sql.DB) bool
}

var migrations = []migration{
        {
                Version:     1,
                Description: "Initial sandbox schema",
                SQL: `
CREATE TABLE IF NOT EXISTS apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    version TEXT,
    execution_type TEXT NOT NULL,
    display_method TEXT NOT NULL,
    network_mode TEXT DEFAULT 'proxy_required',
    manifest_json TEXT NOT NULL,
    manifest_signature TEXT,
    publisher_key TEXT,
    signature_algorithm TEXT,
    install_status TEXT DEFAULT 'available',
    docker_image TEXT,
    docker_image_size_bytes INTEGER,
    binary_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS instances (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES apps(id),
    container_id TEXT,
    process_pid INTEGER,
    status TEXT DEFAULT 'starting',
    proxy_port INTEGER,
    display_port INTEGER,
    agent_api_port INTEGER,
    network_name TEXT,
    tls_mode TEXT DEFAULT 'mitm',
    log_level TEXT DEFAULT 'metadata',
    cpu_limit REAL,
    memory_limit_mb INTEGER,
    disk_limit_mb INTEGER,
    egress_kbps INTEGER,
    ingress_kbps INTEGER,
    started_at DATETIME,
    stopped_at DATETIME
);

CREATE TABLE IF NOT EXISTS proxy_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL REFERENCES instances(id),
    direction TEXT NOT NULL,
    method TEXT,
    url TEXT,
    domain TEXT,
    status_code INTEGER,
    request_headers TEXT,
    request_body TEXT,
    response_headers TEXT,
    response_body TEXT,
    bytes_sent INTEGER,
    bytes_received INTEGER,
    policy_action TEXT,
    policy_rule TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_proxy_logs_instance ON proxy_logs(instance_id);
CREATE INDEX IF NOT EXISTS idx_proxy_logs_domain ON proxy_logs(domain);
CREATE INDEX IF NOT EXISTS idx_proxy_logs_timestamp ON proxy_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_proxy_logs_policy ON proxy_logs(policy_action);

CREATE TABLE IF NOT EXISTS policy_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT NOT NULL REFERENCES apps(id),
    rule_type TEXT NOT NULL,
    target TEXT NOT NULL,
    source TEXT DEFAULT 'manifest',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS resource_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL REFERENCES instances(id),
    app_id TEXT NOT NULL REFERENCES apps(id),
    resource_type TEXT NOT NULL,
    resource_target TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    resolved_by TEXT
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT,
    app_id TEXT NOT NULL,
    decision_type TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    reason TEXT,
    decided_by TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT,
    app_id TEXT,
    event_type TEXT NOT NULL,
    event_data TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_instance ON events(instance_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
`,
        },
        {
                Version:     2,
                Description: "Rename docker_image columns to container_image",
                PreCheck: func(db *sql.DB) bool {
                        rows, err := db.Query("PRAGMA table_info(apps)")
                        if err != nil {
                                return true
                        }
                        defer rows.Close()
                        for rows.Next() {
                                var cid int
                                var name, ctype string
                                var notnull int
                                var dfltValue sql.NullString
                                var pk int
                                if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
                                        continue
                                }
                                if name == "docker_image" {
                                        return true
                                }
                        }
                        return false
                },
                SQL: `
ALTER TABLE apps RENAME COLUMN docker_image TO container_image;
ALTER TABLE apps RENAME COLUMN docker_image_size_bytes TO container_image_size_bytes;
`,
        },
}

func ensureMigrationsTable(db *sql.DB) error {
        _, err := db.Exec(`
                CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        description TEXT NOT NULL,
                        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
        `)
        return err
}

func currentVersion(db *sql.DB) (int, error) {
        var version int
        err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
        if err != nil {
                return 0, err
        }
        return version, nil
}

func ApplyMigrations(db *sql.DB) error {
        if err := ensureMigrationsTable(db); err != nil {
                return fmt.Errorf("failed to create migrations table: %w", err)
        }

        current, err := currentVersion(db)
        if err != nil {
                return fmt.Errorf("failed to get current schema version: %w", err)
        }

        for _, m := range migrations {
                if m.Version <= current {
                        continue
                }

                if m.PreCheck != nil && !m.PreCheck(db) {
                        log.Printf("[sandbox] Skipping migration %d (pre-check: columns already renamed): %s", m.Version, m.Description)
                        db.Exec("INSERT INTO schema_migrations (version, description) VALUES (?, ?)", m.Version, m.Description)
                        continue
                }

                log.Printf("[sandbox] Applying migration %d: %s", m.Version, m.Description)

                tx, err := db.Begin()
                if err != nil {
                        return fmt.Errorf("failed to begin transaction for migration %d: %w", m.Version, err)
                }

                if _, err := tx.Exec(m.SQL); err != nil {
                        tx.Rollback()
                        return fmt.Errorf("failed to apply migration %d: %w", m.Version, err)
                }

                if _, err := tx.Exec("INSERT INTO schema_migrations (version, description) VALUES (?, ?)", m.Version, m.Description); err != nil {
                        tx.Rollback()
                        return fmt.Errorf("failed to record migration %d: %w", m.Version, err)
                }

                if err := tx.Commit(); err != nil {
                        return fmt.Errorf("failed to commit migration %d: %w", m.Version, err)
                }

                log.Printf("[sandbox] Migration %d applied successfully", m.Version)
        }

        return nil
}
