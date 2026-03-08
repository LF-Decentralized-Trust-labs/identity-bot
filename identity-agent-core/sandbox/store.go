package sandbox

import (
        "database/sql"
        "fmt"
        "log"
        "os"
        "path/filepath"
        "sync"
        "time"

        "github.com/google/uuid"
        _ "modernc.org/sqlite"
)

type App struct {
        ID                  string  `json:"id"`
        Name                string  `json:"name"`
        Description         *string `json:"description,omitempty"`
        Version             *string `json:"version,omitempty"`
        ExecutionType       string  `json:"execution_type"`
        DisplayMethod       string  `json:"display_method"`
        NetworkMode         string  `json:"network_mode"`
        ManifestJSON        string  `json:"manifest_json"`
        ManifestSignature   *string `json:"manifest_signature,omitempty"`
        PublisherKey        *string `json:"publisher_key,omitempty"`
        SignatureAlgorithm  *string `json:"signature_algorithm,omitempty"`
        InstallStatus       string  `json:"install_status"`
        DockerImage         *string `json:"docker_image,omitempty"`
        DockerImageSizeBytes *int64 `json:"docker_image_size_bytes,omitempty"`
        BinaryPath          *string `json:"binary_path,omitempty"`
        CreatedAt           string  `json:"created_at"`
        UpdatedAt           string  `json:"updated_at"`
}

type Instance struct {
        ID            string  `json:"id"`
        AppID         string  `json:"app_id"`
        ContainerID   *string `json:"container_id,omitempty"`
        ProcessPID    *int    `json:"process_pid,omitempty"`
        Status        string  `json:"status"`
        ProxyPort     *int    `json:"proxy_port,omitempty"`
        DisplayPort   *int    `json:"display_port,omitempty"`
        AgentAPIPort  *int    `json:"agent_api_port,omitempty"`
        NetworkName   *string `json:"network_name,omitempty"`
        TLSMode       string  `json:"tls_mode"`
        LogLevel      string  `json:"log_level"`
        CPULimit      *float64 `json:"cpu_limit,omitempty"`
        MemoryLimitMB *int    `json:"memory_limit_mb,omitempty"`
        DiskLimitMB   *int    `json:"disk_limit_mb,omitempty"`
        EgressKbps    *int    `json:"egress_kbps,omitempty"`
        IngressKbps   *int    `json:"ingress_kbps,omitempty"`
        StartedAt     *string `json:"started_at,omitempty"`
        StoppedAt     *string `json:"stopped_at,omitempty"`
}

type ProxyLog struct {
        ID              int64   `json:"id"`
        InstanceID      string  `json:"instance_id"`
        Direction       string  `json:"direction"`
        Method          *string `json:"method,omitempty"`
        URL             *string `json:"url,omitempty"`
        Domain          *string `json:"domain,omitempty"`
        StatusCode      *int    `json:"status_code,omitempty"`
        RequestHeaders  *string `json:"request_headers,omitempty"`
        RequestBody     *string `json:"request_body,omitempty"`
        ResponseHeaders *string `json:"response_headers,omitempty"`
        ResponseBody    *string `json:"response_body,omitempty"`
        BytesSent       *int64  `json:"bytes_sent,omitempty"`
        BytesReceived   *int64  `json:"bytes_received,omitempty"`
        PolicyAction    *string `json:"policy_action,omitempty"`
        PolicyRule      *string `json:"policy_rule,omitempty"`
        Timestamp       string  `json:"timestamp"`
}

type PolicyRule struct {
        ID        int64  `json:"id"`
        AppID     string `json:"app_id"`
        RuleType  string `json:"rule_type"`
        Target    string `json:"target"`
        Source    string `json:"source"`
        CreatedAt string `json:"created_at"`
}

type ResourceRequest struct {
        ID             int64   `json:"id"`
        InstanceID     string  `json:"instance_id"`
        AppID          string  `json:"app_id"`
        ResourceType   string  `json:"resource_type"`
        ResourceTarget string  `json:"resource_target"`
        Status         string  `json:"status"`
        RequestedAt    string  `json:"requested_at"`
        ResolvedAt     *string `json:"resolved_at,omitempty"`
        ResolvedBy     *string `json:"resolved_by,omitempty"`
}

type PolicyDecision struct {
        ID           int64   `json:"id"`
        InstanceID   *string `json:"instance_id,omitempty"`
        AppID        string  `json:"app_id"`
        DecisionType string  `json:"decision_type"`
        Action       string  `json:"action"`
        Target       *string `json:"target,omitempty"`
        Reason       *string `json:"reason,omitempty"`
        DecidedBy    *string `json:"decided_by,omitempty"`
        Timestamp    string  `json:"timestamp"`
}

type Event struct {
        ID         int64   `json:"id"`
        InstanceID *string `json:"instance_id,omitempty"`
        AppID      *string `json:"app_id,omitempty"`
        EventType  string  `json:"event_type"`
        EventData  *string `json:"event_data,omitempty"`
        Timestamp  string  `json:"timestamp"`
}

type ProxyLogFilter struct {
        InstanceID   string
        Domain       string
        StatusCode   *int
        PolicyAction string
        Direction    string
        Since        *time.Time
        Until        *time.Time
        Limit        int
        Offset       int
}

type SandboxStore struct {
        db         *sql.DB
        dbPath     string
        pruneStop  chan struct{}
        pruneWg    sync.WaitGroup
}

const (
        defaultRetentionDays = 7
        defaultMaxSizeMB     = 500
        pruneInterval        = 24 * time.Hour
)

func NewSandboxStore(dataDir string) (*SandboxStore, error) {
        if err := os.MkdirAll(dataDir, 0755); err != nil {
                return nil, fmt.Errorf("failed to create data directory: %w", err)
        }

        dbPath := filepath.Join(dataDir, "sandbox.db")
        db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
        if err != nil {
                return nil, fmt.Errorf("failed to open sandbox database: %w", err)
        }

        if err := db.Ping(); err != nil {
                db.Close()
                return nil, fmt.Errorf("failed to ping sandbox database: %w", err)
        }

        if err := ApplyMigrations(db); err != nil {
                db.Close()
                return nil, fmt.Errorf("failed to apply migrations: %w", err)
        }

        s := &SandboxStore{
                db:        db,
                dbPath:    dbPath,
                pruneStop: make(chan struct{}),
        }

        if err := s.Prune(); err != nil {
                log.Printf("[sandbox] Initial prune failed (non-fatal): %v", err)
        }

        s.startPruneLoop()

        log.Printf("[sandbox] Initialized sandbox store at: %s", dbPath)
        return s, nil
}

func (s *SandboxStore) Close() error {
        close(s.pruneStop)
        s.pruneWg.Wait()
        return s.db.Close()
}

func NewInstanceID() string {
        return uuid.New().String()
}

func (s *SandboxStore) SaveApp(app App) error {
        _, err := s.db.Exec(`
                INSERT INTO apps (id, name, description, version, execution_type, display_method, network_mode,
                        manifest_json, manifest_signature, publisher_key, signature_algorithm, install_status,
                        docker_image, docker_image_size_bytes, binary_path, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                        name=excluded.name, description=excluded.description, version=excluded.version,
                        execution_type=excluded.execution_type, display_method=excluded.display_method,
                        network_mode=excluded.network_mode, manifest_json=excluded.manifest_json,
                        manifest_signature=excluded.manifest_signature, publisher_key=excluded.publisher_key,
                        signature_algorithm=excluded.signature_algorithm, install_status=excluded.install_status,
                        docker_image=excluded.docker_image, docker_image_size_bytes=excluded.docker_image_size_bytes,
                        binary_path=excluded.binary_path, updated_at=CURRENT_TIMESTAMP`,
                app.ID, app.Name, app.Description, app.Version, app.ExecutionType, app.DisplayMethod,
                app.NetworkMode, app.ManifestJSON, app.ManifestSignature, app.PublisherKey,
                app.SignatureAlgorithm, app.InstallStatus, app.DockerImage, app.DockerImageSizeBytes,
                app.BinaryPath)
        return err
}

func (s *SandboxStore) GetApp(id string) (*App, error) {
        var app App
        err := s.db.QueryRow(`SELECT id, name, description, version, execution_type, display_method,
                network_mode, manifest_json, manifest_signature, publisher_key, signature_algorithm,
                install_status, docker_image, docker_image_size_bytes, binary_path, created_at, updated_at
                FROM apps WHERE id = ?`, id).Scan(
                &app.ID, &app.Name, &app.Description, &app.Version, &app.ExecutionType, &app.DisplayMethod,
                &app.NetworkMode, &app.ManifestJSON, &app.ManifestSignature, &app.PublisherKey,
                &app.SignatureAlgorithm, &app.InstallStatus, &app.DockerImage, &app.DockerImageSizeBytes,
                &app.BinaryPath, &app.CreatedAt, &app.UpdatedAt)
        if err == sql.ErrNoRows {
                return nil, nil
        }
        if err != nil {
                return nil, err
        }
        return &app, nil
}

func (s *SandboxStore) ListApps() ([]App, error) {
        rows, err := s.db.Query(`SELECT id, name, description, version, execution_type, display_method,
                network_mode, manifest_json, manifest_signature, publisher_key, signature_algorithm,
                install_status, docker_image, docker_image_size_bytes, binary_path, created_at, updated_at
                FROM apps ORDER BY name`)
        if err != nil {
                return nil, err
        }
        defer rows.Close()

        var apps []App
        for rows.Next() {
                var app App
                if err := rows.Scan(&app.ID, &app.Name, &app.Description, &app.Version, &app.ExecutionType,
                        &app.DisplayMethod, &app.NetworkMode, &app.ManifestJSON, &app.ManifestSignature,
                        &app.PublisherKey, &app.SignatureAlgorithm, &app.InstallStatus, &app.DockerImage,
                        &app.DockerImageSizeBytes, &app.BinaryPath, &app.CreatedAt, &app.UpdatedAt); err != nil {
                        return nil, err
                }
                apps = append(apps, app)
        }
        if apps == nil {
                apps = []App{}
        }
        return apps, rows.Err()
}

func (s *SandboxStore) UpdateAppStatus(id string, status string) error {
        _, err := s.db.Exec("UPDATE apps SET install_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", status, id)
        return err
}

func (s *SandboxStore) DeleteApp(id string) error {
        _, err := s.db.Exec("DELETE FROM apps WHERE id = ?", id)
        return err
}

func (s *SandboxStore) SaveInstance(inst Instance) error {
        if inst.ID == "" {
                inst.ID = NewInstanceID()
        }
        _, err := s.db.Exec(`
                INSERT INTO instances (id, app_id, container_id, process_pid, status, proxy_port, display_port,
                        agent_api_port, network_name, tls_mode, log_level, cpu_limit, memory_limit_mb, disk_limit_mb,
                        egress_kbps, ingress_kbps, started_at, stopped_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                        container_id=excluded.container_id, process_pid=excluded.process_pid, status=excluded.status,
                        proxy_port=excluded.proxy_port, display_port=excluded.display_port,
                        agent_api_port=excluded.agent_api_port, network_name=excluded.network_name,
                        tls_mode=excluded.tls_mode, log_level=excluded.log_level, cpu_limit=excluded.cpu_limit,
                        memory_limit_mb=excluded.memory_limit_mb, disk_limit_mb=excluded.disk_limit_mb,
                        egress_kbps=excluded.egress_kbps, ingress_kbps=excluded.ingress_kbps,
                        started_at=excluded.started_at, stopped_at=excluded.stopped_at`,
                inst.ID, inst.AppID, inst.ContainerID, inst.ProcessPID, inst.Status, inst.ProxyPort,
                inst.DisplayPort, inst.AgentAPIPort, inst.NetworkName, inst.TLSMode, inst.LogLevel,
                inst.CPULimit, inst.MemoryLimitMB, inst.DiskLimitMB, inst.EgressKbps, inst.IngressKbps,
                inst.StartedAt, inst.StoppedAt)
        return err
}

func (s *SandboxStore) GetInstance(id string) (*Instance, error) {
        var inst Instance
        err := s.db.QueryRow(`SELECT id, app_id, container_id, process_pid, status, proxy_port, display_port,
                agent_api_port, network_name, tls_mode, log_level, cpu_limit, memory_limit_mb, disk_limit_mb,
                egress_kbps, ingress_kbps, started_at, stopped_at
                FROM instances WHERE id = ?`, id).Scan(
                &inst.ID, &inst.AppID, &inst.ContainerID, &inst.ProcessPID, &inst.Status, &inst.ProxyPort,
                &inst.DisplayPort, &inst.AgentAPIPort, &inst.NetworkName, &inst.TLSMode, &inst.LogLevel,
                &inst.CPULimit, &inst.MemoryLimitMB, &inst.DiskLimitMB, &inst.EgressKbps, &inst.IngressKbps,
                &inst.StartedAt, &inst.StoppedAt)
        if err == sql.ErrNoRows {
                return nil, nil
        }
        if err != nil {
                return nil, err
        }
        return &inst, nil
}

func (s *SandboxStore) GetInstancesByApp(appID string) ([]Instance, error) {
        rows, err := s.db.Query(`SELECT id, app_id, container_id, process_pid, status, proxy_port, display_port,
                agent_api_port, network_name, tls_mode, log_level, cpu_limit, memory_limit_mb, disk_limit_mb,
                egress_kbps, ingress_kbps, started_at, stopped_at
                FROM instances WHERE app_id = ? ORDER BY started_at DESC`, appID)
        if err != nil {
                return nil, err
        }
        defer rows.Close()

        var instances []Instance
        for rows.Next() {
                var inst Instance
                if err := rows.Scan(&inst.ID, &inst.AppID, &inst.ContainerID, &inst.ProcessPID, &inst.Status,
                        &inst.ProxyPort, &inst.DisplayPort, &inst.AgentAPIPort, &inst.NetworkName, &inst.TLSMode,
                        &inst.LogLevel, &inst.CPULimit, &inst.MemoryLimitMB, &inst.DiskLimitMB, &inst.EgressKbps,
                        &inst.IngressKbps, &inst.StartedAt, &inst.StoppedAt); err != nil {
                        return nil, err
                }
                instances = append(instances, inst)
        }
        if instances == nil {
                instances = []Instance{}
        }
        return instances, rows.Err()
}

func (s *SandboxStore) GetRunningInstances() ([]Instance, error) {
        rows, err := s.db.Query(`SELECT id, app_id, container_id, process_pid, status, proxy_port, display_port,
                agent_api_port, network_name, tls_mode, log_level, cpu_limit, memory_limit_mb, disk_limit_mb,
                egress_kbps, ingress_kbps, started_at, stopped_at
                FROM instances WHERE status IN ('starting', 'running') ORDER BY started_at DESC`)
        if err != nil {
                return nil, err
        }
        defer rows.Close()

        var instances []Instance
        for rows.Next() {
                var inst Instance
                if err := rows.Scan(&inst.ID, &inst.AppID, &inst.ContainerID, &inst.ProcessPID, &inst.Status,
                        &inst.ProxyPort, &inst.DisplayPort, &inst.AgentAPIPort, &inst.NetworkName, &inst.TLSMode,
                        &inst.LogLevel, &inst.CPULimit, &inst.MemoryLimitMB, &inst.DiskLimitMB, &inst.EgressKbps,
                        &inst.IngressKbps, &inst.StartedAt, &inst.StoppedAt); err != nil {
                        return nil, err
                }
                instances = append(instances, inst)
        }
        if instances == nil {
                instances = []Instance{}
        }
        return instances, rows.Err()
}

func (s *SandboxStore) UpdateInstanceStatus(id string, status string) error {
        q := "UPDATE instances SET status = ? WHERE id = ?"
        if status == "stopped" || status == "error" {
                q = "UPDATE instances SET status = ?, stopped_at = CURRENT_TIMESTAMP WHERE id = ?"
        }
        _, err := s.db.Exec(q, status, id)
        return err
}

func (s *SandboxStore) InsertProxyLog(pl ProxyLog) (int64, error) {
        result, err := s.db.Exec(`
                INSERT INTO proxy_logs (instance_id, direction, method, url, domain, status_code,
                        request_headers, request_body, response_headers, response_body,
                        bytes_sent, bytes_received, policy_action, policy_rule)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                pl.InstanceID, pl.Direction, pl.Method, pl.URL, pl.Domain, pl.StatusCode,
                pl.RequestHeaders, pl.RequestBody, pl.ResponseHeaders, pl.ResponseBody,
                pl.BytesSent, pl.BytesReceived, pl.PolicyAction, pl.PolicyRule)
        if err != nil {
                return 0, err
        }
        return result.LastInsertId()
}

func (s *SandboxStore) QueryProxyLogs(filter ProxyLogFilter) ([]ProxyLog, error) {
        query := "SELECT id, instance_id, direction, method, url, domain, status_code, request_headers, request_body, response_headers, response_body, bytes_sent, bytes_received, policy_action, policy_rule, timestamp FROM proxy_logs WHERE 1=1"
        var args []interface{}

        if filter.InstanceID != "" {
                query += " AND instance_id = ?"
                args = append(args, filter.InstanceID)
        }
        if filter.Domain != "" {
                query += " AND domain = ?"
                args = append(args, filter.Domain)
        }
        if filter.StatusCode != nil {
                query += " AND status_code = ?"
                args = append(args, *filter.StatusCode)
        }
        if filter.PolicyAction != "" {
                query += " AND policy_action = ?"
                args = append(args, filter.PolicyAction)
        }
        if filter.Direction != "" {
                query += " AND direction = ?"
                args = append(args, filter.Direction)
        }
        if filter.Since != nil {
                query += " AND timestamp >= ?"
                args = append(args, filter.Since.UTC().Format(time.RFC3339))
        }
        if filter.Until != nil {
                query += " AND timestamp <= ?"
                args = append(args, filter.Until.UTC().Format(time.RFC3339))
        }

        query += " ORDER BY timestamp DESC"

        if filter.Limit > 0 {
                query += " LIMIT ?"
                args = append(args, filter.Limit)
        } else {
                query += " LIMIT 1000"
        }
        if filter.Offset > 0 {
                query += " OFFSET ?"
                args = append(args, filter.Offset)
        }

        rows, err := s.db.Query(query, args...)
        if err != nil {
                return nil, err
        }
        defer rows.Close()

        var logs []ProxyLog
        for rows.Next() {
                var pl ProxyLog
                if err := rows.Scan(&pl.ID, &pl.InstanceID, &pl.Direction, &pl.Method, &pl.URL, &pl.Domain,
                        &pl.StatusCode, &pl.RequestHeaders, &pl.RequestBody, &pl.ResponseHeaders, &pl.ResponseBody,
                        &pl.BytesSent, &pl.BytesReceived, &pl.PolicyAction, &pl.PolicyRule, &pl.Timestamp); err != nil {
                        return nil, err
                }
                logs = append(logs, pl)
        }
        if logs == nil {
                logs = []ProxyLog{}
        }
        return logs, rows.Err()
}

func (s *SandboxStore) GetHeldProxyLogs(instanceID string) ([]ProxyLog, error) {
        return s.QueryProxyLogs(ProxyLogFilter{
                InstanceID:   instanceID,
                PolicyAction: "held",
        })
}

func (s *SandboxStore) UpdateProxyLogAction(id int64, action string, rule string) error {
        _, err := s.db.Exec("UPDATE proxy_logs SET policy_action = ?, policy_rule = ? WHERE id = ?", action, rule, id)
        return err
}

func (s *SandboxStore) SavePolicyRule(rule PolicyRule) (int64, error) {
        result, err := s.db.Exec(`INSERT INTO policy_rules (app_id, rule_type, target, source) VALUES (?, ?, ?, ?)`,
                rule.AppID, rule.RuleType, rule.Target, rule.Source)
        if err != nil {
                return 0, err
        }
        return result.LastInsertId()
}

func (s *SandboxStore) GetPolicyRules(appID string) ([]PolicyRule, error) {
        rows, err := s.db.Query("SELECT id, app_id, rule_type, target, source, created_at FROM policy_rules WHERE app_id = ? ORDER BY created_at", appID)
        if err != nil {
                return nil, err
        }
        defer rows.Close()

        var rules []PolicyRule
        for rows.Next() {
                var r PolicyRule
                if err := rows.Scan(&r.ID, &r.AppID, &r.RuleType, &r.Target, &r.Source, &r.CreatedAt); err != nil {
                        return nil, err
                }
                rules = append(rules, r)
        }
        if rules == nil {
                rules = []PolicyRule{}
        }
        return rules, rows.Err()
}

func (s *SandboxStore) DeletePolicyRule(id int64) error {
        _, err := s.db.Exec("DELETE FROM policy_rules WHERE id = ?", id)
        return err
}

func (s *SandboxStore) SaveResourceRequest(req ResourceRequest) (int64, error) {
        result, err := s.db.Exec(`INSERT INTO resource_requests (instance_id, app_id, resource_type, resource_target, status) VALUES (?, ?, ?, ?, ?)`,
                req.InstanceID, req.AppID, req.ResourceType, req.ResourceTarget, req.Status)
        if err != nil {
                return 0, err
        }
        return result.LastInsertId()
}

func (s *SandboxStore) GetPendingResourceRequests(appID string) ([]ResourceRequest, error) {
        rows, err := s.db.Query(`SELECT id, instance_id, app_id, resource_type, resource_target, status, requested_at, resolved_at, resolved_by
                FROM resource_requests WHERE app_id = ? AND status = 'pending' ORDER BY requested_at`, appID)
        if err != nil {
                return nil, err
        }
        defer rows.Close()

        var reqs []ResourceRequest
        for rows.Next() {
                var r ResourceRequest
                if err := rows.Scan(&r.ID, &r.InstanceID, &r.AppID, &r.ResourceType, &r.ResourceTarget,
                        &r.Status, &r.RequestedAt, &r.ResolvedAt, &r.ResolvedBy); err != nil {
                        return nil, err
                }
                reqs = append(reqs, r)
        }
        if reqs == nil {
                reqs = []ResourceRequest{}
        }
        return reqs, rows.Err()
}

func (s *SandboxStore) ResolveResourceRequest(id int64, status string, resolvedBy string) error {
        _, err := s.db.Exec("UPDATE resource_requests SET status = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by = ? WHERE id = ?",
                status, resolvedBy, id)
        return err
}

func (s *SandboxStore) InsertPolicyDecision(pd PolicyDecision) (int64, error) {
        result, err := s.db.Exec(`INSERT INTO policy_decisions (instance_id, app_id, decision_type, action, target, reason, decided_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
                pd.InstanceID, pd.AppID, pd.DecisionType, pd.Action, pd.Target, pd.Reason, pd.DecidedBy)
        if err != nil {
                return 0, err
        }
        return result.LastInsertId()
}

func (s *SandboxStore) InsertEvent(evt Event) (int64, error) {
        result, err := s.db.Exec(`INSERT INTO events (instance_id, app_id, event_type, event_data) VALUES (?, ?, ?, ?)`,
                evt.InstanceID, evt.AppID, evt.EventType, evt.EventData)
        if err != nil {
                return 0, err
        }
        return result.LastInsertId()
}

func (s *SandboxStore) GetEvents(appID string, eventType string, limit int) ([]Event, error) {
        query := "SELECT id, instance_id, app_id, event_type, event_data, timestamp FROM events WHERE 1=1"
        var args []interface{}

        if appID != "" {
                query += " AND app_id = ?"
                args = append(args, appID)
        }
        if eventType != "" {
                query += " AND event_type = ?"
                args = append(args, eventType)
        }

        query += " ORDER BY timestamp DESC"
        if limit > 0 {
                query += " LIMIT ?"
                args = append(args, limit)
        } else {
                query += " LIMIT 100"
        }

        rows, err := s.db.Query(query, args...)
        if err != nil {
                return nil, err
        }
        defer rows.Close()

        var events []Event
        for rows.Next() {
                var e Event
                if err := rows.Scan(&e.ID, &e.InstanceID, &e.AppID, &e.EventType, &e.EventData, &e.Timestamp); err != nil {
                        return nil, err
                }
                events = append(events, e)
        }
        if events == nil {
                events = []Event{}
        }
        return events, rows.Err()
}

func (s *SandboxStore) Prune() error {
        cutoff := time.Now().Add(-time.Duration(defaultRetentionDays) * 24 * time.Hour).UTC().Format(time.RFC3339)

        tx, err := s.db.Begin()
        if err != nil {
                return fmt.Errorf("failed to begin prune transaction: %w", err)
        }

        result, err := tx.Exec("DELETE FROM proxy_logs WHERE timestamp < ?", cutoff)
        if err != nil {
                tx.Rollback()
                return fmt.Errorf("failed to prune proxy_logs by age: %w", err)
        }
        logsDeleted, _ := result.RowsAffected()

        result, err = tx.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
        if err != nil {
                tx.Rollback()
                return fmt.Errorf("failed to prune events by age: %w", err)
        }
        eventsDeleted, _ := result.RowsAffected()

        result, err = tx.Exec("DELETE FROM policy_decisions WHERE timestamp < ?", cutoff)
        if err != nil {
                tx.Rollback()
                return fmt.Errorf("failed to prune policy_decisions by age: %w", err)
        }
        decisionsDeleted, _ := result.RowsAffected()

        if err := tx.Commit(); err != nil {
                return fmt.Errorf("failed to commit prune transaction: %w", err)
        }

        if logsDeleted > 0 || eventsDeleted > 0 || decisionsDeleted > 0 {
                log.Printf("[sandbox] Pruned %d proxy_logs, %d events, %d policy_decisions older than %d days",
                        logsDeleted, eventsDeleted, decisionsDeleted, defaultRetentionDays)
        }

        if err := s.pruneBySizePerApp(); err != nil {
                log.Printf("[sandbox] Size-based pruning failed (non-fatal): %v", err)
        }

        return nil
}

func (s *SandboxStore) pruneBySizePerApp() error {
        maxBytes := int64(defaultMaxSizeMB) * 1024 * 1024

        rows, err := s.db.Query("SELECT DISTINCT app_id FROM instances")
        if err != nil {
                return err
        }
        defer rows.Close()

        var appIDs []string
        for rows.Next() {
                var appID string
                if err := rows.Scan(&appID); err != nil {
                        return err
                }
                appIDs = append(appIDs, appID)
        }

        for _, appID := range appIDs {
                var totalSize int64
                err := s.db.QueryRow(`
                        SELECT COALESCE(SUM(
                                COALESCE(LENGTH(method), 0) + COALESCE(LENGTH(url), 0) + COALESCE(LENGTH(domain), 0) +
                                COALESCE(LENGTH(request_headers), 0) + COALESCE(LENGTH(request_body), 0) +
                                COALESCE(LENGTH(response_headers), 0) + COALESCE(LENGTH(response_body), 0) +
                                COALESCE(LENGTH(policy_action), 0) + COALESCE(LENGTH(policy_rule), 0) + 100
                        ), 0)
                        FROM proxy_logs pl
                        JOIN instances i ON pl.instance_id = i.id
                        WHERE i.app_id = ?`, appID).Scan(&totalSize)
                if err != nil {
                        continue
                }

                if totalSize <= maxBytes {
                        continue
                }

                deleteCount := (totalSize - maxBytes) * 100 / totalSize
                if deleteCount < 10 {
                        deleteCount = 10
                }

                result, err := s.db.Exec(`
                        DELETE FROM proxy_logs WHERE id IN (
                                SELECT pl.id FROM proxy_logs pl
                                JOIN instances i ON pl.instance_id = i.id
                                WHERE i.app_id = ?
                                ORDER BY pl.timestamp ASC
                                LIMIT ?
                        )`, appID, deleteCount)
                if err != nil {
                        log.Printf("[sandbox] Size pruning failed for app %s: %v", appID, err)
                        continue
                }
                deleted, _ := result.RowsAffected()
                if deleted > 0 {
                        log.Printf("[sandbox] Size-pruned %d proxy_logs for app %s (was %d MB, cap %d MB)",
                                deleted, appID, totalSize/(1024*1024), defaultMaxSizeMB)
                }
        }

        return nil
}

func (s *SandboxStore) startPruneLoop() {
        s.pruneWg.Add(1)
        go func() {
                defer s.pruneWg.Done()
                ticker := time.NewTicker(pruneInterval)
                defer ticker.Stop()

                for {
                        select {
                        case <-ticker.C:
                                if err := s.Prune(); err != nil {
                                        log.Printf("[sandbox] Scheduled prune failed: %v", err)
                                }
                        case <-s.pruneStop:
                                return
                        }
                }
        }()
}

func (s *SandboxStore) DB() *sql.DB {
        return s.db
}
