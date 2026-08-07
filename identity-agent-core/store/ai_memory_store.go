package store

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// AIMemoryStore manages the AI Memory domain (ai-memory.db).
// It stores AI conversation history and per-app AI settings.
// This is distinct from human communications (email, SMS) — see communications.db (future).
//
// User-facing name: "AI Hub"
// Developer-facing name: "AI Memory domain"
type AIMemoryStore struct {
	db *sql.DB
}

// Conversation represents a single AI chat session.
type Conversation struct {
	ID        string `json:"id"`
	SourceApp string `json:"source_app"` // "openwebui", "openclaw", etc.
	Title     string `json:"title"`
	Model     string `json:"model,omitempty"`
	CreatedAt int64  `json:"created_at"`  // Unix timestamp
	UpdatedAt int64  `json:"updated_at"`  // Unix timestamp
	Archived  bool   `json:"archived"`
}

// Message represents a single turn in an AI conversation.
type Message struct {
	ID             string `json:"id"`
	ConversationID string `json:"conversation_id"`
	Role           string `json:"role"`    // "user", "assistant", "system"
	Content        string `json:"content"`
	Model          string `json:"model,omitempty"`
	Timestamp      int64  `json:"timestamp"` // Unix timestamp
	TokenCount     int    `json:"token_count,omitempty"`
}

// AISetting is a key-value setting scoped to a specific AI app.
type AISetting struct {
	AppID     string `json:"app_id"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	UpdatedAt int64  `json:"updated_at"`
}

// NewAIMemoryStore opens (or creates) ai-memory.db in the given data directory.
func NewAIMemoryStore(dir string) (*AIMemoryStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	dbPath := filepath.Join(dir, "ai-memory.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ai-memory.db: %w", err)
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma (%s): %w", p, err)
		}
	}

	s := &AIMemoryStore{db: db}
	if err := s.applyMigrations(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to apply ai-memory migrations: %w", err)
	}

	log.Printf("[ai-memory] Initialized AI Memory store at: %s", dbPath)
	return s, nil
}

func (s *AIMemoryStore) Close() error {
	return s.db.Close()
}

// ── Migrations ────────────────────────────────────────────────────────────────

func (s *AIMemoryStore) applyMigrations() error {
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS ai_memory_schema_migrations (
			version     INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return err
	}

	var current int
	s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM ai_memory_schema_migrations`).Scan(&current)

	migrations := []struct {
		version     int
		description string
		sql         string
	}{
		{
			version:     1,
			description: "Initial AI Memory schema with FTS5",
			sql: `
CREATE TABLE IF NOT EXISTS conversations (
    id          TEXT PRIMARY KEY,
    source_app  TEXT NOT NULL DEFAULT '',
    title       TEXT NOT NULL DEFAULT '',
    model       TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL DEFAULT 0,
    archived    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_conversations_source ON conversations(source_app);
CREATE INDEX IF NOT EXISTS idx_conversations_updated ON conversations(updated_at DESC);

CREATE TABLE IF NOT EXISTS messages (
    id              TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,
    content         TEXT NOT NULL DEFAULT '',
    model           TEXT NOT NULL DEFAULT '',
    timestamp       INTEGER NOT NULL DEFAULT 0,
    token_count     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(timestamp DESC);

-- FTS5 virtual table for semantic-ish keyword search across message content
-- Stepping stone before full vector DB integration
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    content,
    conversation_id UNINDEXED,
    content='messages',
    content_rowid='rowid',
    tokenize='porter unicode61'
);

-- Triggers to keep FTS index in sync with messages table
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, content, conversation_id)
    VALUES (new.rowid, new.content, new.conversation_id);
END;

CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content, conversation_id)
    VALUES ('delete', old.rowid, old.content, old.conversation_id);
END;

CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content, conversation_id)
    VALUES ('delete', old.rowid, old.content, old.conversation_id);
    INSERT INTO messages_fts(rowid, content, conversation_id)
    VALUES (new.rowid, new.content, new.conversation_id);
END;

CREATE TABLE IF NOT EXISTS ai_settings (
    app_id      TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (app_id, key)
);
`,
		},
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}

		log.Printf("[ai-memory] Applying migration %d: %s", m.version, m.description)

		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", m.version, err)
		}
		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", m.version, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO ai_memory_schema_migrations (version, description) VALUES (?, ?)`,
			m.version, m.description,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.version, err)
		}
		log.Printf("[ai-memory] Migration %d applied", m.version)
	}

	return nil
}

// ── Conversations ─────────────────────────────────────────────────────────────

// SaveConversation creates or updates a conversation record.
func (s *AIMemoryStore) SaveConversation(conv Conversation) error {
	if conv.CreatedAt == 0 {
		conv.CreatedAt = time.Now().Unix()
	}
	conv.UpdatedAt = time.Now().Unix()

	_, err := s.db.Exec(`
		INSERT INTO conversations (id, source_app, title, model, created_at, updated_at, archived)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			source_app = excluded.source_app,
			title      = excluded.title,
			model      = excluded.model,
			updated_at = excluded.updated_at,
			archived   = excluded.archived`,
		conv.ID, conv.SourceApp, conv.Title, conv.Model,
		conv.CreatedAt, conv.UpdatedAt, boolToInt(conv.Archived),
	)
	if err != nil {
		return fmt.Errorf("failed to save conversation: %w", err)
	}
	return nil
}

// GetConversations returns all conversations, newest first.
func (s *AIMemoryStore) GetConversations(includeArchived bool) ([]Conversation, error) {
	query := `SELECT id, source_app, title, model, created_at, updated_at, archived
	          FROM conversations`
	if !includeArchived {
		query += ` WHERE archived = 0`
	}
	query += ` ORDER BY updated_at DESC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query conversations: %w", err)
	}
	defer rows.Close()
	return scanConversations(rows)
}

// GetConversation returns a single conversation by ID.
func (s *AIMemoryStore) GetConversation(id string) (*Conversation, error) {
	rows, err := s.db.Query(
		`SELECT id, source_app, title, model, created_at, updated_at, archived
		 FROM conversations WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("failed to query conversation: %w", err)
	}
	defer rows.Close()

	convs, err := scanConversations(rows)
	if err != nil {
		return nil, err
	}
	if len(convs) == 0 {
		return nil, nil
	}
	return &convs[0], nil
}

// DeleteConversation deletes a conversation and all its messages (via CASCADE).
func (s *AIMemoryStore) DeleteConversation(id string) error {
	_, err := s.db.Exec(`DELETE FROM conversations WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete conversation: %w", err)
	}
	return nil
}

// ArchiveConversation marks a conversation as archived.
func (s *AIMemoryStore) ArchiveConversation(id string, archived bool) error {
	_, err := s.db.Exec(
		`UPDATE conversations SET archived = ?, updated_at = ? WHERE id = ?`,
		boolToInt(archived), time.Now().Unix(), id,
	)
	return err
}

func scanConversations(rows *sql.Rows) ([]Conversation, error) {
	var convs []Conversation
	for rows.Next() {
		var c Conversation
		var archived int
		if err := rows.Scan(&c.ID, &c.SourceApp, &c.Title, &c.Model,
			&c.CreatedAt, &c.UpdatedAt, &archived); err != nil {
			return nil, fmt.Errorf("failed to scan conversation: %w", err)
		}
		c.Archived = archived != 0
		convs = append(convs, c)
	}
	if convs == nil {
		convs = []Conversation{}
	}
	return convs, nil
}

// ── Messages ──────────────────────────────────────────────────────────────────

// SaveMessage adds a message to a conversation.
func (s *AIMemoryStore) SaveMessage(msg Message) error {
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().Unix()
	}
	_, err := s.db.Exec(`
		INSERT INTO messages (id, conversation_id, role, content, model, timestamp, token_count)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			role        = excluded.role,
			content     = excluded.content,
			model       = excluded.model,
			timestamp   = excluded.timestamp,
			token_count = excluded.token_count`,
		msg.ID, msg.ConversationID, msg.Role, msg.Content,
		msg.Model, msg.Timestamp, msg.TokenCount,
	)
	if err != nil {
		return fmt.Errorf("failed to save message: %w", err)
	}

	// Update conversation's updated_at timestamp
	s.db.Exec(`UPDATE conversations SET updated_at = ? WHERE id = ?`,
		msg.Timestamp, msg.ConversationID)

	return nil
}

// GetMessages returns all messages for a conversation, in chronological order.
func (s *AIMemoryStore) GetMessages(conversationID string) ([]Message, error) {
	rows, err := s.db.Query(
		`SELECT id, conversation_id, role, content, model, timestamp, token_count
		 FROM messages WHERE conversation_id = ? ORDER BY timestamp ASC`, conversationID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer rows.Close()
	return scanMessages(rows)
}

// SearchMessages performs a full-text search across message content using FTS5.
// Returns matching messages with their conversation context.
func (s *AIMemoryStore) SearchMessages(query string, limit int) ([]Message, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
		SELECT m.id, m.conversation_id, m.role, m.content, m.model, m.timestamp, m.token_count
		FROM messages m
		JOIN messages_fts f ON m.rowid = f.rowid
		WHERE messages_fts MATCH ?
		ORDER BY rank
		LIMIT ?`, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search messages: %w", err)
	}
	defer rows.Close()
	return scanMessages(rows)
}

func scanMessages(rows *sql.Rows) ([]Message, error) {
	var messages []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content,
			&m.Model, &m.Timestamp, &m.TokenCount); err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, m)
	}
	if messages == nil {
		messages = []Message{}
	}
	return messages, nil
}

// ── AI Settings ───────────────────────────────────────────────────────────────

// GetAISetting retrieves a setting value for a specific app and key.
func (s *AIMemoryStore) GetAISetting(appID, key string) (string, error) {
	var value string
	err := s.db.QueryRow(
		`SELECT value FROM ai_settings WHERE app_id = ? AND key = ?`, appID, key,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get AI setting: %w", err)
	}
	return value, nil
}

// SetAISetting stores a setting value for a specific app and key.
func (s *AIMemoryStore) SetAISetting(appID, key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO ai_settings (app_id, key, value, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(app_id, key) DO UPDATE SET
			value      = excluded.value,
			updated_at = excluded.updated_at`,
		appID, key, value, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to set AI setting: %w", err)
	}
	return nil
}

// GetAISettings returns all settings for a specific app.
func (s *AIMemoryStore) GetAISettings(appID string) ([]AISetting, error) {
	rows, err := s.db.Query(
		`SELECT app_id, key, value, updated_at FROM ai_settings WHERE app_id = ? ORDER BY key ASC`, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get AI settings: %w", err)
	}
	defer rows.Close()

	var settings []AISetting
	for rows.Next() {
		var s AISetting
		if err := rows.Scan(&s.AppID, &s.Key, &s.Value, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan AI setting: %w", err)
		}
		settings = append(settings, s)
	}
	if settings == nil {
		settings = []AISetting{}
	}
	return settings, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
