package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// CollectOptions controls which tiers are gathered.
type CollectOptions struct {
	Tiers         []string
	LeanTier3     bool // default true — externalize bulk, keep pointers only
	LogWindowDays int  // local log retention window (default 30)
}

func DefaultCollectOptions(tiers []string) CollectOptions {
	return CollectOptions{
		Tiers:         tiers,
		LeanTier3:     true,
		LogWindowDays: 30,
	}
}

// Collector gathers identity data from the agent data directory.
type Collector struct {
	DataDir string
	Store   store.Store
}

// Collect builds a payload bundle for the requested tiers.
func (c *Collector) Collect(opts CollectOptions) (*PayloadBundle, []ExternalDataPointer, error) {
	if len(opts.Tiers) == 0 {
		opts.Tiers = []string{TierCritical}
	}
	bundle := &PayloadBundle{Sections: map[string][]byte{}, Ordered: []PayloadSection{}}
	var pointers []ExternalDataPointer

	tierSet := map[string]bool{}
	for _, t := range opts.Tiers {
		tierSet[t] = true
	}

	// Tier 1 — always included when any tier is requested.
	if tierSet[TierCritical] || tierSet[TierImportant] || tierSet[TierFull] {
		if err := c.collectTier1(bundle); err != nil {
			return nil, nil, err
		}
	}

	if tierSet[TierImportant] || tierSet[TierFull] {
		if err := c.collectTier2(bundle); err != nil {
			return nil, nil, err
		}
	}

	if tierSet[TierFull] {
		ptrs, err := c.collectTier3(bundle, opts)
		if err != nil {
			return nil, nil, err
		}
		pointers = append(pointers, ptrs...)
	}

	return bundle, pointers, nil
}

func (c *Collector) collectTier1(bundle *PayloadBundle) error {
	identity, err := c.Store.GetIdentity()
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if identity != nil {
		if err := c.addJSONSection(bundle, "identity_state", identity); err != nil {
			return err
		}
	}

	var events []store.EventRecord
	if identity != nil {
		events, err = c.Store.GetEvents(identity.AID)
		if err != nil {
			return fmt.Errorf("kel: %w", err)
		}
	}
	if err := c.addJSONSection(bundle, "kel_events", events); err != nil {
		return err
	}

	// SQLite identity.db snapshot for tier1 tables.
	if sqlStore, ok := c.Store.(*store.SQLiteStore); ok {
		dbPath := filepath.Join(c.DataDir, "identity.db")
		if data, err := os.ReadFile(dbPath); err == nil {
			c.addRawSection(bundle, "sqlite_identity_db", data)
		}
		_ = sqlStore // used for type assertion path
	}

	// Login relationships (pairwise seeds) — tier1 key material.
	loginPath := filepath.Join(c.DataDir, "login_relationships.json")
	if data, err := os.ReadFile(loginPath); err == nil {
		c.addRawSection(bundle, "login_relationships", data)
	}

	// The root keystore seed — the HD derivation root every pairwise/login/asset/
	// audit key and the credential-vault key re-derive from. Captured UNWRAPPED
	// here (the archive payload is encrypted under the backup key), because the
	// on-disk copy may be sealed to this device's hardware: recovery on another
	// device must be mnemonic -> archive -> seed, never depend on the old
	// device's secure element. Without this section, device loss loses every
	// derived key even with a backup in hand.
	if seed, err := secureenclave.LoadRootSeed(c.DataDir); err == nil {
		c.addRawSection(bundle, "root_seed", seed)
	}

	return nil
}

func (c *Collector) collectTier2(bundle *PayloadBundle) error {
	contacts, err := c.Store.GetContacts()
	if err != nil {
		return fmt.Errorf("contacts: %w", err)
	}
	if err := c.addJSONSection(bundle, "contacts", contacts); err != nil {
		return err
	}

	creds, err := c.Store.GetCredentials()
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	if err := c.addJSONSection(bundle, "credentials", creds); err != nil {
		return err
	}

	settings, err := c.Store.GetSettings()
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	if err := c.addJSONSection(bundle, "settings", settings); err != nil {
		return err
	}

	pending, err := c.Store.GetPendingRequests()
	if err != nil {
		return fmt.Errorf("pending_requests: %w", err)
	}
	if err := c.addJSONSection(bundle, "pending_requests", pending); err != nil {
		return err
	}

	return nil
}

func (c *Collector) collectTier3(bundle *PayloadBundle, opts CollectOptions) ([]ExternalDataPointer, error) {
	var pointers []ExternalDataPointer

	// AI memory index — pointers only when lean mode (no bulk bytes).
	aiPath := filepath.Join(c.DataDir, "ai_memory.db")
	if st, err := os.Stat(aiPath); err == nil && !opts.LeanTier3 {
		data, err := os.ReadFile(aiPath)
		if err == nil {
			c.addRawSection(bundle, "ai_memory_db", data)
		}
	} else if err == nil {
		pointers = append(pointers, ExternalDataPointer{
			Domain:     "ai_memory",
			Locator:    aiPath,
			KeyRef:     "local:ai_memory.db",
			SizeBytes:  st.Size(),
			ArchivedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}

	// Sandbox — index manifest only, not container images or bulk app data.
	sandboxDir := filepath.Join(c.DataDir, "sandbox")
	if entries, err := os.ReadDir(sandboxDir); err == nil {
		index := map[string]interface{}{"entries": []string{}}
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		index["entries"] = names
		if err := c.addJSONSection(bundle, "sandbox_index", index); err != nil {
			return pointers, err
		}
	}

	// Logs — only recent window locally; older logs externalized as pointers.
	logsDir := filepath.Join(c.DataDir, "logs")
	cutoff := time.Now().AddDate(0, 0, -opts.LogWindowDays)
	_ = filepath.Walk(logsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.ModTime().Before(cutoff) {
			pointers = append(pointers, ExternalDataPointer{
				Domain:     "logs",
				Locator:    path,
				KeyRef:     fmt.Sprintf("local:%s", filepath.Base(path)),
				SizeBytes:  info.Size(),
				ArchivedAt: info.ModTime().UTC().Format(time.RFC3339),
			})
			return nil
		}
		if !opts.LeanTier3 {
			data, rerr := os.ReadFile(path)
			if rerr == nil {
				c.addRawSection(bundle, "log_"+filepath.Base(path), data)
			}
		}
		return nil
	})

	return pointers, nil
}

func (c *Collector) addJSONSection(bundle *PayloadBundle, name string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.addRawSection(bundle, name, data)
	return nil
}

func (c *Collector) addRawSection(bundle *PayloadBundle, name string, data []byte) {
	bundle.Sections[name] = data
	bundle.Ordered = append(bundle.Ordered, PayloadSection{Name: name, Data: data})
}

// ExportTableJSON exports a SQLite table as JSON rows (utility for tests).
func ExportTableJSON(db *sql.DB, table string) ([]byte, error) {
	rows, err := db.Query(fmt.Sprintf("SELECT * FROM %s", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var result []map[string]interface{}
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := map[string]interface{}{}
		for i, col := range cols {
			row[col] = vals[i]
		}
		result = append(result, row)
	}
	return json.Marshal(result)
}

// CopyFileSection reads a file into a section if it exists.
func CopyFileSection(bundle *PayloadBundle, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	bundle.Sections[name] = data
	bundle.Ordered = append(bundle.Ordered, PayloadSection{Name: name, Data: data})
	return nil
}