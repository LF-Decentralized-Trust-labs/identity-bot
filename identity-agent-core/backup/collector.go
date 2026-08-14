package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

// collectTier3 takes everything else this device holds.
//
// It used to name the files it wanted, which meant anything else on the device
// was silently absent from every backup — and required this core to know what
// software built on top of it keeps on disk, which it cannot and should not.
// Now it sweeps, and only an explicit, reasoned exclusion is left out. See
// everything_this_device_holds.go.
func (c *Collector) collectTier3(bundle *PayloadBundle, opts CollectOptions) ([]ExternalDataPointer, error) {
	// The sandbox index: what apps existed, without their payloads. Carried as
	// its own section because it is a summary the sweep deliberately excludes
	// the underlying files for.
	sandboxDir := filepath.Join(c.DataDir, "sandbox")
	if entries, err := os.ReadDir(sandboxDir); err == nil {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if err := c.addJSONSection(bundle, "sandbox_index",
			map[string]interface{}{"entries": names}); err != nil {
			return nil, err
		}
	}

	skipped, err := c.collectEveryOtherFile(bundle)
	if err != nil {
		return nil, err
	}

	// What was deliberately left out, recorded IN the archive. Otherwise
	// "nothing else was on this device" and "something was and we left it"
	// look identical to whoever opens this later.
	if len(skipped) > 0 {
		if err := c.addJSONSection(bundle, "not_carried", skipped); err != nil {
			return nil, err
		}
	}

	return nil, nil
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
