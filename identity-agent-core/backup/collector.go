package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// CollectOptions controls which tiers are gathered.
//
// It used to carry LeanTier3 and LogWindowDays as well — externalise bulk,
// keep pointers only; a thirty-day log window. Both were declared, defaulted,
// threaded through every call and never read: collectTier3 ignored its options
// entirely and no ExternalDataPointer was ever constructed. Options that do
// nothing are worse than absent, because they read as decisions somebody made.
// The job they described is done by the exclusions in
// everything_this_device_holds.go, where each one says what it leaves out and
// why.
type CollectOptions struct {
	Tiers []string
}

func DefaultCollectOptions(tiers []string) CollectOptions {
	return CollectOptions{Tiers: tiers}
}

// Collector gathers identity data from the agent data directory.
type Collector struct {
	DataDir string
	Store   store.Store

	// NotCarried is what the last Collect deliberately left out, so a caller
	// can put it in front of somebody rather than it being knowable only by
	// opening the archive.
	NotCarried []SkippedFile
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

	// The identity database, taken as a snapshot rather than read off disk.
	//
	// A failure to snapshot fails the whole collection. This used to be an
	// ignored error — os.ReadFile with `err == nil`, so an unreadable database
	// produced an archive with no database section and no complaint. That is
	// the same class of bug as the WAL one SnapshotSQLite exists to fix: the
	// archive is valid and incomplete, and nobody learns which until they try
	// to recover from it.
	if sqlStore, ok := c.Store.(*store.SQLiteStore); ok {
		data, err := SnapshotSQLite(sqlStore.DB(), c.DataDir)
		if err != nil {
			return fmt.Errorf("identity database: %w", err)
		}
		c.addRawSection(bundle, "sqlite_identity_db", data)
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

	// What this identity chose about being coerced, in tier 1.
	//
	// It lived only in the tier-3 sweep, which nothing requests: the default
	// tiers are tier1 and tier2 in Go and hardcoded twice in the Dart client,
	// and no screen can select tier 3. So somebody set a duress policy, the
	// agent stored it and read it back and confirmed it — and it was absent
	// from every archive, which is the only place a recovering device can
	// learn it. The gate then found nothing and passed.
	//
	// It belongs in tier 1 regardless of that bug: it is a property of the
	// identity that governs how the identity may be recovered, which is the
	// same class of thing as the key material beside it.
	if raw, err := os.ReadFile(filepath.Join(c.DataDir, "duress_policy.json")); err == nil && len(raw) > 0 {
		c.addRawSection(bundle, "file:duress_policy.json", raw)
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
		// And said out loud, which it never was. It was written into the
		// archive and read by nothing — no log line, no screen — so the one
		// record of what a backup does not contain lived where nobody would
		// find it until they were already trying to recover from it.
		for _, s := range skipped {
			log.Printf("[backup] not carried: %s (%s)", s.Path, s.Reason)
		}
	}
	c.NotCarried = skipped

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
