package watcher

import "time"

// Store persists watcher observations and alerts.
type Store interface {
	RecordFirstSeen(rec FirstSeenRecord) error
	// The reads of what this watcher has seen and what it has caught are
	// unexported on purpose: only this package can call them, and it calls them
	// from the opt-out check (Service.Disclosable, DisclosableAll and
	// DisclosableAlerts) and from its own verification. Another package cannot
	// read a first-seen record or a duplicity alert without the check.
	getFirstSeen(aid string, seq int) (*FirstSeenRecord, error)
	listFirstSeen(aid string) ([]FirstSeenRecord, error)
	InsertDuplicityAlert(alert DuplicityAlert) (int64, error)
	listDuplicityAlerts(aid string) ([]DuplicityAlert, error)
	IsOptedOut(aid string) (bool, error)
	SetOptOut(aid string, optedOut bool) error
	GetConfig(key string) (string, error)
	SetConfig(key, value string) error
	PruneIntermediate(aid string, keepSeqs []int) error
	PruneStale(before time.Time) (int, error)
}
