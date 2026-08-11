package watcher

import "time"

// Store persists watcher observations and alerts.
type Store interface {
	RecordFirstSeen(rec FirstSeenRecord) error
	GetFirstSeen(aid string, seq int) (*FirstSeenRecord, error)
	ListFirstSeen(aid string) ([]FirstSeenRecord, error)
	InsertDuplicityAlert(alert DuplicityAlert) (int64, error)
	ListDuplicityAlerts(aid string) ([]DuplicityAlert, error)
	IsOptedOut(aid string) (bool, error)
	SetOptOut(aid string, optedOut bool) error
	GetConfig(key string) (string, error)
	SetConfig(key, value string) error
	PruneIntermediate(aid string, keepSeqs []int) error
	PruneStale(before time.Time) (int, error)
}
