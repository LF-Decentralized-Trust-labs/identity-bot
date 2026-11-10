package watcher

import (
	"errors"
	"time"
)

// ErrFirstSeenConflict is returned by RecordFirstSeen when a different digest is
// offered for a position already observed. The first observation is kept.
var ErrFirstSeenConflict = errors.New("a different digest was already first seen at this position")

// Store persists watcher observations and alerts.
type Store interface {
	// RecordFirstSeen is first-wins: an existing row is only reinforced when the
	// digest is the same, otherwise it returns ErrFirstSeenConflict.
	RecordFirstSeen(rec FirstSeenRecord) error
	GetFirstSeen(aid string, seq int) (*FirstSeenRecord, error)
	ListFirstSeen(aid string) ([]FirstSeenRecord, error)
	InsertDuplicityAlert(alert DuplicityAlert) (int64, error)
	ListDuplicityAlerts(aid string) ([]DuplicityAlert, error)
	IsOptedOut(aid string) (bool, error)
	SetOptOut(aid string, optedOut bool) error
	GetConfig(key string) (string, error)
	SetConfig(key, value string) error
	PruneStale(before time.Time) (int, error)
}
