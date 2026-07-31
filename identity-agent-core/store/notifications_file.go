package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// The file-backed half of the notification store.
//
// Store has two implementations and the interface binds both, so a method added
// for SQLite that is not added here does not fail at the call site — it fails
// the build, which is the right place. FileStore is not constructed at runtime
// any more, but it is still the interface's second implementation and leaving it
// half-built would make the next person wonder which parts are real.

func (s *FileStore) notificationsPath() string {
	return filepath.Join(s.dir, "notifications.json")
}

func (s *FileStore) loadNotifications() (map[string]Notification, error) {
	data, err := os.ReadFile(s.notificationsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Notification{}, nil
		}
		return nil, fmt.Errorf("failed to read notifications: %w", err)
	}
	out := map[string]Notification{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("failed to parse notifications: %w", err)
	}
	return out, nil
}

func (s *FileStore) saveNotifications(m map[string]Notification) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.notificationsPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("failed to write notifications: %w", err)
	}
	if err := os.Rename(tmp, s.notificationsPath()); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to replace notifications: %w", err)
	}
	return nil
}

func (s *FileStore) SaveNotification(n Notification) error {
	if n.ID == "" {
		return fmt.Errorf("a notification needs an id, or it can never be marked read")
	}
	if n.ReceivedAt == "" {
		n.ReceivedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if n.Status == "" {
		n.Status = NotificationUnread
	}
	if n.Severity == "" {
		n.Severity = NotificationInfo
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadNotifications()
	if err != nil {
		return err
	}
	// Same rule as the SQLite side: written once, never rewritten by a later
	// delivery of the same message. It cannot change what was said, and it
	// cannot mark something the person has already dealt with as new again.
	if _, exists := all[n.ID]; exists {
		return nil
	}
	all[n.ID] = n
	return s.saveNotifications(all)
}

func (s *FileStore) GetNotification(id string) (*Notification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all, err := s.loadNotifications()
	if err != nil {
		return nil, err
	}
	n, ok := all[id]
	if !ok {
		return nil, nil
	}
	return &n, nil
}

func (s *FileStore) GetNotifications(status string, limit int) ([]Notification, error) {
	if limit <= 0 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	all, err := s.loadNotifications()
	if err != nil {
		return nil, err
	}
	var out []Notification
	for _, n := range all {
		if status == "" || n.Status == status {
			out = append(out, n)
		}
	}
	// Newest first, matching the SQLite side. Ties broken by id so the order is
	// stable rather than whatever the map iteration gave.
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReceivedAt != out[j].ReceivedAt {
			return out[i].ReceivedAt > out[j].ReceivedAt
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *FileStore) SetNotificationStatus(id, status string) error {
	switch status {
	case NotificationUnread, NotificationRead, NotificationDismissed:
	default:
		return fmt.Errorf("%q is not a notification status", status)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.loadNotifications()
	if err != nil {
		return err
	}
	n, ok := all[id]
	if !ok {
		return fmt.Errorf("no notification %q", id)
	}
	n.Status = status
	n.ReadAt = ""
	if status != NotificationUnread {
		n.ReadAt = time.Now().UTC().Format(time.RFC3339)
	}
	all[id] = n
	return s.saveNotifications(all)
}
