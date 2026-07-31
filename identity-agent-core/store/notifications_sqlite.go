package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Things another agent told this one.
//
// Before this there was nowhere to put such a thing. /api/alerts computed itself
// fresh on every request from pending contacts, pending requests and pending
// credentials — a view over three approval queues, owning no table. Anything
// that was not one of those three could not be shown at all, however urgent, and
// the only party who could tell you something was one asking your permission.
//
// The shape follows signing_requests deliberately. That table is the closest
// existing relative: a persisted queue of typed items, each with plain language
// for a person, a status lifecycle and an expiry. The difference is the axis —
// a signing request waits for the device holding the keys, a notification waits
// for the person.

// notificationColumns is the read list, written once so a column added to one
// query cannot be forgotten in another.
const notificationColumns = `id, from_aid, to_aid, kind, severity, title, body,
       payload, status, verified, received_at, read_at, expires_at`

func scanNotification(row interface{ Scan(...interface{}) error }) (*Notification, error) {
	var n Notification
	var verified int
	err := row.Scan(&n.ID, &n.FromAID, &n.ToAID, &n.Kind, &n.Severity, &n.Title,
		&n.Body, &n.Payload, &n.Status, &verified, &n.ReceivedAt, &n.ReadAt, &n.ExpiresAt)
	if err != nil {
		return nil, err
	}
	n.Verified = verified != 0
	return &n, nil
}

func (s *SQLiteStore) SaveNotification(n Notification) error {
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

	_, err := s.db.Exec(`
INSERT INTO notifications
    (`+notificationColumns+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
-- A notification is written once and never rewritten by a later delivery of
-- the same message. Two things follow, and both matter.
--
-- What was said cannot change underneath somebody. A sender who could re-send
-- the same id with different words could alter the text of something already
-- read and acted on.
--
-- And a redelivery cannot reopen it. The obvious version of this clause
-- updated status from the incoming row, so a duplicate arriving with the
-- default "unread" marked a message the person had already dealt with as new
-- again — every retry putting it back in front of them. SetNotificationStatus
-- is the only thing that moves status, because reading something is an act of
-- the reader, not of the sender.
ON CONFLICT(id) DO NOTHING`,
		n.ID, n.FromAID, n.ToAID, n.Kind, n.Severity, n.Title, n.Body,
		n.Payload, n.Status, boolToInt(n.Verified), n.ReceivedAt, n.ReadAt, n.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to save notification: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetNotification(id string) (*Notification, error) {
	n, err := scanNotification(s.db.QueryRow(
		`SELECT `+notificationColumns+` FROM notifications WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read notification: %w", err)
	}
	return n, nil
}

// GetNotifications returns the newest first.
//
// Newest first rather than oldest, unlike the signing queue: that is a list of
// work to get through, this is a list of what has happened, and the thing that
// happened most recently is the one somebody is looking for.
//
// An empty status means every status, so a client can show a history rather than
// only what is waiting.
func (s *SQLiteStore) GetNotifications(status string, limit int) ([]Notification, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT ` + notificationColumns + ` FROM notifications`
	args := []interface{}{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY received_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query notifications: %w", err)
	}
	defer rows.Close()

	var out []Notification
	for rows.Next() {
		n, err := scanNotification(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan notification: %w", err)
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// SetNotificationStatus marks one read or dismissed.
//
// Read and dismissed are separate states rather than one flag, because "I have
// seen this" and "stop showing me this" are different intentions and a person
// who has read something urgent has not necessarily dealt with it.
func (s *SQLiteStore) SetNotificationStatus(id, status string) error {
	switch status {
	case NotificationUnread, NotificationRead, NotificationDismissed:
	default:
		return fmt.Errorf("%q is not a notification status", status)
	}

	readAt := ""
	if status != NotificationUnread {
		readAt = time.Now().UTC().Format(time.RFC3339)
	}
	res, err := s.db.Exec(
		`UPDATE notifications SET status = ?, read_at = ? WHERE id = ?`, status, readAt, id)
	if err != nil {
		return fmt.Errorf("failed to update notification: %w", err)
	}
	// Reported rather than silently succeeding. A client that marks a
	// notification read and is told nothing would show it as read until the next
	// refresh put it back.
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("no notification %q", id)
	}
	return nil
}
