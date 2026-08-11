package store

import (
	"database/sql"
	"fmt"
	"time"
)

// The machines this identity has adopted.
//
// An owner adopts a machine, issues a delegation over the key that machine
// generated, and — until this existed — remembered none of it. The adoption
// result went back to whoever asked and nothing was written down, so an app
// that restarted had no idea the machine existed, while the machine itself
// knew exactly who its owner was. One side of a relationship remembering it is
// not a relationship.

// AdoptedAgent is one machine, as its owner knows it.
type AdoptedAgent struct {
	// AID is the identifier the machine minted for itself before anyone owned
	// it — its address, and the key in this table because it is the one thing
	// about the machine that never changes.
	AID string `json:"aid"`
	// DelegatedAID is what it signs as, under this owner's authority.
	DelegatedAID string `json:"delegated_aid"`
	// URL is where it is reached. The field expected to change: a machine's
	// address moves over its life and its identifier does not.
	URL string `json:"url"`
	// Kind is what it runs — an individual agent or an organisation's.
	Kind string `json:"kind"`
	// Label is what its owner calls it. Empty until somebody names it, which
	// is better than inventing a name they then have to correct.
	Label string `json:"label"`
	// Sealed records whether the hardware proved itself when it was adopted,
	// and Measurement what it was running.
	//
	// Kept rather than re-derived. "Is this machine sealed" is a question a
	// person asks about a machine they already own, and answering it later by
	// asking the machine would mean trusting whatever it says about itself
	// today — which is exactly what the check at adoption existed to avoid.
	Sealed      bool   `json:"sealed"`
	Measurement string `json:"measurement,omitempty"`

	AdoptedAt  string `json:"adopted_at"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

// SaveAdoptedAgent records a machine this identity has adopted.
//
// Idempotent on the machine's own identifier, so re-adopting one that is
// already known updates where it is reached rather than producing a second row
// for the same machine. What it was adopted as — the delegation, whether it was
// sealed, what it was running — is not rewritten by a later adoption attempt,
// because those are facts about a ceremony that already happened.
func (s *SQLiteStore) SaveAdoptedAgent(a AdoptedAgent) error {
	if a.AID == "" {
		return fmt.Errorf("an adopted agent needs the identifier it minted for itself")
	}
	if a.Kind == "" {
		a.Kind = "individual"
	}
	sealed := 0
	if a.Sealed {
		sealed = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO adopted_agents
			(aid, delegated_aid, url, kind, label, sealed, measurement, adopted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
		ON CONFLICT(aid) DO UPDATE SET
			url   = excluded.url,
			label = CASE WHEN excluded.label != '' THEN excluded.label ELSE adopted_agents.label END
	`, a.AID, a.DelegatedAID, a.URL, a.Kind, a.Label, sealed, a.Measurement, nullIfEmpty(a.AdoptedAt))
	if err != nil {
		return fmt.Errorf("could not record the adopted agent: %w", err)
	}
	return nil
}

// ListAdoptedAgents returns every machine this identity has adopted, newest
// first — which is the order somebody who just adopted one wants to see.
func (s *SQLiteStore) ListAdoptedAgents() ([]AdoptedAgent, error) {
	rows, err := s.db.Query(`
		SELECT aid, delegated_aid, url, kind, label, sealed, measurement,
		       COALESCE(adopted_at, ''), COALESCE(last_seen_at, '')
		FROM adopted_agents
		ORDER BY adopted_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("could not read the adopted agents: %w", err)
	}
	defer rows.Close()

	var out []AdoptedAgent
	for rows.Next() {
		var a AdoptedAgent
		var sealed int
		if err := rows.Scan(&a.AID, &a.DelegatedAID, &a.URL, &a.Kind, &a.Label,
			&sealed, &a.Measurement, &a.AdoptedAt, &a.LastSeenAt); err != nil {
			return nil, err
		}
		a.Sealed = sealed == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkAdoptedAgentSeen records that a machine answered just now.
//
// Separate from the rest because it is written on a different schedule — every
// time anything reaches the machine, rather than once when it is adopted — and
// folding it into a general update would mean rewriting facts about the
// adoption on every health check.
func (s *SQLiteStore) MarkAdoptedAgentSeen(aid string) error {
	_, err := s.db.Exec(
		`UPDATE adopted_agents SET last_seen_at = CURRENT_TIMESTAMP WHERE aid = ?`, aid)
	return err
}

// ForgetAdoptedAgent removes a machine from this owner's list.
//
// It does NOT revoke the delegation, and the name says so. The delegation lives
// in a key event log that has already been published; forgetting a machine here
// makes an owner stop listing it, and the machine can still sign as what it was
// made. Revocation is a separate act with a separate record, and conflating the
// two would let somebody believe they had taken a machine's authority away by
// deleting a row.
func (s *SQLiteStore) ForgetAdoptedAgent(aid string) error {
	_, err := s.db.Exec(`DELETE FROM adopted_agents WHERE aid = ?`, aid)
	return err
}

func nullIfEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// parsedOrZero is used by callers that need a time rather than the stored text.
func ParseAdoptedAt(v string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", v)
	if err != nil {
		if t2, err2 := time.Parse(time.RFC3339, v); err2 == nil {
			return t2
		}
		return time.Time{}
	}
	return t
}
