package asset

import (
	"errors"
	"time"

	"identity-agent-core/enrolsecret"
)

// ---- Employee invites (org-scoped) ----

// CreateEmployeeInvite records an invite for the code in inv.Token, keeping
// only its digest (the invite's ID), never the code.
func (s *Store) CreateEmployeeInvite(inv EmployeeInvite) error {
	if inv.Token == "" {
		return errors.New("an invite needs a code")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inv.ID, inv.Token = enrolsecret.Digest(inv.Token), ""
	s.empInvites[inv.ID] = inv
	return s.saveLocked(s.empInvitesPath, s.empInvites)
}

// findEmployeeInviteLocked compares a presented code to every stored digest,
// never stopping early.
func (s *Store) findEmployeeInviteLocked(token string) (string, bool) {
	id, found := "", false
	if token == "" {
		return "", false
	}
	for key, inv := range s.empInvites {
		if enrolsecret.Equal(token, inv.ID) {
			id, found = key, true
		}
	}
	return id, found
}

func (s *Store) GetEmployeeInvite(token string) (EmployeeInvite, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.findEmployeeInviteLocked(token)
	if !ok {
		return EmployeeInvite{}, false
	}
	return s.empInvites[id], true
}

func (s *Store) ListEmployeeInvites() []EmployeeInvite {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []EmployeeInvite{}
	for _, inv := range s.empInvites {
		out = append(out, inv)
	}
	return out
}

func (s *Store) IncrementEmployeeInviteUse(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.findEmployeeInviteLocked(token); ok {
		inv := s.empInvites[id]
		inv.UseCount++
		s.empInvites[id] = inv
		return s.saveLocked(s.empInvitesPath, s.empInvites)
	}
	return nil
}

// RevokeEmployeeInvite withdraws an employee invite, named by its ID (the
// digest the list shows) and never by its code. Like RevokeInvite it says
// ErrInviteNotFound for an unknown invite and ErrInviteClosed for one already
// revoked or used up.
func (s *Store) RevokeEmployeeInvite(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.empInvites[id]
	if !ok {
		return ErrInviteNotFound
	}
	if inv.Revoked || (inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses) {
		return ErrInviteClosed
	}
	inv.Revoked = true
	s.empInvites[id] = inv
	if err := s.saveLocked(s.empInvitesPath, s.empInvites); err != nil {
		inv.Revoked = false
		s.empInvites[id] = inv
		return err
	}
	return nil
}

// ---- Employee roster (org-scoped) ----

func (s *Store) UpsertEmployee(e Employee) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if existing, ok := s.employees[e.PairwiseAID]; ok {
		e.CreatedAt = existing.CreatedAt
	} else if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	s.employees[e.PairwiseAID] = e
	return s.saveLocked(s.employeesPath, s.employees)
}

func (s *Store) GetEmployee(pairwiseAID string) (Employee, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.employees[pairwiseAID]
	return e, ok
}

func (s *Store) ListEmployees() []Employee {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Employee{}
	for _, e := range s.employees {
		out = append(out, e)
	}
	return out
}

// SetEmployeeStatus transitions an employee's lifecycle and optionally records
// the issued credential SAID (on approval). Returns the updated Employee.
func (s *Store) SetEmployeeStatus(pairwiseAID, status, credentialSAID string) (Employee, bool, error) {
	return s.setEmployeeStatus(pairwiseAID, status, credentialSAID, nil)
}

// ApproveEmployee makes a member active and records which machine approved
// them: a controller's identifier, or "" for the owner.
func (s *Store) ApproveEmployee(pairwiseAID, byController string) (Employee, bool, error) {
	return s.setEmployeeStatus(pairwiseAID, "active", "", &byController)
}

func (s *Store) setEmployeeStatus(pairwiseAID, status, credentialSAID string, approvedBy *string) (Employee, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.employees[pairwiseAID]
	if !ok {
		return Employee{}, false, nil
	}
	e.Status = status
	if credentialSAID != "" {
		e.CredentialSAID = credentialSAID
	}
	if approvedBy != nil {
		e.ApprovedByController = *approvedBy
	}
	e.UpdatedAt = time.Now().UTC()
	s.employees[pairwiseAID] = e
	return e, true, s.saveLocked(s.employeesPath, s.employees)
}

// IsActiveEmployee is the membership gate consulted when an asset's
// MembershipSource is "employees": only Status == "active" passes.
func (s *Store) IsActiveEmployee(pairwiseAID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.employees[pairwiseAID]
	return ok && e.Status == "active"
}
