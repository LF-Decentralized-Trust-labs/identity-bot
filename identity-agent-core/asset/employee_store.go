package asset

import "time"

// ---- Employee invites (org-scoped) ----

func (s *Store) CreateEmployeeInvite(inv EmployeeInvite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.empInvites[inv.Token] = inv
	return s.saveLocked(s.empInvitesPath, s.empInvites)
}

func (s *Store) GetEmployeeInvite(token string) (EmployeeInvite, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.empInvites[token]
	return inv, ok
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
	if inv, ok := s.empInvites[token]; ok {
		inv.UseCount++
		s.empInvites[token] = inv
		return s.saveLocked(s.empInvitesPath, s.empInvites)
	}
	return nil
}

func (s *Store) RevokeEmployeeInvite(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inv, ok := s.empInvites[token]; ok {
		inv.Revoked = true
		s.empInvites[token] = inv
		return s.saveLocked(s.empInvitesPath, s.empInvites)
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
