package login

import (
	"sync"
	"time"
)

type pendingLogin struct {
	SessionToken string
	RPSessionURL string
	Bundle       *ChallengeBundle
	Relationship *SiteRelationship
	CreatedAt    time.Time
}

type PendingStore struct {
	mu      sync.RWMutex
	pending map[string]*pendingLogin
}

func NewPendingStore() *PendingStore {
	return &PendingStore{pending: map[string]*pendingLogin{}}
}

func (s *PendingStore) Put(key string, p *pendingLogin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[key] = p
}

func (s *PendingStore) Get(key string) (*pendingLogin, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pending[key]
	return p, ok
}

func (s *PendingStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, key)
}

func (s *PendingStore) List() []*pendingLogin {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*pendingLogin, 0, len(s.pending))
	for _, p := range s.pending {
		out = append(out, p)
	}
	return out
}
