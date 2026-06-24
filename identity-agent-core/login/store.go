package login

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type RelationshipStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]SiteRelationship
}

func NewRelationshipStore(dataDir string) (*RelationshipStore, error) {
	path := filepath.Join(dataDir, "login_relationships.json")
	s := &RelationshipStore{path: path, items: map[string]SiteRelationship{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *RelationshipStore) Get(siteAID string) (SiteRelationship, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.items[siteAID]
	return r, ok
}

func (s *RelationshipStore) Put(rel SiteRelationship) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Security: do not persist raw private seeds in the main relationships JSON.
	// The AID (PairwiseAID) is the handle; secrets live in secure storage.
	rel.SeedB64 = ""
	s.items[rel.SiteAID] = rel
	return s.saveLocked()
}

func (s *RelationshipStore) load() error {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &s.items)
}

func (s *RelationshipStore) saveLocked() error {
	b, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *RelationshipStore) DevRelayOOBI(pairwiseAID, relayBase string) string {
	return fmt.Sprintf("%s/oobi/%s", relayBase, pairwiseAID)
}