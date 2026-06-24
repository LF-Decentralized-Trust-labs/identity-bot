package login

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type RelationshipStore struct {
	mu        sync.RWMutex
	path      string
	items     map[string]SiteRelationship
	highWater int // never-decrementing high-water mark for RelationshipIndex; survives deletes
}

func NewRelationshipStore(dataDir string) (*RelationshipStore, error) {
	path := filepath.Join(dataDir, "login_relationships.json")
	s := &RelationshipStore{path: path, items: map[string]SiteRelationship{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.loadHighWater()
	// ensure highWater >= max in items
	for _, r := range s.items {
		if r.RelationshipIndex > s.highWater {
			s.highWater = r.RelationshipIndex
		}
	}
	return s, nil
}

func (s *RelationshipStore) loadHighWater() {
	hpath := s.path + ".highwater"
	if b, err := os.ReadFile(hpath); err == nil {
		var hw int
		fmt.Sscanf(string(b), "%d", &hw)
		if hw > s.highWater {
			s.highWater = hw
		}
	}
}

func (s *RelationshipStore) saveHighWaterLocked() error {
	hpath := s.path + ".highwater"
	return os.WriteFile(hpath, []byte(fmt.Sprintf("%d\n", s.highWater)), 0600)
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
	// Assign stable monotonic index from highWater (never reuses after delete).
	if rel.RelationshipIndex == 0 {
		s.highWater++
		rel.RelationshipIndex = s.highWater
	} else if rel.RelationshipIndex > s.highWater {
		s.highWater = rel.RelationshipIndex
	}
	s.items[rel.SiteAID] = rel
	return s.saveLocked()
}

// NextRelationshipIndex returns the next never-reused high-water index without side effects.
// The highWater is a persisted monotonic counter (updated on Put); it is not recomputed from live items.
func (s *RelationshipStore) NextRelationshipIndex() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.highWater + 1
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
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return s.saveHighWaterLocked()
}

func (s *RelationshipStore) DevRelayOOBI(pairwiseAID, relayBase string) string {
	return fmt.Sprintf("%s/oobi/%s", relayBase, pairwiseAID)
}