package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RemoteCredentialSecrets holds provider credentials (never stored in plaintext on disk).
type RemoteCredentialSecrets struct {
	AccessKey          string `json:"access_key,omitempty"`
	SecretKey          string `json:"secret_key,omitempty"`
	SessionToken       string `json:"session_token,omitempty"`
	Username           string `json:"username,omitempty"`
	Password           string `json:"password,omitempty"`
	AccountName        string `json:"account_name,omitempty"`
	ServiceAccountJSON string `json:"service_account_json,omitempty"`
}

// CredentialStore persists destination credentials encrypted in the data directory.
type CredentialStore struct {
	dir       string
	masterKey []byte
	mu        sync.RWMutex
}

func NewCredentialStore(dataDir string) (*CredentialStore, error) {
	cs := &CredentialStore{dir: filepath.Join(dataDir, "backup")}
	if err := os.MkdirAll(cs.dir, 0700); err != nil {
		return nil, err
	}
	key, err := cs.loadOrCreateMasterKey()
	if err != nil {
		return nil, err
	}
	cs.masterKey = key
	return cs, nil
}

func (cs *CredentialStore) masterKeyPath() string {
	return filepath.Join(cs.dir, "credentials_master.key")
}

func (cs *CredentialStore) credPath(id string) string {
	return filepath.Join(cs.dir, "credentials_"+id+".enc")
}

func (cs *CredentialStore) loadOrCreateMasterKey() ([]byte, error) {
	path := cs.masterKeyPath()
	data, err := os.ReadFile(path)
	if err == nil && len(data) == 32 {
		return data, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func (cs *CredentialStore) Save(id string, cred RemoteCredentialSecrets) error {
	if id == "" {
		return fmt.Errorf("credential id required")
	}
	plain, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	enc, err := encryptLocal(cs.masterKey, plain)
	if err != nil {
		return err
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return os.WriteFile(cs.credPath(id), enc, 0600)
}

func (cs *CredentialStore) Load(id string) (RemoteCredentialSecrets, error) {
	var out RemoteCredentialSecrets
	if id == "" {
		return out, fmt.Errorf("credential id required")
	}
	cs.mu.RLock()
	data, err := os.ReadFile(cs.credPath(id))
	cs.mu.RUnlock()
	if err != nil {
		return out, err
	}
	plain, err := decryptLocal(cs.masterKey, data)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(plain, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (cs *CredentialStore) Delete(id string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	err := os.Remove(cs.credPath(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func encryptLocal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, GCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, nil)...), nil
}

func decryptLocal(key, blob []byte) ([]byte, error) {
	if len(blob) < GCMNonceLen {
		return nil, fmt.Errorf("credential blob too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := blob[:GCMNonceLen]
	return gcm.Open(nil, nonce, blob[GCMNonceLen:], nil)
}
