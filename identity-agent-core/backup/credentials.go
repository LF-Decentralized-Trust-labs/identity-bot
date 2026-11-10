package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"identity-agent-core/atomicfile"
	"identity-agent-core/secureenclave"
	"io/fs"
	"log"
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

	// OAuth sign-in to a consumer cloud drive (Google Drive). The refresh token
	// is the long-lived grant and the one that matters; the access token is
	// short-lived and is renewed from it, so it is not kept here. The client id
	// and secret are the ones the grant was made to — a refresh token only works
	// with the client that obtained it.
	OAuthRefreshToken string `json:"oauth_refresh_token,omitempty"`
	OAuthClientID     string `json:"oauth_client_id,omitempty"`
	OAuthClientSecret string `json:"oauth_client_secret,omitempty"`
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

// masterKeyUse names this key to the platform wrapper, so the envelope it
// writes does not open as some other use's.
const masterKeyUse = "backup-credentials"

// loadOrCreateMasterKey returns the key that seals every stored credential.
//
// The key is held the way the root seed is: under the platform wrapper where
// this machine has one (secureenclave.KeyToHoldUnderTheWrapper), so the files
// beside it — which now include a sign-in token to somebody's cloud drive — are
// not opened by the disk alone. A key written before this was a bare 32-byte
// file; it is read as before and put through the wrapper when one works.
func (cs *CredentialStore) loadOrCreateMasterKey() ([]byte, error) {
	path := cs.masterKeyPath()
	dataDir := filepath.Dir(cs.dir)
	data, err := os.ReadFile(path)
	if err == nil {
		key, wrapped, oerr := secureenclave.OpenKeyHeldUnderTheWrapper(masterKeyUse, data)
		switch {
		case oerr == nil:
			if !wrapped && secureenclave.TheWrapperWorksHere(dataDir) {
				cs.rewrap(path, dataDir, key)
			}
			return key, nil
		case errors.Is(oerr, secureenclave.ErrNotAHeldKey) && len(data) == 32:
			// Written before keys were wrapped.
			if secureenclave.TheWrapperWorksHere(dataDir) {
				cs.rewrap(path, dataDir, data)
			}
			return data, nil
		default:
			// Do not make a new key: it would orphan every credential sealed
			// by this one.
			return nil, fmt.Errorf("backup credential key not available: %w", oerr)
		}
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	held, err := secureenclave.KeyToHoldUnderTheWrapper(dataDir, masterKeyUse, key)
	if err != nil {
		return nil, err
	}
	// Create, not Write: if another caller made the key first, adopt theirs
	// rather than replace a key that may already have sealed something.
	if err := atomicfile.Create(path, held, 0600); err != nil {
		if errors.Is(err, fs.ErrExist) {
			if data, rerr := os.ReadFile(path); rerr == nil {
				if k, _, oerr := secureenclave.OpenKeyHeldUnderTheWrapper(masterKeyUse, data); oerr == nil {
					return k, nil
				}
			}
		}
		return nil, err
	}
	return key, nil
}

// rewrap puts an existing key through the wrapper. A failure leaves the file
// as it was and is logged: the key still opens, and it is tried again next time.
func (cs *CredentialStore) rewrap(path, dataDir string, key []byte) {
	held, err := secureenclave.KeyToHoldUnderTheWrapper(dataDir, masterKeyUse, key)
	if err == nil {
		err = atomicfile.Write(path, held, 0600)
	}
	if err != nil {
		log.Printf("[backup] credential key left as it was, not yet wrapped: %v", err)
	}
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
	return atomicfile.Write(cs.credPath(id), enc, 0600)
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
