package remote

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"
)

// Backend pushes and pulls client-side encrypted .iab archives.
type Backend interface {
	Push(ctx context.Context, objectKey string, data []byte) error
	Pull(ctx context.Context, objectKey string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
}

// NewBackend constructs a remote backend for a configured destination.
func NewBackend(dest DestinationConfig, creds CredentialSecrets) (Backend, error) {
	provider := strings.ToLower(strings.TrimSpace(dest.Provider))
	switch provider {
	case "s3", "s3_compatible", "minio":
		return NewS3Backend(dest, creds)
	case "gcs":
		return NewGCSBackend(dest, creds)
	case "azure", "azure_blob":
		return NewAzureBackend(dest, creds)
	case "webdav":
		return NewWebDAVBackend(dest, creds)
	case "sftp":
		return NewSFTPBackend(dest, creds)
	case "smb":
		return NewSMBBackend(dest, creds)
	default:
		return nil, fmt.Errorf("unsupported cloud provider %q", dest.Provider)
	}
}

// ArchiveObjectKey builds a deterministic object key for an encrypted archive.
func ArchiveObjectKey(dest DestinationConfig, snapshotType string) string {
	prefix := strings.Trim(dest.Prefix, "/")
	name := fmt.Sprintf("backup-%s-%s.iab", snapshotType, time.Now().UTC().Format("20060102-150405"))
	if prefix == "" {
		return name
	}
	return path.Join(prefix, name)
}

// LatestArchiveKey returns the newest .iab object under prefix.
func LatestArchiveKey(ctx context.Context, b Backend, prefix string) (string, error) {
	keys, err := b.List(ctx, prefix)
	if err != nil {
		return "", err
	}
	var latest string
	for _, k := range keys {
		if !strings.HasSuffix(k, ".iab") {
			continue
		}
		if latest == "" || k > latest {
			latest = k
		}
	}
	if latest == "" {
		return "", fmt.Errorf("no .iab archives found under %q", prefix)
	}
	return latest, nil
}
