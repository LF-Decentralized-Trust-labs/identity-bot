package remote

import (
	"context"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

type smbBackend struct {
	host     string
	share    string
	basePath string
	username string
	password string
	domain   string
}

func NewSMBBackend(dest DestinationConfig, creds CredentialSecrets) (Backend, error) {
	raw := dest.RemoteURL
	if raw == "" {
		raw = dest.Endpoint
	}
	if raw == "" {
		return nil, fmt.Errorf("smb destination requires remote_url (smb://host/share/path)")
	}
	if !strings.HasPrefix(raw, "smb://") {
		return nil, fmt.Errorf("smb url must use smb:// scheme")
	}
	trimmed := strings.TrimPrefix(raw, "smb://")
	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid smb url")
	}
	host := parts[0]
	share := parts[1]
	base := ""
	if len(parts) == 3 {
		base = parts[2]
	}
	if creds.Username == "" {
		return nil, fmt.Errorf("smb destination requires username")
	}
	return &smbBackend{
		host:     host,
		share:    share,
		basePath: strings.Trim(base, "/"),
		username: creds.Username,
		password: creds.Password,
		domain:   creds.AccountName,
	}, nil
}

func (b *smbBackend) withShare(fn func(*smb2.Share) error) error {
	conn, err := net.DialTimeout("tcp", b.host+":445", 30*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     b.username,
			Password: b.password,
			Domain:   b.domain,
		},
	}
	session, err := d.Dial(conn)
	if err != nil {
		return err
	}
	defer session.Logoff()
	share, err := session.Mount(b.share)
	if err != nil {
		return err
	}
	defer share.Umount()
	return fn(share)
}

func (b *smbBackend) Push(ctx context.Context, objectKey string, data []byte) error {
	_ = ctx
	full := b.fullPath(objectKey)
	return b.withShare(func(sh *smb2.Share) error {
		if err := sh.MkdirAll(path.Dir(full), 0755); err != nil {
			return err
		}
		f, err := sh.Create(full)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(data)
		return err
	})
}

func (b *smbBackend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	_ = ctx
	full := b.fullPath(objectKey)
	var out []byte
	err := b.withShare(func(sh *smb2.Share) error {
		f, err := sh.Open(full)
		if err != nil {
			return err
		}
		defer f.Close()
		out, err = io.ReadAll(f)
		return err
	})
	return out, err
}

func (b *smbBackend) List(ctx context.Context, prefix string) ([]string, error) {
	_ = ctx
	dir := b.fullPath(prefix)
	var keys []string
	err := b.withShare(func(sh *smb2.Share) error {
		entries, err := sh.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".iab") {
				if prefix != "" {
					keys = append(keys, path.Join(prefix, name))
				} else {
					keys = append(keys, name)
				}
			}
		}
		return nil
	})
	return keys, err
}

func (b *smbBackend) fullPath(objectKey string) string {
	if b.basePath == "" {
		return strings.TrimLeft(objectKey, "/")
	}
	return path.Join(b.basePath, objectKey)
}