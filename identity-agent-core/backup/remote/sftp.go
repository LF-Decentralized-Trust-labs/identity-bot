package remote

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sftpBackend struct {
	host     string
	basePath string
	sshConfig *ssh.ClientConfig
}

func NewSFTPBackend(dest DestinationConfig, creds CredentialSecrets) (Backend, error) {
	raw := dest.RemoteURL
	if raw == "" {
		raw = dest.Endpoint
	}
	if raw == "" {
		return nil, fmt.Errorf("sftp destination requires remote_url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid sftp url: %w", err)
	}
	if u.Scheme != "sftp" {
		return nil, fmt.Errorf("sftp url must use sftp:// scheme")
	}
	if creds.Username == "" {
		return nil, fmt.Errorf("sftp destination requires username")
	}
	auth := []ssh.AuthMethod{}
	if creds.Password != "" {
		auth = append(auth, ssh.Password(creds.Password))
	}
	if creds.SecretKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(creds.SecretKey))
		if err != nil {
			return nil, fmt.Errorf("invalid sftp private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("sftp destination requires password or secret_key")
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":22"
	}
	return &sftpBackend{
		host:     host,
		basePath: strings.TrimRight(u.Path, "/"),
		sshConfig: &ssh.ClientConfig{
			User:            creds.Username,
			Auth:            auth,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // user-managed NAS; pin in future
			Timeout:         30 * time.Second,
		},
	}, nil
}

func (b *sftpBackend) withClient(fn func(*sftp.Client) error) error {
	conn, err := ssh.Dial("tcp", b.host, b.sshConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	client, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	defer client.Close()
	return fn(client)
}

func (b *sftpBackend) Push(ctx context.Context, objectKey string, data []byte) error {
	_ = ctx
	full := b.fullPath(objectKey)
	return b.withClient(func(c *sftp.Client) error {
		if err := c.MkdirAll(path.Dir(full)); err != nil {
			return err
		}
		f, err := c.Create(full)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(data)
		return err
	})
}

func (b *sftpBackend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	_ = ctx
	full := b.fullPath(objectKey)
	var out []byte
	err := b.withClient(func(c *sftp.Client) error {
		f, err := c.Open(full)
		if err != nil {
			return err
		}
		defer f.Close()
		out, err = io.ReadAll(f)
		return err
	})
	return out, err
}

func (b *sftpBackend) List(ctx context.Context, prefix string) ([]string, error) {
	_ = ctx
	dir := b.fullPath(prefix)
	var keys []string
	err := b.withClient(func(c *sftp.Client) error {
		w := c.Walk(dir)
		for w.Step() {
			if w.Err() != nil {
				return w.Err()
			}
			if w.Stat().IsDir() {
				continue
			}
			name := w.Path()
			if strings.HasSuffix(name, ".iab") {
				rel := strings.TrimPrefix(name, b.basePath+"/")
				keys = append(keys, strings.TrimLeft(rel, "/"))
			}
		}
		return nil
	})
	return keys, err
}

func (b *sftpBackend) fullPath(objectKey string) string {
	if b.basePath == "" || b.basePath == "/" {
		return "/" + strings.TrimLeft(objectKey, "/")
	}
	return path.Join(b.basePath, objectKey)
}

// Ensure net package used for build tag compatibility.
var _ = net.Dial
var _ = os.ErrNotExist