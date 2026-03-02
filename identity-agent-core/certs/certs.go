package certs

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

//go:embed cacert.pem
var embeddedCACert []byte

var (
	rootPool *x509.CertPool
	poolOnce sync.Once
	dataDir  string
)

func InitCerts(dir string) {
	dataDir = dir
	poolOnce.Do(func() {
		rootPool = loadCertPool()
	})
}

func RootCAs() *x509.CertPool {
	poolOnce.Do(func() {
		rootPool = loadCertPool()
	})
	return rootPool
}

func HTTPClient(timeout time.Duration) *http.Client {
	pool := RootCAs()
	if pool == nil {
		return &http.Client{Timeout: timeout}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}
}

func loadCertPool() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err == nil && len(pool.Subjects()) > 0 {
		log.Printf("[certs] Using system certificate pool (%d certs)", len(pool.Subjects()))
		return pool
	}

	if dataDir != "" {
		localPath := filepath.Join(dataDir, "cacert.pem")
		if data, err := os.ReadFile(localPath); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(data) {
				log.Printf("[certs] Using local certificate bundle: %s", localPath)
				return pool
			}
		}
	}

	pool = x509.NewCertPool()
	if pool.AppendCertsFromPEM(embeddedCACert) {
		log.Printf("[certs] Using embedded certificate bundle")

		if dataDir != "" {
			localPath := filepath.Join(dataDir, "cacert.pem")
			if err := os.WriteFile(localPath, embeddedCACert, 0644); err == nil {
				log.Printf("[certs] Wrote embedded bundle to %s for future use", localPath)
			}
		}

		return pool
	}

	log.Printf("[certs] WARNING: No certificate pool available, HTTPS may fail")
	return nil
}

func TryUpdateCerts(dir string) {
	go func() {
		time.Sleep(30 * time.Second)
		doUpdate(dir)
	}()
}

func doUpdate(dir string) {
	localPath := filepath.Join(dir, "cacert.pem")

	info, err := os.Stat(localPath)
	if err == nil && time.Since(info.ModTime()) < 30*24*time.Hour {
		return
	}

	log.Printf("[certs] Checking for updated CA bundle...")
	client := HTTPClient(30 * time.Second)
	resp, err := client.Get("https://curl.se/ca/cacert.pem")
	if err != nil {
		log.Printf("[certs] CA bundle update check failed (non-fatal): %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[certs] CA bundle update returned HTTP %d (non-fatal)", resp.StatusCode)
		return
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil || len(data) < 1000 {
		log.Printf("[certs] CA bundle download incomplete (non-fatal)")
		return
	}

	testPool := x509.NewCertPool()
	if !testPool.AppendCertsFromPEM(data) {
		log.Printf("[certs] Downloaded CA bundle is invalid PEM (non-fatal)")
		return
	}

	if err := os.WriteFile(localPath, data, 0644); err != nil {
		log.Printf("[certs] Failed to write updated CA bundle (non-fatal): %v", err)
		return
	}

	log.Printf("[certs] CA bundle updated successfully")
}
