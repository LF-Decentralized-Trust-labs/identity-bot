package drivers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type DriverStatus struct {
	Status      string `json:"status"`
	Driver      string `json:"driver"`
	Version     string `json:"version"`
	KeriLibrary string `json:"keri_library"`
	Uptime      string `json:"uptime"`
}

type DriverInceptionRequest struct {
	PublicKey     string `json:"public_key"`
	NextPublicKey string `json:"next_public_key"`
}

type DriverInceptionResponse struct {
	AID            string                 `json:"aid"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	PublicKey      string                 `json:"public_key"`
	NextKeyDigest  string                 `json:"next_key_digest"`
}

type DriverErrorResponse struct {
	Error string `json:"error"`
}

type KeriDriver struct {
	BaseURL    string
	client     *http.Client
	process    *exec.Cmd
	managed    bool
}

func NewKeriDriver() *KeriDriver {
	driverURL := os.Getenv("KERI_DRIVER_URL")
	if driverURL != "" {
		log.Printf("[keri-driver] Using external driver at: %s", driverURL)
		return &KeriDriver{
			BaseURL: driverURL,
			client:  &http.Client{Timeout: 30 * time.Second},
			managed: false,
		}
	}

	port := os.Getenv("KERI_DRIVER_PORT")
	if port == "" {
		port = "9999"
	}

	return &KeriDriver{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%s", port),
		client:  &http.Client{Timeout: 30 * time.Second},
		managed: true,
	}
}

func (d *KeriDriver) Start() error {
	if !d.managed {
		log.Printf("[keri-driver] External driver mode — skipping process launch")
		return d.waitForReady(10 * time.Second)
	}

	log.Printf("[keri-driver] Starting managed Python KERI driver...")

	scriptPath := os.Getenv("KERI_DRIVER_SCRIPT")
	if scriptPath == "" {
		scriptPath = "./drivers/keri-core/server.py"
	}

	pythonBin := os.Getenv("KERI_DRIVER_PYTHON")
	if pythonBin == "" {
		pythonBin = "python3"
	}

	port := os.Getenv("KERI_DRIVER_PORT")
	if port == "" {
		port = "9999"
	}

	cmd := exec.Command(pythonBin, scriptPath)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("KERI_DRIVER_PORT=%s", port),
		"KERI_DRIVER_HOST=127.0.0.1",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start KERI driver: %w", err)
	}

	d.process = cmd
	log.Printf("[keri-driver] Python process started (PID: %d)", cmd.Process.Pid)

	return d.waitForReady(15 * time.Second)
}

func (d *KeriDriver) waitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++
		status, err := d.GetStatus()
		if err == nil && status.Status == "active" {
			log.Printf("[keri-driver] Driver ready (attempt %d) — library: %s", attempt, status.KeriLibrary)
			return nil
		}

		if attempt <= 3 {
			time.Sleep(500 * time.Millisecond)
		} else {
			time.Sleep(1 * time.Second)
		}
	}

	return fmt.Errorf("KERI driver did not become ready within %s", timeout)
}

func (d *KeriDriver) Stop() {
	if d.process != nil && d.process.Process != nil {
		log.Printf("[keri-driver] Stopping Python KERI driver (PID: %d)...", d.process.Process.Pid)
		d.process.Process.Kill()
		d.process.Wait()
		log.Printf("[keri-driver] KERI driver stopped")
	}
}

func (d *KeriDriver) GetStatus() (*DriverStatus, error) {
	resp, err := d.client.Get(d.BaseURL + "/status")
	if err != nil {
		return nil, fmt.Errorf("driver status request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("driver status returned %d", resp.StatusCode)
	}

	var status DriverStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode driver status: %w", err)
	}

	return &status, nil
}

func (d *KeriDriver) CreateInception(publicKey, nextPublicKey string) (*DriverInceptionResponse, error) {
	reqBody := DriverInceptionRequest{
		PublicKey:     publicKey,
		NextPublicKey: nextPublicKey,
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inception request: %w", err)
	}

	resp, err := d.client.Post(
		d.BaseURL+"/inception",
		"application/json",
		bytes.NewReader(bodyJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("driver inception request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read driver response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		var errResp DriverErrorResponse
		json.Unmarshal(body, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("driver inception failed: %s", errResp.Error)
		}
		return nil, fmt.Errorf("driver inception failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result DriverInceptionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode inception response: %w", err)
	}

	return &result, nil
}
