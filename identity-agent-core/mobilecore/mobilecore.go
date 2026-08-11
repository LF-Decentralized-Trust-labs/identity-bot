package mobilecore

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/server"
)

var (
	instance *server.CoreServer
	mu       sync.Mutex
)

func StartServer(dataDir string, port int) error {
	mu.Lock()
	defer mu.Unlock()

	if instance != nil {
		return fmt.Errorf("server already running")
	}

	cfg := server.Config{
		DataDir:          dataDir,
		Port:             port,
		EnableKeriDriver: false,
		FlutterWebDir:    "",
	}

	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	instance = srv
	log.Printf("[mobilecore] Go Core started on port %d (data: %s)", port, dataDir)
	return nil
}

func StopServer() error {
	mu.Lock()
	defer mu.Unlock()

	if instance == nil {
		return nil
	}

	instance.Stop()
	instance = nil
	log.Println("[mobilecore] Go Core stopped")
	return nil
}

func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return instance != nil && instance.IsRunning()
}

func GetHealth() (string, error) {
	mu.Lock()
	srv := instance
	mu.Unlock()

	if srv == nil {
		return "", fmt.Errorf("server not running")
	}

	health := map[string]interface{}{
		"status":  "active",
		"agent":   "keri-go",
		"version": "0.1.0",
		"mode":    "mobile_standalone",
	}

	data, err := json.Marshal(health)
	if err != nil {
		return "", fmt.Errorf("failed to marshal health: %w", err)
	}
	return string(data), nil
}

func GetPort() int {
	mu.Lock()
	srv := instance
	mu.Unlock()

	if srv == nil {
		return 0
	}
	return srv.Port
}

// RunKeriSelfTest runs the KERI conformance suite on this device and returns
// the result as JSON.
//
// It exists because `go test` does not run on a phone, and a desktop result
// does not transfer. The architecture is the same, but the runtime is not: a
// different libc surface through cgo, a sandboxed filesystem, tighter memory.
// An implementation can be byte-perfect on a developer machine and wrong on the
// device it ships to, and nothing in a desktop run would say so.
//
// The vectors are embedded in the library, so this reads no files and writes
// none, and is safe to call at any point in the app's life.
//
// The result reports what it did NOT check as well as what passed: a number of
// the cases produce no bytes to compare and are verified by assertions in the
// library's own test suite instead. Counting those as passes would let a run
// claim more coverage than it has.
func RunKeriSelfTest() (string, error) {
	return keri.SelfTestJSON()
}
