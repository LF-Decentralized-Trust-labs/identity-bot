package tunnel

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// Short, memorable adjectives for auto-generated tunnel names.
var adjectives = []string{
	"blue", "red", "gold", "green", "swift",
	"bold", "calm", "dark", "fair", "keen",
	"warm", "cool", "wild", "soft", "true",
	"deep", "fast", "pure", "wise", "bright",
}

// Short, memorable nouns for auto-generated tunnel names.
var nouns = []string{
	"fox", "oak", "sun", "sky", "owl",
	"elm", "bee", "ash", "bay", "fir",
	"hawk", "jade", "lion", "pine", "reef",
	"star", "wolf", "dove", "iris", "sage",
}

// GenerateName produces a short random name like "bold-fox" or "swift-oak-7".
func GenerateName() string {
	adj := adjectives[rand.Intn(len(adjectives))]
	noun := nouns[rand.Intn(len(nouns))]
	// ~50% chance of appending a short digit for more combinations
	if rand.Intn(2) == 0 {
		return fmt.Sprintf("%s-%s-%d", adj, noun, rand.Intn(99)+1)
	}
	return fmt.Sprintf("%s-%s", adj, noun)
}

// CheckNameAvailable queries the Grape ID hub to see if a name is free.
func CheckNameAvailable(domain, name string) (bool, error) {
	scheme := "https"
	if isLocalDomain(domain) {
		scheme = "http"
	}

	url := fmt.Sprintf("%s://%s/check-name?name=%s", scheme, domain, name)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false, fmt.Errorf("hub unreachable: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return false, fmt.Errorf("hub returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Available bool `json:"available"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to parse hub response: %v", err)
	}
	return result.Available, nil
}

// FindAvailableName generates random names and checks availability, returning
// the first available one. Tries up to maxAttempts times.
func FindAvailableName(domain string, maxAttempts int) (string, error) {
	if domain == "" {
		domain = "grapeid.org"
	}
	for i := 0; i < maxAttempts; i++ {
		name := GenerateName()
		available, err := CheckNameAvailable(domain, name)
		if err != nil {
			log.Printf("[tunnel] Name check failed for '%s': %v", name, err)
			// Hub unreachable — no point retrying with different names
			return "", fmt.Errorf("cannot reach Grape ID hub at %s: %v", domain, err)
		}
		if available {
			log.Printf("[tunnel] Auto-generated tunnel name '%s' is available", name)
			return name, nil
		}
		log.Printf("[tunnel] Auto-generated name '%s' taken, trying another", name)
	}
	return "", fmt.Errorf("could not find available name after %d attempts", maxAttempts)
}

func isLocalDomain(domain string) bool {
	return strings.Contains(domain, "localhost") || strings.Contains(domain, "127.0.0.1")
}
