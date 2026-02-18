package keri

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type InceptionEvent struct {
	Version          string   `json:"v"`
	Type             string   `json:"t"`
	SAID             string   `json:"d"`
	Prefix           string   `json:"i"`
	SequenceNumber   string   `json:"s"`
	SigningThreshold string   `json:"kt"`
	Keys             []string `json:"k"`
	NextThreshold    string   `json:"nt"`
	NextKeys         []string `json:"n"`
	BackerThreshold  string   `json:"bt"`
	Backers          []string `json:"b"`
	Config           []string `json:"c"`
	Anchors          []string `json:"a"`
}

type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

type InceptionResult struct {
	AID            string          `json:"aid"`
	Event          InceptionEvent  `json:"inception_event"`
	EventJSON      string          `json:"event_json"`
	PublicKey      string          `json:"public_key"`
	NextPublicKey  string          `json:"next_public_key"`
}

func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

func KeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) < ed25519.SeedSize {
		hash := sha256.Sum256(seed)
		seed = hash[:ed25519.SeedSize]
	}
	priv := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

func EncodePublicKey(pub ed25519.PublicKey) string {
	return "B" + base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(pub)
}

func DigestKey(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	return "E" + base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

func computeSAID(event *InceptionEvent) (string, error) {
	event.SAID = "#" + strings.Repeat("a", 43)
	event.Prefix = "#" + strings.Repeat("a", 43)

	data, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event for SAID: %w", err)
	}

	size := len(data)
	event.Version = fmt.Sprintf("KERI10JSON%06x_", size)

	data, err = json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event for SAID: %w", err)
	}

	hash := sha256.Sum256(data)
	said := "E" + base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])

	return said, nil
}

func CreateInceptionEvent(signingPub ed25519.PublicKey, nextPub ed25519.PublicKey) (*InceptionResult, error) {
	signingKeyStr := EncodePublicKey(signingPub)
	nextKeyDigest := DigestKey(nextPub)

	event := &InceptionEvent{
		Version:          "KERI10JSON000000_",
		Type:             "icp",
		SAID:             "",
		Prefix:           "",
		SequenceNumber:   "0",
		SigningThreshold: "1",
		Keys:             []string{signingKeyStr},
		NextThreshold:    "1",
		NextKeys:         []string{nextKeyDigest},
		BackerThreshold:  "0",
		Backers:          []string{},
		Config:           []string{},
		Anchors:          []string{},
	}

	said, err := computeSAID(event)
	if err != nil {
		return nil, fmt.Errorf("failed to compute SAID: %w", err)
	}

	event.SAID = said
	event.Prefix = said

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inception event: %w", err)
	}

	return &InceptionResult{
		AID:           said,
		Event:         *event,
		EventJSON:     string(eventJSON),
		PublicKey:     signingKeyStr,
		NextPublicKey: nextKeyDigest,
	}, nil
}

func SignEvent(priv ed25519.PrivateKey, eventJSON []byte) []byte {
	return ed25519.Sign(priv, eventJSON)
}

func VerifySignature(pub ed25519.PublicKey, eventJSON []byte, signature []byte) bool {
	return ed25519.Verify(pub, eventJSON, signature)
}
