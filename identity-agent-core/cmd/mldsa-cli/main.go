// Command mldsa-cli exposes deterministic ML-DSA-65 sign/verkey/verify over
// stdout JSON, so the Python KERI reference implementation can produce and check
// the same golden vectors as the Go core without linking a second crypto engine.
//
// This exists because there is one KERI engine on every platform and it is this
// Go core. The Python driver previously shelled out to a Rust proof-of-concept
// crate for ML-DSA; that crate is gone, and reaching back into it made the
// hybrid-PQC harnesses unrunnable on every machine.
//
// It is a test/harness tool, not part of the served API. It takes a seed rather
// than generating one, because the whole point is a byte-identical vector.
//
//	go run ./cmd/mldsa-cli verkey '{"seed_hex":"..."}'
//	go run ./cmd/mldsa-cli sign   '{"seed_hex":"...","msg_hex":"..."}'
//	go run ./cmd/mldsa-cli verify '{"vk_hex":"...","msg_hex":"...","sig_hex":"..."}'
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type request struct {
	SeedHex string `json:"seed_hex"`
	MsgHex  string `json:"msg_hex"`
	VkHex   string `json:"vk_hex"`
	SigHex  string `json:"sig_hex"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: mldsa-cli <sign|verkey|verify> <json>")
	}
	op := os.Args[1]

	var req request
	if err := json.Unmarshal([]byte(os.Args[2]), &req); err != nil {
		return fmt.Errorf("bad request json: %w", err)
	}

	switch op {
	case "verkey":
		seed, err := seedFrom(req.SeedHex)
		if err != nil {
			return err
		}
		pk, _ := mldsa65.NewKeyFromSeed(seed)
		var packed [mldsa65.PublicKeySize]byte
		pk.Pack(&packed)
		return emit(map[string]string{"vk_hex": hex.EncodeToString(packed[:])})

	case "sign":
		seed, err := seedFrom(req.SeedHex)
		if err != nil {
			return err
		}
		msg, err := hex.DecodeString(req.MsgHex)
		if err != nil {
			return fmt.Errorf("msg_hex: %w", err)
		}
		_, sk := mldsa65.NewKeyFromSeed(seed)
		sig := make([]byte, mldsa65.SignatureSize)
		// Deterministic (randomized=false) and no context, matching
		// iacrypto.SignHybridMessage — a randomized signature would still verify
		// but would not be the same bytes, which is the whole point here.
		if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		return emit(map[string]string{"sig_hex": hex.EncodeToString(sig)})

	case "verify":
		vk, err := hex.DecodeString(req.VkHex)
		if err != nil {
			return fmt.Errorf("vk_hex: %w", err)
		}
		if len(vk) != mldsa65.PublicKeySize {
			return fmt.Errorf("vk_hex is %d bytes, want %d", len(vk), mldsa65.PublicKeySize)
		}
		msg, err := hex.DecodeString(req.MsgHex)
		if err != nil {
			return fmt.Errorf("msg_hex: %w", err)
		}
		sig, err := hex.DecodeString(req.SigHex)
		if err != nil {
			return fmt.Errorf("sig_hex: %w", err)
		}
		var pk mldsa65.PublicKey
		var packed [mldsa65.PublicKeySize]byte
		copy(packed[:], vk)
		pk.Unpack(&packed)
		return emit(map[string]bool{"ok": mldsa65.Verify(&pk, msg, nil, sig)})
	}

	return fmt.Errorf("unknown op %q (want sign, verkey or verify)", op)
}

func seedFrom(s string) (*[mldsa65.SeedSize]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("seed_hex: %w", err)
	}
	if len(raw) != mldsa65.SeedSize {
		return nil, fmt.Errorf("seed is %d bytes, want %d", len(raw), mldsa65.SeedSize)
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], raw)
	return &seed, nil
}

func emit(v any) error {
	return json.NewEncoder(os.Stdout).Encode(v)
}
