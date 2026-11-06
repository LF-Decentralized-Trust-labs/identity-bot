package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/contractcheck"
	"identity-agent-core/keymath"

	keri "github.com/grapeid/keri-go"
)

// identity-key-vectors.json is how an identity's keys come from its recovery
// phrase, worked through: the phrase, its BIP39 seed, and for each key the
// SLIP-0010 path, the 32-byte Ed25519 seed at the end of it and the public
// key. This core derives an identity's keys this way (DerivePairwiseSeed,
// m/44'/0'/0'/branch'/key') and so does the app that holds a phrase, so an
// identity founded on one is recoverable on the other. Each side checks the
// same file: a change on one side fails its own tests before it founds an
// identity the other cannot find again.
//
// When the derivation changes on purpose, regenerate it with
// IA_WRITE_CONTRACTS=1 go test ./backup -run TestTheIdentityKeyVectorsHold
// and review the diff.
const identityKeyVectorsPath = "identity-key-vectors.json"

type identityKeyVectors struct {
	About     string              `json:"about"`
	Published slip10Vector        `json:"slip10_published"`
	Phrases   []identityKeyPhrase `json:"phrases"`
}

// slip10Vector is SLIP-0010's own first Ed25519 test vector, chain
// m/0'/1'/2'/2'/1000000000', as published with the standard: an anchor that
// neither implementation wrote.
type slip10Vector struct {
	SeedHex       string `json:"seed_hex"`
	Path          string `json:"path"`
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
}

type identityKeyPhrase struct {
	Mnemonic     string        `json:"mnemonic"`
	BIP39SeedHex string        `json:"bip39_seed_hex"`
	Keys         []identityKey `json:"keys"`
	// PostQuantum are the post-quantum next keys of generations 0 to 2: the
	// ML-DSA-65 key each child seed gives, as qb64 under the proposed code
	// 2AAE, and the next-key digest a commitment to it is (ADR-061 section 1).
	PostQuantum []postQuantumKey `json:"post_quantum"`
	// Messaging are the messaging keysets of generations 0 and 1, by the
	// anchor a key log commits to each with.
	Messaging []messagingKeySet `json:"messaging"`
	// SignatureForms are one signature in each indexed form KERI attaches, by
	// key 0 over this phrase's founding: the founding committing to key 1 and
	// post-quantum generation 0.
	SignatureForms *signatureForms `json:"signature_forms,omitempty"`
}

type postQuantumKey struct {
	Generation int    `json:"generation"`
	Path       string `json:"path"`
	SeedHex    string `json:"seed_hex"`
	VerkeyQB64 string `json:"verkey_qb64"`
	Digest     string `json:"digest"`
}

type messagingKeySet struct {
	Generation int                    `json:"generation"`
	Path       string                 `json:"path"`
	Anchor     map[string]interface{} `json:"anchor"`
}

type signatureForms struct {
	FoundingRaw string `json:"founding_raw"`
	// A opens n[0] from k[0]; TwoA is index 0 and ondex 1; B is current-only.
	A    string `json:"A"`
	TwoA string `json:"2A"`
	B    string `json:"B"`
}

// identityKey is key n of the identity on branch 0: n = 0 is the key it is
// founded with, 1 the key founding commits to, and so on.
type identityKey struct {
	Index         int    `json:"index"`
	Path          string `json:"path"`
	SeedHex       string `json:"seed_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
	PublicKeyQB64 string `json:"public_key_qb64"`
}

// SLIP-0010's published result for its first Ed25519 vector, written here as
// well as in the file so a regenerated file cannot quietly move it.
const (
	slip10PublishedPrivate = "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
	slip10PublishedPublic  = "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a" // published with a 00 prefix
)

func parseHardenedPath(p string) ([]uint32, error) {
	if !strings.HasPrefix(p, "m/") {
		return nil, fmt.Errorf("a path starts m/")
	}
	var out []uint32
	for _, seg := range strings.Split(p[2:], "/") {
		if !strings.HasSuffix(seg, "'") {
			return nil, fmt.Errorf("every Ed25519 step is hardened, %q is not", seg)
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(seg, "'"), 10, 31)
		if err != nil {
			return nil, err
		}
		out = append(out, uint32(n)|0x80000000)
	}
	return out, nil
}

func computeIdentityKeyVectors(in identityKeyVectors) (identityKeyVectors, error) {
	out := identityKeyVectors{
		About: "How an identity's keys come from its recovery phrase: BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, " +
			"salt \"mnemonic\"), then SLIP-0010 Ed25519 with every step hardened. Key n of an identity is at " +
			"m/44'/0'/0'/0'/n': 0 founds it, 1 is what founding commits to, n+1 is what the rotation to key n commits to. " +
			"public_key_qb64 is the key in CESR with code D. post_quantum: the post-quantum next key of generation j is at " +
			"m/44'/0'/0'/7000001'/j', ML-DSA-65 from that child seed, qb64 under 2AAE, and its commitment is Blake3-256 over " +
			"that qb64 text, as code E. messaging: the messaging keyset of generation g is at m/44'/0'/0'/7000002'/g', " +
			"by its anchor. signature_forms: key 0's signature over the founding, in the A, 2A and B forms. " +
			"Checked by identity-agent-core/backup and by the app's key manager.",
		Published: in.Published,
	}
	path, err := parseHardenedPath(in.Published.Path)
	if err != nil {
		return out, err
	}
	seed, err := hex.DecodeString(in.Published.SeedHex)
	if err != nil {
		return out, err
	}
	priv, _ := deriveSLIP10Ed25519(seed, path)
	out.Published.PrivateKeyHex = hex.EncodeToString(priv)
	out.Published.PublicKeyHex = hex.EncodeToString(ed25519.NewKeyFromSeed(priv).Public().(ed25519.PublicKey))

	for _, p := range in.Phrases {
		bip39, err := MnemonicToBIP39Seed(p.Mnemonic, "")
		if err != nil {
			return out, fmt.Errorf("%q: %w", p.Mnemonic, err)
		}
		ph := identityKeyPhrase{Mnemonic: p.Mnemonic, BIP39SeedHex: hex.EncodeToString(bip39)}
		for gen := 0; gen < 3; gen++ {
			s, err := DerivePairwiseSeed(bip39, PostQuantumBranch, gen)
			if err != nil {
				return out, err
			}
			pq, err := keymath.PostQuantumNextKey(s)
			if err != nil {
				return out, err
			}
			ph.PostQuantum = append(ph.PostQuantum, postQuantumKey{Generation: gen,
				Path: fmt.Sprintf("m/44'/0'/0'/%d'/%d'", PostQuantumBranch, gen), SeedHex: hex.EncodeToString(s),
				VerkeyQB64: pq.Verkey, Digest: pq.Digest})
		}
		for gen := 0; gen < 2; gen++ {
			s, err := DerivePairwiseSeed(bip39, MessagingBranch, gen)
			if err != nil {
				return out, err
			}
			anchor, err := keymath.MessagingKeySet(s)
			if err != nil {
				return out, err
			}
			// Through JSON, so the anchor reads back as the file holds it.
			var a map[string]interface{}
			b, _ := json.Marshal(anchor)
			_ = json.Unmarshal(b, &a)
			ph.Messaging = append(ph.Messaging, messagingKeySet{Generation: gen,
				Path: fmt.Sprintf("m/44'/0'/0'/%d'/%d'", MessagingBranch, gen), Anchor: a})
		}
		forms, err := signatureFormsOf(bip39, ph.PostQuantum[0].Digest)
		if err != nil {
			return out, err
		}
		ph.SignatureForms = forms
		for _, k := range p.Keys {
			s, err := DerivePairwiseSeed(bip39, 0, k.Index)
			if err != nil {
				return out, err
			}
			pub := ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
			ph.Keys = append(ph.Keys, identityKey{
				Index:         k.Index,
				Path:          fmt.Sprintf("m/44'/0'/0'/0'/%d'", k.Index),
				SeedHex:       hex.EncodeToString(s),
				PublicKeyHex:  hex.EncodeToString(pub),
				PublicKeyQB64: iacrypto.VerkeyQB64(pub),
			})
		}
		out.Phrases = append(out.Phrases, ph)
	}
	return out, nil
}

// signatureFormsOf signs this phrase's founding with key 0 in each indexed form.
func signatureFormsOf(bip39 []byte, pqDigest string) (*signatureForms, error) {
	s0, err := DerivePairwiseSeed(bip39, 0, 0)
	if err != nil {
		return nil, err
	}
	s1, err := DerivePairwiseSeed(bip39, 0, 1)
	if err != nil {
		return nil, err
	}
	k0 := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(s0).Public().(ed25519.PublicKey))
	n1, err := keri.NextDigest(iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(s1).Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, err
	}
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{k0}, NextDigests: []string{n1, pqDigest},
		Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(s0), raw)
	enc := func(at keri.SignaturePlace) string {
		q, err := keri.EncodeIndexedSignature(sig, at)
		if err != nil {
			panic(err)
		}
		return q
	}
	return &signatureForms{FoundingRaw: string(raw), A: enc(keri.SamePlace(0)),
		TwoA: enc(keri.SignaturePlace{Index: 0, Ondex: 1}), B: enc(keri.SignaturePlace{Index: 0, CurrentOnly: true})}, nil
}

func TestTheIdentityKeyVectorsHold(t *testing.T) {
	committed, err := os.ReadFile(identityKeyVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var file identityKeyVectors
	dec := json.NewDecoder(bytes.NewReader(committed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		t.Fatal(err)
	}
	if len(file.Phrases) == 0 {
		t.Fatal("the vectors hold no phrase")
	}
	got, err := computeIdentityKeyVectors(file)
	if err != nil {
		t.Fatal(err)
	}
	if got.Published.PrivateKeyHex != slip10PublishedPrivate || got.Published.PublicKeyHex != slip10PublishedPublic {
		t.Fatalf("SLIP-0010's own vector does not reproduce: %+v", got.Published)
	}
	// Each path in the file is the one the derivation took.
	for _, p := range got.Phrases {
		for _, k := range p.Keys {
			path, err := parseHardenedPath(k.Path)
			if err != nil {
				t.Fatal(err)
			}
			bip39, _ := hex.DecodeString(p.BIP39SeedHex)
			s, _ := deriveSLIP10Ed25519(bip39, path)
			if hex.EncodeToString(s) != k.SeedHex {
				t.Fatalf("key %d is not the key at %s", k.Index, k.Path)
			}
		}
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if contractcheck.Writing(t) {
		if err := os.WriteFile(identityKeyVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(out, committed) {
		t.Fatalf("identity-key-vectors.json is not what this core derives:\n%s", out)
	}
}
