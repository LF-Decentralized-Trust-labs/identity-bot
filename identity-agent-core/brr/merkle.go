package brr

import (
	"encoding/binary"

	"github.com/zeebo/blake3"
)

const treeDepth = 32
const bucketDepth = 7

// BulkProof mirrors the BRR service bulk-proof response.
type BulkProof struct {
	RegistryPrefix string   `json:"registry_prefix"`
	MerkleRoot     string   `json:"merkle_root"`
	BucketIndex    uint64   `json:"bucket_index"`
	BucketStart    uint64   `json:"bucket_start"`
	BucketEnd      uint64   `json:"bucket_end"`
	RevokedIDs     []string `json:"revoked_ids"`
	SubtreeRoot    string   `json:"subtree_root"`
	Siblings       []string `json:"siblings"`
}

var zeroHashes [treeDepth + 1][32]byte

func init() {
	zeroHashes[0] = blake3.Sum256([]byte("brr:empty:0"))
	for i := 1; i <= treeDepth; i++ {
		zeroHashes[i] = nodeHash(zeroHashes[i-1], zeroHashes[i-1])
	}
}

func leafHash(blindedIDHex string) [32]byte {
	return blake3.Sum256(append([]byte("brr:leaf:"), []byte(blindedIDHex)...))
}

func nodeHash(left, right [32]byte) [32]byte {
	buf := make([]byte, 64)
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	return blake3.Sum256(buf)
}

func leafIndex(blindedIDHex string) uint64 {
	h := leafHash(blindedIDHex)
	return binary.BigEndian.Uint64(h[:8]) & ((1 << treeDepth) - 1)
}

func verifyBulkProof(proof BulkProof) bool {
	subRoot, err := decodeHex32(proof.SubtreeRoot)
	if err != nil {
		return false
	}
	recomputed := composeToRoot(subRoot, proof.BucketStart, proof.Siblings, treeDepth-bucketDepth)
	root, err := decodeHex32(proof.MerkleRoot)
	if err != nil {
		return false
	}
	return recomputed == root
}

func composeToRoot(subRoot [32]byte, bucketStart uint64, siblings []string, subDepth int) [32]byte {
	cur := subRoot
	prefix := bucketStart
	for i, sibHex := range siblings {
		d := subDepth - i
		if d <= 0 {
			break
		}
		sib, _ := decodeHex32(sibHex)
		shift := treeDepth - d
		if (prefix>>shift)%2 == 0 {
			cur = nodeHash(cur, sib)
		} else {
			cur = nodeHash(sib, cur)
		}
		prefix &^= 1 << shift
	}
	return cur
}

func isRevoked(blindedID string, revoked []string) bool {
	for _, id := range revoked {
		if id == blindedID {
			return true
		}
	}
	return false
}

func decodeHex32(hexStr string) ([32]byte, error) {
	var out [32]byte
	if len(hexStr) != 64 {
		return out, errBadHex
	}
	for i := 0; i < 32; i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := hexStr[i*2+j]
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v |= c - 'A' + 10
			default:
				return out, errBadHex
			}
		}
		out[i] = v
	}
	return out, nil
}

var errBadHex = &badHexError{}

type badHexError struct{}

func (e *badHexError) Error() string { return "invalid hex" }