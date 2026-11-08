package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/shehzade/contraband/pkg/common"
)

// ReassemblyResult contains the assembled bytes, hash, and verdict.
type ReassemblyResult struct {
	Payload      []byte
	ComputedHash string
	Verdict      common.Verdict
	Status       string
	Error        error
}

// ReassembleChunks validates contiguous sequences, constructs the full binary payload,
// computes the rolling SHA-256 hash, and performs cryptographic verification.
func ReassembleChunks(chunks map[uint32][]byte, total uint32, expectedHash string) ReassemblyResult {
	if total == 0 {
		return ReassemblyResult{
			Status:  "corrupted",
			Verdict: common.VerdictBlockedL7,
			Error:   fmt.Errorf("%w: total chunks is zero", ErrInvalidChunk),
		}
	}

	var fullPayload []byte
	hasher := sha256.New()

	for s := uint32(1); s <= total; s++ {
		chunkData, found := chunks[s]
		if !found {
			return ReassemblyResult{
				Status:  "corrupted",
				Verdict: common.VerdictBlockedL7,
				Error:   fmt.Errorf("%w: chunk %d missing during final assembly", ErrSessionIncomplete, s),
			}
		}
		if len(fullPayload)+len(chunkData) <= 2*1024*1024 {
			fullPayload = append(fullPayload, chunkData...)
		}
		hasher.Write(chunkData)
	}

	computedHash := hex.EncodeToString(hasher.Sum(nil))

	if expectedHash != "" && !strings.EqualFold(computedHash, expectedHash) {
		return ReassemblyResult{
			Payload:      fullPayload,
			ComputedHash: computedHash,
			Status:       "corrupted",
			Verdict:      common.VerdictBlockedDLP,
			Error:        ErrHashMismatch,
		}
	}

	return ReassemblyResult{
		Payload:      fullPayload,
		ComputedHash: computedHash,
		Status:       "completed",
		Verdict:      common.VerdictSuccess,
		Error:        nil,
	}
}
