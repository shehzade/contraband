package server

import (
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server/state"
)

var (
	ErrLedgerClosed      = state.ErrLedgerClosed
	ErrSessionNotFound   = state.ErrSessionNotFound
	ErrProbeNotFound     = state.ErrProbeNotFound
	ErrInvalidChunk      = state.ErrInvalidChunk
	ErrHashMismatch      = state.ErrHashMismatch
	ErrSessionIncomplete = state.ErrSessionIncomplete
)

type Ledger = state.Ledger
type LedgerObserver = state.LedgerObserver
type MemoryLedger = state.MemoryLedger
type SQLiteLedger = state.SQLiteLedger

// NewLedger creates a polymorphic Ledger instance. If dbPath is empty or ":memory:",
// it initializes a fast in-memory ledger. Otherwise, it opens a pure-Go SQLite ledger.
func NewLedger(dbPath string) (Ledger, error) {
	return state.NewLedger(dbPath)
}

// NewMemoryLedger initializes a fresh in-memory ledger.
func NewMemoryLedger() *MemoryLedger {
	return state.NewMemoryLedger()
}

// NewSQLiteLedger opens or creates a SQLite database at the specified path.
func NewSQLiteLedger(dbPath string) (*SQLiteLedger, error) {
	return state.NewSQLiteLedger(dbPath)
}

// CloneSession creates a deep copy of a Session struct to prevent data races.
func CloneSession(s *common.Session) *common.Session {
	return state.CloneSession(s)
}

type ReassemblyResult = state.ReassemblyResult

// ReassembleChunks validates contiguous sequences, constructs the full binary payload,
// computes the rolling SHA-256 hash, and performs cryptographic verification.
func ReassembleChunks(chunks map[uint32][]byte, total uint32, expectedHash string) state.ReassemblyResult {
	return state.ReassembleChunks(chunks, total, expectedHash)
}

// FormatTimeMS returns the duration formatted in milliseconds.
func FormatTimeMS(d time.Duration) float64 {
	return state.FormatTimeMS(d)
}
