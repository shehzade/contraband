package state

import (
	"errors"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

var (
	ErrLedgerClosed      = errors.New("ledger is closed")
	ErrSessionNotFound   = errors.New("session not found")
	ErrProbeNotFound     = errors.New("probe result not found")
	ErrInvalidChunk      = errors.New("invalid chunk sequence or length")
	ErrHashMismatch      = errors.New("payload hash does not match expected hash")
	ErrSessionIncomplete = errors.New("session payload not fully reassembled or incomplete")
)

// LedgerObserver receives asynchronous notifications of live chunk arrivals and session completions.
type LedgerObserver interface {
	OnChunkReceived(session *common.Session, seq, total uint32, chunkSize int64)
	OnSessionCompleted(session *common.Session)
}

// ProbeObserver receives live notifications of recorded probes.
type ProbeObserver interface {
	OnProbeRecorded(probe *common.ProbeResult)
}

// Ledger defines the thread-safe contract for storing probes, tracking sessions,
// assembling chunks, and capturing forensic credentials across all server listeners.
type Ledger interface {
	// Probe Operations
	RecordProbe(result common.ProbeResult) error
	GetProbe(id string) (*common.ProbeResult, error)
	GetAllProbes() ([]common.ProbeResult, error)

	// Session Operations
	GetSession(token common.SessionToken) (*common.Session, error)
	UpdateSession(session *common.Session) error
	GetAllSessions() ([]*common.Session, error)

	// Chunk Assembly & Hash Verification
	AssembleChunk(token common.SessionToken, seq uint32, total uint32, payload []byte, expectedHash string) (*common.Session, bool, error)
	AssembleChunkWithMeta(token common.SessionToken, seq uint32, total uint32, payload []byte, expectedHash, clientIP, protocol string, port int, clientHost, networkZone string) (*common.Session, bool, error)
	GetSessionPayload(token common.SessionToken) ([]byte, error)

	// Credential Capture Operations
	RecordCredential(cred common.CapturedCredential) error
	GetCredentials() ([]common.CapturedCredential, error)

	// Forensic Export & Lifecycle
	ExportJSON() ([]byte, error)
	Reset() error
	Close() error

	// Observer attachment
	SetObserver(obs LedgerObserver)
}

// NewLedger creates a polymorphic Ledger instance. If dbPath is empty or ":memory:",
// it initializes a fast in-memory ledger. Otherwise, it opens a pure-Go SQLite ledger.
func NewLedger(dbPath string) (Ledger, error) {
	if dbPath == "" || dbPath == ":memory:" {
		return NewMemoryLedger(), nil
	}
	return NewSQLiteLedger(dbPath)
}

// CloneSession creates a deep copy of a Session struct to prevent data races.
func CloneSession(s *common.Session) *common.Session {
	if s == nil {
		return nil
	}
	copied := *s
	if s.Chunks != nil {
		copied.Chunks = make(map[uint32]common.ChunkRecord, len(s.Chunks))
		for k, v := range s.Chunks {
			copied.Chunks[k] = v
		}
	}
	return &copied
}

// FormatTimeMS returns the duration formatted in milliseconds.
func FormatTimeMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}
