package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// MemoryLedger implements an in-memory, thread-safe session ledger and chunk assembler.
type MemoryLedger struct {
	mu              sync.RWMutex
	probes          map[string]common.ProbeResult
	sessions        map[common.SessionToken]*common.Session
	chunks          map[common.SessionToken]map[uint32][]byte
	chunkSizes      map[common.SessionToken]int64
	diskFiles       map[common.SessionToken]*os.File
	diskPaths       map[common.SessionToken]string
	completedTokens []common.SessionToken
	credentials     []common.CapturedCredential
	observer        LedgerObserver
	closed          bool
}

// NewMemoryLedger constructs an empty, initialized in-memory ledger.
func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{
		probes:          make(map[string]common.ProbeResult),
		sessions:        make(map[common.SessionToken]*common.Session),
		chunks:          make(map[common.SessionToken]map[uint32][]byte),
		chunkSizes:      make(map[common.SessionToken]int64),
		diskFiles:       make(map[common.SessionToken]*os.File),
		diskPaths:       make(map[common.SessionToken]string),
		completedTokens: make([]common.SessionToken, 0, 64),
		credentials:     make([]common.CapturedCredential, 0),
	}
}

// SetObserver attaches an observer to receive real-time chunk and session events.
func (m *MemoryLedger) SetObserver(obs LedgerObserver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.observer = obs
}

// RecordProbe stores or updates an individual probe result with strict validation.
func (m *MemoryLedger) RecordProbe(result common.ProbeResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrLedgerClosed
	}

	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now().UTC()
	}
	if result.TargetPort == 0 {
		result.TargetPort = 80
	}

	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid probe result: %w", err)
	}

	m.probes[result.ID] = result
	if m.observer != nil {
		if po, ok := m.observer.(ProbeObserver); ok {
			po.OnProbeRecorded(&result)
		}
	}
	return nil
}

// GetProbe retrieves a probe by its unique UUID v4 string.
func (m *MemoryLedger) GetProbe(id string) (*common.ProbeResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrLedgerClosed
	}

	p, exists := m.probes[id]
	if !exists {
		return nil, ErrProbeNotFound
	}

	copied := p
	return &copied, nil
}

// GetAllProbes returns a snapshot slice of all recorded probe results.
func (m *MemoryLedger) GetAllProbes() ([]common.ProbeResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrLedgerClosed
	}

	results := make([]common.ProbeResult, 0, len(m.probes))
	for _, p := range m.probes {
		results = append(results, p)
	}
	return results, nil
}

// GetSession retrieves a session by its 16-byte session token.
func (m *MemoryLedger) GetSession(token common.SessionToken) (*common.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrLedgerClosed
	}

	session, exists := m.sessions[token]
	if !exists {
		return nil, ErrSessionNotFound
	}

	return CloneSession(session), nil
}

// UpdateSession updates the mutable fields of an active session, creating it if it does not exist.
func (m *MemoryLedger) UpdateSession(session *common.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrLedgerClosed
	}
	if session == nil {
		return fmt.Errorf("cannot update nil session")
	}

	existing, exists := m.sessions[session.Token]
	if !exists {
		m.sessions[session.Token] = CloneSession(session)
		if _, ok := m.chunks[session.Token]; !ok {
			m.chunks[session.Token] = make(map[uint32][]byte)
		}
		return nil
	}

	if session.ClientIP != "" {
		existing.ClientIP = session.ClientIP
	}
	if session.Protocol != "" {
		existing.Protocol = session.Protocol
	}
	if session.Port != 0 {
		existing.Port = session.Port
	}
	existing.Status = session.Status
	existing.Verdict = session.Verdict
	if !session.LastActive.IsZero() {
		existing.LastActive = session.LastActive
	}
	if session.TotalBytes != 0 {
		existing.TotalBytes = session.TotalBytes
	}
	if session.ExpectedBytes != 0 {
		existing.ExpectedBytes = session.ExpectedBytes
	}
	if session.TotalChunks != 0 {
		existing.TotalChunks = session.TotalChunks
	}
	if session.ReceivedChunks != 0 {
		existing.ReceivedChunks = session.ReceivedChunks
	}
	existing.PayloadHash = session.PayloadHash
	if session.ExpectedHash != "" {
		existing.ExpectedHash = session.ExpectedHash
	}

	return nil
}

// GetAllSessions returns a snapshot of all active and completed sessions.
func (m *MemoryLedger) GetAllSessions() ([]*common.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrLedgerClosed
	}

	sessions := make([]*common.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, CloneSession(s))
	}
	return sessions, nil
}

// AssembleChunk buffers an incoming chunk, updates session metrics, triggers reassembly upon completion,
// and notifies any attached observer.
func (m *MemoryLedger) AssembleChunk(token common.SessionToken, seq uint32, total uint32, payload []byte, expectedHash string) (*common.Session, bool, error) {
	return m.AssembleChunkWithMeta(token, seq, total, payload, expectedHash, "", "", 0, "", "")
}

// AssembleChunkWithMeta buffers an incoming chunk with explicit client IP, protocol, port, host, and network zone metadata.
func (m *MemoryLedger) AssembleChunkWithMeta(token common.SessionToken, seq uint32, total uint32, payload []byte, expectedHash, clientIP, protocol string, port int, clientHost, networkZone string) (*common.Session, bool, error) {
	m.mu.Lock()

	if m.closed {
		m.mu.Unlock()
		return nil, false, ErrLedgerClosed
	}
	if total == 0 || seq == 0 || seq > total {
		m.mu.Unlock()
		return nil, false, fmt.Errorf("%w: seq=%d total=%d", ErrInvalidChunk, seq, total)
	}

	session, exists := m.sessions[token]
	if !exists {
		session = common.NewSession(token, clientIP, protocol, port)
		session.ClientHost = clientHost
		session.NetworkZone = networkZone
		session.TotalChunks = int(total)
		session.ExpectedHash = expectedHash
		m.sessions[token] = session
		m.chunks[token] = make(map[uint32][]byte)
	} else {
		// Idempotency: if session was already completed or corrupted, do not allow stray/duplicate
		// chunks to overwrite state or re-trigger reassembly.
		if session.Status == "completed" {
			retSession := CloneSession(session)
			m.mu.Unlock()
			return retSession, true, nil
		}
		if session.Status == "corrupted" {
			retSession := CloneSession(session)
			m.mu.Unlock()
			return retSession, true, ErrHashMismatch
		}

		if session.ClientIP == "" && clientIP != "" {
			session.ClientIP = clientIP
		}
		if session.Protocol == "" && protocol != "" {
			session.Protocol = protocol
		}
		if session.Port == 0 && port > 0 {
			session.Port = port
		}
		if session.ClientHost == "" && clientHost != "" {
			session.ClientHost = clientHost
		}
		if session.NetworkZone == "" && networkZone != "" {
			session.NetworkZone = networkZone
		}
	}

	// Dynamic disk spill: if cumulative session bytes exceed 2MB or chunk length >= 1MB,
	// spill to a temporary file so resident heap stays strictly < 32MB invariant.
	isSpilled := false
	var diskF *os.File
	if m.diskFiles != nil {
		diskF = m.diskFiles[token]
		if diskF != nil {
			isSpilled = true
		}
	}

	if !isSpilled && (session.TotalBytes+int64(len(payload)) > 2*1024*1024 || len(payload) >= 1024*1024) {
		tmpF, err := os.CreateTemp("", fmt.Sprintf("ctrb_%s_*.dat", token.String()))
		if err == nil {
			m.diskFiles[token] = tmpF
			diskF = tmpF
			isSpilled = true

			// Determine canonical chunk size
			cSize := m.chunkSizes[token]
			if cSize <= 0 {
				if seq < total {
					cSize = int64(len(payload))
				} else if total == 1 {
					cSize = int64(len(payload))
				} else if existingChunks, ok := m.chunks[token]; ok {
					for sIdx, cData := range existingChunks {
						if sIdx < total && len(cData) > 0 {
							cSize = int64(len(cData))
							break
						}
					}
				}
				if cSize > 0 {
					m.chunkSizes[token] = cSize
				}
			}

			// Flush existing in-memory chunks to temp file if cSize is known
			if cSize > 0 {
				if existingChunks, ok := m.chunks[token]; ok {
					for sIdx, cData := range existingChunks {
						if len(cData) > 0 {
							offset := int64(sIdx-1) * cSize
							_, _ = tmpF.WriteAt(cData, offset)
							existingChunks[sIdx] = nil // free memory, retain sequence key for deduplication
						}
					}
				}
			}
		}
	}

	if isSpilled && diskF != nil {
		tokenChunks := m.chunks[token]
		if tokenChunks == nil {
			tokenChunks = make(map[uint32][]byte)
			m.chunks[token] = tokenChunks
		}

		// Sequence Deduplication: if this sequence has already been received, treat as idempotent duplicate.
		// Avoids duplicate ReceivedChunks increment and premature reassembly on incomplete disk file.
		if _, duplicate := tokenChunks[seq]; duplicate {
			retSession := CloneSession(session)
			m.mu.Unlock()
			return retSession, false, nil
		}

		cSize := m.chunkSizes[token]
		if cSize <= 0 {
			if seq < total {
				cSize = int64(len(payload))
			} else if total == 1 {
				cSize = int64(len(payload))
			} else if existingChunks, ok := m.chunks[token]; ok {
				for sIdx, cData := range existingChunks {
					if sIdx < total && len(cData) > 0 {
						cSize = int64(len(cData))
						break
					}
				}
			}

			if cSize > 0 {
				m.chunkSizes[token] = cSize
				// Canonical chunk size just discovered; flush any previously buffered chunks (e.g. remainder chunk seq == total)
				for sIdx, cData := range tokenChunks {
					if len(cData) > 0 {
						remOffset := int64(sIdx-1) * cSize
						_, _ = diskF.WriteAt(cData, remOffset)
						tokenChunks[sIdx] = nil
					}
				}
			}
		}

		if cSize > 0 {
			offset := int64(seq-1) * cSize
			_, _ = diskF.WriteAt(payload, offset)
			tokenChunks[seq] = nil
		} else {
			// Canonical chunk size not yet known (remainder chunk arrived first for total > 1).
			// Buffer chunk in memory until canonical size is determined.
			chunkCopy := make([]byte, len(payload))
			copy(chunkCopy, payload)
			tokenChunks[seq] = chunkCopy
		}

		session.ReceivedChunks = len(tokenChunks)
		session.TotalBytes += int64(len(payload))
		session.LastActive = time.Now().UTC()
		if len(session.Chunks) < 32 {
			session.Chunks[seq] = common.ChunkRecord{
				Sequence:   seq,
				Total:      total,
				Length:     uint32(len(payload)),
				ReceivedAt: time.Now().UTC(),
			}
		}
	} else {
		tokenChunks := m.chunks[token]
		if _, duplicate := tokenChunks[seq]; !duplicate {
			chunkCopy := make([]byte, len(payload))
			copy(chunkCopy, payload)
			tokenChunks[seq] = chunkCopy

			session.ReceivedChunks = len(tokenChunks)
			session.TotalBytes += int64(len(payload))
			session.LastActive = time.Now().UTC()
			if len(session.Chunks) < 32 {
				session.Chunks[seq] = common.ChunkRecord{
					Sequence:   seq,
					Total:      total,
					Length:     uint32(len(payload)),
					ReceivedAt: time.Now().UTC(),
				}
			}
		}
	}

	obs := m.observer

	// Check if all chunks have arrived
	if session.ReceivedChunks >= int(total) {
		var reasmErr error
		if isSpilled && diskF != nil {
			// Ensure any buffered chunk (e.g. remainder chunk) is flushed to disk
			if cSize := m.chunkSizes[token]; cSize > 0 {
				if tokenChunks, ok := m.chunks[token]; ok {
					for sIdx, cData := range tokenChunks {
						if len(cData) > 0 {
							offset := int64(sIdx-1) * cSize
							_, _ = diskF.WriteAt(cData, offset)
							tokenChunks[sIdx] = nil
						}
					}
				}
			}
			_ = diskF.Sync()
			_, _ = diskF.Seek(0, 0)
			hasher := sha256.New()
			buf := make([]byte, 64*1024)
			_, _ = io.CopyBuffer(hasher, diskF, buf)
			computedHash := hex.EncodeToString(hasher.Sum(nil))

			if session.ExpectedHash != "" && !strings.EqualFold(computedHash, session.ExpectedHash) {
				session.PayloadHash = computedHash
				session.Status = "corrupted"
				session.Verdict = common.VerdictBlockedDLP
				reasmErr = ErrHashMismatch
			} else {
				session.PayloadHash = computedHash
				session.Status = "completed"
				session.Verdict = common.VerdictSuccess
			}
			tmpPath := diskF.Name()
			_ = diskF.Close()
			delete(m.diskFiles, token)
			delete(m.chunks, token)
			delete(m.chunkSizes, token)
			if m.diskPaths != nil {
				m.diskPaths[token] = tmpPath
			}
			m.completedTokens = append(m.completedTokens, token)
			if len(m.completedTokens) > 2000 {
				oldTok := m.completedTokens[0]
				m.completedTokens = m.completedTokens[1:]
				delete(m.chunks, oldTok)
				if m.diskPaths != nil {
					if oldPath, ok := m.diskPaths[oldTok]; ok {
						_ = os.Remove(oldPath)
						delete(m.diskPaths, oldTok)
					}
				}
			}
		} else {
			tokenChunks := m.chunks[token]
			res := ReassembleChunks(tokenChunks, total, session.ExpectedHash)
			session.PayloadHash = res.ComputedHash
			session.Status = res.Status
			session.Verdict = res.Verdict

			m.completedTokens = append(m.completedTokens, token)
			if len(m.completedTokens) > 2000 {
				oldTok := m.completedTokens[0]
				m.completedTokens = m.completedTokens[1:]
				delete(m.chunks, oldTok)
				if m.diskPaths != nil {
					if oldPath, ok := m.diskPaths[oldTok]; ok {
						_ = os.Remove(oldPath)
						delete(m.diskPaths, oldTok)
					}
				}
			}

			if res.Error != nil {
				reasmErr = res.Error
			}
		}

		if reasmErr != nil {
			retSession := CloneSession(session)
			m.mu.Unlock()
			if obs != nil {
				obs.OnChunkReceived(retSession, seq, total, int64(len(payload)))
				obs.OnSessionCompleted(retSession)
			}
			return retSession, true, reasmErr
		}

		retSession := CloneSession(session)
		m.mu.Unlock()

		if obs != nil {
			obs.OnChunkReceived(retSession, seq, total, int64(len(payload)))
			obs.OnSessionCompleted(retSession)
		}

		return retSession, true, nil
	}

	session.Status = "active"
	session.Verdict = common.VerdictBlockedL7
	retSession := CloneSession(session)
	m.mu.Unlock()

	if obs != nil {
		obs.OnChunkReceived(retSession, seq, total, int64(len(payload)))
	}

	return retSession, false, nil
}

// GetSessionPayload reconstructs the full contiguous payload for a session.
func (m *MemoryLedger) GetSessionPayload(token common.SessionToken) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrLedgerClosed
	}

	session, exists := m.sessions[token]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if session.Status == "corrupted" || session.Verdict == common.VerdictBlockedDLP {
		return nil, ErrHashMismatch
	}

	if m.diskPaths != nil {
		if p, ok := m.diskPaths[token]; ok && p != "" {
			return os.ReadFile(p)
		}
	}

	if m.diskFiles != nil {
		if df, ok := m.diskFiles[token]; ok && df != nil {
			_ = df.Sync()
			_, _ = df.Seek(0, 0)
			return io.ReadAll(df)
		}
	}

	chunks, exists := m.chunks[token]
	if !exists || len(chunks) == 0 {
		return nil, ErrSessionIncomplete
	}

	total := uint32(session.TotalChunks)
	if total == 0 {
		return nil, fmt.Errorf("%w: total chunks is 0", ErrSessionIncomplete)
	}
	if len(chunks) < int(total) {
		return nil, fmt.Errorf("%w: received %d of %d chunks", ErrSessionIncomplete, len(chunks), total)
	}

	var fullPayload []byte
	for s := uint32(1); s <= total; s++ {
		chunkData, found := chunks[s]
		if !found {
			return nil, fmt.Errorf("%w: missing chunk sequence %d", ErrSessionIncomplete, s)
		}
		fullPayload = append(fullPayload, chunkData...)
	}

	if session.ExpectedHash != "" {
		hasher := sha256.New()
		hasher.Write(fullPayload)
		computed := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(computed, session.ExpectedHash) {
			return nil, ErrHashMismatch
		}
	}

	return fullPayload, nil
}

// RecordCredential stores harvested credentials in memory.
func (m *MemoryLedger) RecordCredential(cred common.CapturedCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrLedgerClosed
	}

	m.credentials = append(m.credentials, cred)
	return nil
}

// GetCredentials returns a snapshot of all captured credentials.
func (m *MemoryLedger) GetCredentials() ([]common.CapturedCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrLedgerClosed
	}

	copied := make([]common.CapturedCredential, len(m.credentials))
	copy(copied, m.credentials)
	return copied, nil
}

// ExportJSON serializes the entire ledger state into JSON.
func (m *MemoryLedger) ExportJSON() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrLedgerClosed
	}

	probes := make([]common.ProbeResult, 0, len(m.probes))
	for _, p := range m.probes {
		probes = append(probes, p)
	}

	sessions := make([]*common.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, CloneSession(s))
	}

	dump := struct {
		TotalProbes      int                         `json:"total_probes"`
		TotalSessions    int                         `json:"total_sessions"`
		TotalCredentials int                         `json:"total_credentials"`
		Probes           []common.ProbeResult        `json:"probes"`
		Sessions         []*common.Session           `json:"sessions"`
		Credentials      []common.CapturedCredential `json:"credentials"`
	}{
		TotalProbes:      len(probes),
		TotalSessions:    len(sessions),
		TotalCredentials: len(m.credentials),
		Probes:           probes,
		Sessions:         sessions,
		Credentials:      m.credentials,
	}

	return json.MarshalIndent(dump, "", "  ")
}

// Reset clears all recorded probes, sessions, chunks, credentials, and disk buffer files.
func (m *MemoryLedger) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrLedgerClosed
	}

	for tok, f := range m.diskFiles {
		_ = f.Close()
		_ = os.Remove(f.Name())
		delete(m.diskFiles, tok)
	}
	for tok, p := range m.diskPaths {
		_ = os.Remove(p)
		delete(m.diskPaths, tok)
	}

	m.probes = make(map[string]common.ProbeResult)
	m.sessions = make(map[common.SessionToken]*common.Session)
	m.chunks = make(map[common.SessionToken]map[uint32][]byte)
	m.chunkSizes = make(map[common.SessionToken]int64)
	m.completedTokens = make([]common.SessionToken, 0, 64)
	m.credentials = make([]common.CapturedCredential, 0)
	return nil
}

// Close marks the ledger as closed and purges stored chunks.
func (m *MemoryLedger) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	m.chunks = make(map[common.SessionToken]map[uint32][]byte)
	m.chunkSizes = make(map[common.SessionToken]int64)
	for tok, f := range m.diskFiles {
		_ = f.Close()
		_ = os.Remove(f.Name())
		delete(m.diskFiles, tok)
	}
	for tok, p := range m.diskPaths {
		_ = os.Remove(p)
		delete(m.diskPaths, tok)
	}
	return nil
}
