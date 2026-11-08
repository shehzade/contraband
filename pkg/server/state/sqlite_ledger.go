package state

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	_ "modernc.org/sqlite" // Pure-Go SQLite driver for CGO_ENABLED=0 static compilation
)

// SQLiteLedger implements an ACID-compliant, persistent session ledger using pure-Go SQLite.
type SQLiteLedger struct {
	mu       sync.RWMutex
	db       *sql.DB
	observer LedgerObserver
	closed   bool
}

// NewSQLiteLedger opens or creates a SQLite database at the specified path.
func NewSQLiteLedger(dbPath string) (*SQLiteLedger, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database at %s: %w", dbPath, err)
	}

	db.SetMaxOpenConns(1)

	ledger := &SQLiteLedger{
		db: db,
	}

	if err := ledger.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize sqlite schema: %w", err)
	}

	return ledger, nil
}

// SetObserver attaches an observer to receive real-time chunk and session events.
func (s *SQLiteLedger) SetObserver(obs LedgerObserver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observer = obs
}

func (s *SQLiteLedger) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS probes (
		id TEXT PRIMARY KEY,
		timestamp TEXT NOT NULL,
		stage TEXT NOT NULL,
		protocol TEXT NOT NULL,
		target_port INTEGER NOT NULL,
		target_host TEXT NOT NULL,
		local_addr TEXT,
		proxy_hop TEXT,
		tls_profile TEXT,
		ja3_string TEXT,
		ja4_string TEXT,
		payload_type TEXT,
		carrier_type TEXT,
		target_volume_bytes INTEGER,
		bytes_sent INTEGER,
		bytes_recv INTEGER,
		throughput_kbps REAL,
		payload_hash TEXT,
		wire_hash TEXT,
		verdict TEXT NOT NULL,
		captured_hash TEXT,
		error_message TEXT,
		raw_evidence TEXT,
		timestamps_json TEXT
	);

	CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		token_hex TEXT NOT NULL,
		token TEXT,
		client_ip TEXT NOT NULL,
		protocol TEXT NOT NULL,
		port INTEGER NOT NULL,
		start_time TEXT NOT NULL,
		last_active TEXT NOT NULL,
		total_bytes INTEGER NOT NULL,
		expected_bytes INTEGER NOT NULL,
		total_chunks INTEGER NOT NULL,
		received_chunks INTEGER NOT NULL,
		payload_hash TEXT,
		expected_hash TEXT,
		status TEXT NOT NULL,
		verdict TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS session_chunks (
		session_id TEXT NOT NULL,
		seq INTEGER NOT NULL,
		total INTEGER NOT NULL,
		data BLOB NOT NULL,
		received_at TEXT NOT NULL,
		PRIMARY KEY (session_id, seq),
		FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
	);

	CREATE VIEW IF NOT EXISTS chunks AS
		SELECT session_id AS token, seq AS sequence, total, LENGTH(data) AS length, received_at, data AS payload
		FROM session_chunks;

	CREATE TRIGGER IF NOT EXISTS insert_chunks_trigger INSTEAD OF INSERT ON chunks
	BEGIN
		INSERT INTO session_chunks (session_id, seq, total, data, received_at)
		VALUES (NEW.token, NEW.sequence, NEW.total, NEW.payload, NEW.received_at)
		ON CONFLICT(session_id, seq) DO NOTHING;
	END;

	CREATE TABLE IF NOT EXISTS credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		protocol TEXT NOT NULL,
		timestamp TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		username TEXT NOT NULL,
		domain TEXT,
		hash_type TEXT NOT NULL,
		hash TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_session_chunks_session ON session_chunks(session_id);
	CREATE INDEX IF NOT EXISTS idx_probes_stage ON probes(stage);
	CREATE INDEX IF NOT EXISTS idx_probes_verdict ON probes(verdict);
	CREATE INDEX IF NOT EXISTS idx_probes_timestamp ON probes(timestamp);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLiteLedger) RecordProbe(result common.ProbeResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
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

	tsJSON, err := json.Marshal(result.Timestamps)
	if err != nil {
		return fmt.Errorf("failed to marshal timestamps: %w", err)
	}

	query := `
	INSERT INTO probes (
		id, timestamp, stage, protocol, target_port, target_host,
		local_addr, proxy_hop, tls_profile, ja3_string, ja4_string,
		payload_type, carrier_type, target_volume_bytes, bytes_sent, bytes_recv,
		throughput_kbps, payload_hash, wire_hash, verdict,
		captured_hash, error_message, raw_evidence, timestamps_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		verdict = excluded.verdict,
		bytes_sent = excluded.bytes_sent,
		bytes_recv = excluded.bytes_recv,
		throughput_kbps = excluded.throughput_kbps,
		payload_hash = excluded.payload_hash,
		wire_hash = excluded.wire_hash,
		error_message = excluded.error_message,
		raw_evidence = excluded.raw_evidence,
		timestamps_json = excluded.timestamps_json;
	`
	_, err = s.db.Exec(query,
		result.ID, result.Timestamp.Format(time.RFC3339Nano), result.Stage, result.Protocol,
		result.TargetPort, result.TargetHost, result.LocalAddr, result.ProxyHop,
		result.TLSProfile, result.JA3String, result.JA4String, result.PayloadType,
		result.CarrierType, result.TargetVolume, result.BytesSent, result.BytesRecv,
		result.ThroughputBps, result.PayloadHash, result.WireHash, string(result.Verdict),
		result.CapturedHash, result.ErrorMessage, result.RawEvidence, string(tsJSON),
	)
	if err == nil && s.observer != nil {
		if po, ok := s.observer.(ProbeObserver); ok {
			po.OnProbeRecorded(&result)
		}
	}
	return err
}

func (s *SQLiteLedger) GetProbe(id string) (*common.ProbeResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrLedgerClosed
	}

	query := `SELECT id, timestamp, stage, protocol, target_port, target_host, local_addr,
		proxy_hop, tls_profile, ja3_string, ja4_string, payload_type, carrier_type,
		target_volume_bytes, bytes_sent, bytes_recv, throughput_kbps, payload_hash,
		wire_hash, verdict, captured_hash, error_message, raw_evidence, timestamps_json
		FROM probes WHERE id = ?`

	row := s.db.QueryRow(query, id)
	return scanProbe(row)
}

func (s *SQLiteLedger) GetAllProbes() ([]common.ProbeResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrLedgerClosed
	}

	query := `SELECT id, timestamp, stage, protocol, target_port, target_host, local_addr,
		proxy_hop, tls_profile, ja3_string, ja4_string, payload_type, carrier_type,
		target_volume_bytes, bytes_sent, bytes_recv, throughput_kbps, payload_hash,
		wire_hash, verdict, captured_hash, error_message, raw_evidence, timestamps_json
		FROM probes ORDER BY timestamp ASC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []common.ProbeResult
	for rows.Next() {
		p, err := scanProbe(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *p)
	}
	return results, rows.Err()
}

func (s *SQLiteLedger) GetSession(token common.SessionToken) (*common.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrLedgerClosed
	}

	tokStr := token.String()
	query := `SELECT session_id, token_hex, token, client_ip, protocol, port, start_time, last_active,
		total_bytes, expected_bytes, total_chunks, received_chunks,
		payload_hash, expected_hash, status, verdict
		FROM sessions WHERE session_id = ? OR token_hex = ? OR token = ?`

	row := s.db.QueryRow(query, tokStr, tokStr, tokStr)
	session, err := scanSession(row, token)
	if err != nil {
		return nil, err
	}

	chunkQuery := `SELECT seq, total, LENGTH(data), received_at FROM session_chunks WHERE session_id = ?`
	cRows, err := s.db.Query(chunkQuery, session.SessionID)
	if err == nil {
		defer cRows.Close()
		for cRows.Next() {
			var cr common.ChunkRecord
			var rAt string
			if err := cRows.Scan(&cr.Sequence, &cr.Total, &cr.Length, &rAt); err == nil {
				cr.ReceivedAt, _ = time.Parse(time.RFC3339Nano, rAt)
				session.Chunks[cr.Sequence] = cr
			}
		}
	}

	return session, nil
}

func (s *SQLiteLedger) UpdateSession(session *common.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrLedgerClosed
	}
	if session == nil {
		return fmt.Errorf("cannot update nil session")
	}

	sessID := session.SessionID
	tokStr := session.Token.String()
	if sessID == "" {
		sessID = tokStr
	}
	if tokStr == "" {
		tokStr = sessID
	}

	query := `INSERT INTO sessions (
		session_id, token_hex, token, client_ip, protocol, port,
		start_time, last_active, total_bytes, expected_bytes,
		total_chunks, received_chunks, payload_hash, expected_hash,
		status, verdict
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(session_id) DO UPDATE SET
		status = excluded.status,
		verdict = excluded.verdict,
		last_active = excluded.last_active,
		payload_hash = CASE WHEN excluded.payload_hash != '' THEN excluded.payload_hash ELSE sessions.payload_hash END,
		expected_hash = CASE WHEN excluded.expected_hash != '' THEN excluded.expected_hash ELSE sessions.expected_hash END,
		total_bytes = CASE WHEN excluded.total_bytes > sessions.total_bytes THEN excluded.total_bytes ELSE sessions.total_bytes END,
		received_chunks = CASE WHEN excluded.received_chunks > sessions.received_chunks THEN excluded.received_chunks ELSE sessions.received_chunks END,
		total_chunks = CASE WHEN excluded.total_chunks > 0 THEN excluded.total_chunks ELSE sessions.total_chunks END;`

	_, err := s.db.Exec(query,
		sessID, tokStr, tokStr, session.ClientIP, session.Protocol, session.Port,
		session.StartTime.Format(time.RFC3339Nano),
		session.LastActive.Format(time.RFC3339Nano),
		session.TotalBytes, session.ExpectedBytes,
		session.TotalChunks, session.ReceivedChunks,
		session.PayloadHash, session.ExpectedHash,
		session.Status, string(session.Verdict),
	)
	return err
}

func (s *SQLiteLedger) GetAllSessions() ([]*common.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrLedgerClosed
	}

	query := `SELECT session_id, token_hex, token, client_ip, protocol, port, start_time, last_active,
		total_bytes, expected_bytes, total_chunks, received_chunks,
		payload_hash, expected_hash, status, verdict
		FROM sessions ORDER BY start_time ASC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*common.Session
	for rows.Next() {
		sess, err := scanSession(rows, common.SessionToken{})
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

func (s *SQLiteLedger) AssembleChunk(token common.SessionToken, seq uint32, total uint32, payload []byte, expectedHash string) (*common.Session, bool, error) {
	return s.AssembleChunkWithMeta(token, seq, total, payload, expectedHash, "", "", 0, "", "")
}

func (s *SQLiteLedger) AssembleChunkWithMeta(token common.SessionToken, seq uint32, total uint32, payload []byte, expectedHash, clientIP, protocol string, port int, clientHost, networkZone string) (*common.Session, bool, error) {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		return nil, false, ErrLedgerClosed
	}
	if total == 0 || seq == 0 || seq > total {
		s.mu.Unlock()
		return nil, false, fmt.Errorf("%w: seq=%d total=%d", ErrInvalidChunk, seq, total)
	}

	tokStr := token.String()
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)

	tx, err := s.db.Begin()
	if err != nil {
		s.mu.Unlock()
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()

	upsertSession := `
	INSERT INTO sessions (
		session_id, token_hex, token, client_ip, protocol, port, start_time, last_active,
		total_bytes, expected_bytes, total_chunks, received_chunks,
		payload_hash, expected_hash, status, verdict
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, 0, '', ?, 'active', 'BLOCKED_L7')
	ON CONFLICT(session_id) DO UPDATE SET
		total_chunks = excluded.total_chunks,
		client_ip = CASE WHEN sessions.client_ip = '' AND excluded.client_ip != '' THEN excluded.client_ip ELSE sessions.client_ip END,
		protocol = CASE WHEN sessions.protocol = '' AND excluded.protocol != '' THEN excluded.protocol ELSE sessions.protocol END,
		port = CASE WHEN sessions.port = 0 AND excluded.port != 0 THEN excluded.port ELSE sessions.port END,
		expected_hash = CASE WHEN excluded.expected_hash != '' THEN excluded.expected_hash ELSE sessions.expected_hash END;
	`
	if _, err := tx.Exec(upsertSession, tokStr, tokStr, tokStr, clientIP, protocol, port, nowStr, nowStr, total, expectedHash); err != nil {
		s.mu.Unlock()
		return nil, false, err
	}

	insertChunk := `
	INSERT INTO session_chunks (session_id, seq, total, data, received_at)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(session_id, seq) DO NOTHING;
	`
	res, err := tx.Exec(insertChunk, tokStr, seq, total, payload, nowStr)
	if err != nil {
		s.mu.Unlock()
		return nil, false, err
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected > 0 {
		updateStats := `
		UPDATE sessions SET
			received_chunks = received_chunks + 1,
			total_bytes = total_bytes + ?,
			last_active = ?
		WHERE session_id = ?;
		`
		if _, err := tx.Exec(updateStats, len(payload), nowStr, tokStr); err != nil {
			s.mu.Unlock()
			return nil, false, err
		}
	}

	var sess common.Session
	var sessID, tokHex string
	var tokNull sql.NullString
	var sTime, lActive, verdStr string
	querySess := `SELECT session_id, token_hex, token, client_ip, protocol, port, start_time, last_active,
		total_bytes, expected_bytes, total_chunks, received_chunks,
		payload_hash, expected_hash, status, verdict
		FROM sessions WHERE session_id = ?`
	err = tx.QueryRow(querySess, tokStr).Scan(
		&sessID, &tokHex, &tokNull, &sess.ClientIP, &sess.Protocol, &sess.Port, &sTime, &lActive,
		&sess.TotalBytes, &sess.ExpectedBytes, &sess.TotalChunks, &sess.ReceivedChunks,
		&sess.PayloadHash, &sess.ExpectedHash, &sess.Status, &verdStr,
	)
	if err != nil {
		s.mu.Unlock()
		return nil, false, err
	}
	sess.Token = token
	sess.SessionID = sessID
	sess.Verdict = common.Verdict(verdStr)
	sess.StartTime, _ = time.Parse(time.RFC3339Nano, sTime)
	sess.LastActive, _ = time.Parse(time.RFC3339Nano, lActive)

	obs := s.observer

	// Idempotency: if session was already completed or corrupted, return existing state
	if sess.Status == "completed" {
		_ = tx.Rollback()
		retSess := CloneSession(&sess)
		s.mu.Unlock()
		return retSess, true, nil
	}
	if sess.Status == "corrupted" {
		_ = tx.Rollback()
		retSess := CloneSession(&sess)
		s.mu.Unlock()
		return retSess, true, ErrHashMismatch
	}

	if sess.ReceivedChunks >= int(total) {
		chunkQuery := `SELECT seq, data FROM session_chunks WHERE session_id = ? ORDER BY seq ASC`
		cRows, err := tx.Query(chunkQuery, tokStr)
		if err != nil {
			s.mu.Unlock()
			return nil, false, err
		}
		defer cRows.Close()

		chunkMap := make(map[uint32][]byte)
		for cRows.Next() {
			var sNum uint32
			var pBytes []byte
			if err := cRows.Scan(&sNum, &pBytes); err == nil {
				chunkMap[sNum] = pBytes
			}
		}

		res := ReassembleChunks(chunkMap, total, sess.ExpectedHash)
		sess.PayloadHash = res.ComputedHash
		sess.Status = res.Status
		sess.Verdict = res.Verdict

		updateFinal := `UPDATE sessions SET payload_hash = ?, status = ?, verdict = ? WHERE session_id = ?`
		if _, err := tx.Exec(updateFinal, sess.PayloadHash, sess.Status, string(sess.Verdict), tokStr); err != nil {
			s.mu.Unlock()
			return nil, false, err
		}

		if err := tx.Commit(); err != nil {
			s.mu.Unlock()
			return nil, false, err
		}

		retSess := CloneSession(&sess)
		s.mu.Unlock()

		if obs != nil {
			obs.OnChunkReceived(retSess, seq, total, int64(len(payload)))
			obs.OnSessionCompleted(retSess)
		}

		if res.Error != nil {
			return retSess, true, res.Error
		}
		return retSess, true, nil
	}

	if err := tx.Commit(); err != nil {
		s.mu.Unlock()
		return nil, false, err
	}

	retSess := CloneSession(&sess)
	s.mu.Unlock()

	if obs != nil {
		obs.OnChunkReceived(retSess, seq, total, int64(len(payload)))
	}

	return retSess, false, nil
}

func (s *SQLiteLedger) GetSessionPayload(token common.SessionToken) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrLedgerClosed
	}

	tokStr := token.String()

	var totalChunks int
	var status, verdict, expectedHash string
	err := s.db.QueryRow("SELECT total_chunks, status, verdict, expected_hash FROM sessions WHERE session_id = ? OR token_hex = ? OR token = ?", tokStr, tokStr, tokStr).Scan(&totalChunks, &status, &verdict, &expectedHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	if status == "corrupted" || common.Verdict(verdict) == common.VerdictBlockedDLP {
		return nil, ErrHashMismatch
	}

	if totalChunks <= 0 {
		return nil, fmt.Errorf("%w: total chunks is %d", ErrSessionIncomplete, totalChunks)
	}

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM session_chunks WHERE session_id = ? OR session_id IN (SELECT session_id FROM sessions WHERE token_hex = ? OR token = ?)", tokStr, tokStr, tokStr).Scan(&count); err != nil {
		return nil, err
	}
	if count < totalChunks {
		return nil, fmt.Errorf("%w: received %d of %d chunks", ErrSessionIncomplete, count, totalChunks)
	}

	query := `SELECT seq, data FROM session_chunks WHERE session_id = ? OR session_id IN (SELECT session_id FROM sessions WHERE token_hex = ? OR token = ?) ORDER BY seq ASC`
	rows, err := s.db.Query(query, tokStr, tokStr, tokStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fullPayload []byte
	var expectedSeq uint32 = 1

	for rows.Next() {
		var seq uint32
		var payload []byte
		if err := rows.Scan(&seq, &payload); err != nil {
			return nil, err
		}
		if seq != expectedSeq {
			return nil, fmt.Errorf("%w: missing sequence %d (found %d)", ErrSessionIncomplete, expectedSeq, seq)
		}
		fullPayload = append(fullPayload, payload...)
		expectedSeq++
	}

	if int(expectedSeq-1) != totalChunks {
		return nil, fmt.Errorf("%w: missing trailing chunks: expected %d, assembled %d", ErrSessionIncomplete, totalChunks, expectedSeq-1)
	}

	if expectedHash != "" {
		hasher := sha256.New()
		hasher.Write(fullPayload)
		computed := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(computed, expectedHash) {
			return nil, ErrHashMismatch
		}
	}

	return fullPayload, nil
}

func (s *SQLiteLedger) RecordCredential(cred common.CapturedCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrLedgerClosed
	}

	query := `INSERT INTO credentials (protocol, timestamp, client_ip, username, domain, hash_type, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		cred.Protocol, cred.Timestamp.Format(time.RFC3339Nano), cred.ClientIP,
		cred.Username, cred.Domain, cred.HashType, cred.Hash,
	)
	return err
}

func (s *SQLiteLedger) GetCredentials() ([]common.CapturedCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrLedgerClosed
	}

	query := `SELECT protocol, timestamp, client_ip, username, domain, hash_type, hash FROM credentials ORDER BY id ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []common.CapturedCredential
	for rows.Next() {
		var c common.CapturedCredential
		var ts string
		if err := rows.Scan(&c.Protocol, &ts, &c.ClientIP, &c.Username, &c.Domain, &c.HashType, &c.Hash); err != nil {
			return nil, err
		}
		c.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (s *SQLiteLedger) ExportJSON() ([]byte, error) {
	probes, err := s.GetAllProbes()
	if err != nil {
		return nil, err
	}
	sessions, err := s.GetAllSessions()
	if err != nil {
		return nil, err
	}
	creds, err := s.GetCredentials()
	if err != nil {
		return nil, err
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
		TotalCredentials: len(creds),
		Probes:           probes,
		Sessions:         sessions,
		Credentials:      creds,
	}

	return json.MarshalIndent(dump, "", "  ")
}

// Reset clears all records from session_chunks, sessions, probes, and credentials tables.
func (s *SQLiteLedger) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrLedgerClosed
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM session_chunks`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM probes`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM credentials`); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLiteLedger) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanProbe(s scannable) (*common.ProbeResult, error) {
	var p common.ProbeResult
	var ts, verdStr, tsJSON string
	err := s.Scan(
		&p.ID, &ts, &p.Stage, &p.Protocol, &p.TargetPort, &p.TargetHost,
		&p.LocalAddr, &p.ProxyHop, &p.TLSProfile, &p.JA3String, &p.JA4String,
		&p.PayloadType, &p.CarrierType, &p.TargetVolume, &p.BytesSent, &p.BytesRecv,
		&p.ThroughputBps, &p.PayloadHash, &p.WireHash, &verdStr,
		&p.CapturedHash, &p.ErrorMessage, &p.RawEvidence, &tsJSON,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrProbeNotFound
		}
		return nil, err
	}

	p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	p.Verdict = common.Verdict(verdStr)
	if tsJSON != "" {
		_ = json.Unmarshal([]byte(tsJSON), &p.Timestamps)
	}
	return &p, nil
}

func scanSession(s scannable, fallbackToken common.SessionToken) (*common.Session, error) {
	var sess common.Session
	var sessID, tokHex string
	var tok sql.NullString
	var sTime, lActive, verdStr string
	err := s.Scan(
		&sessID, &tokHex, &tok, &sess.ClientIP, &sess.Protocol, &sess.Port, &sTime, &lActive,
		&sess.TotalBytes, &sess.ExpectedBytes, &sess.TotalChunks, &sess.ReceivedChunks,
		&sess.PayloadHash, &sess.ExpectedHash, &sess.Status, &verdStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	if tok.Valid && tok.String != "" {
		parsed, err := common.ParseSessionToken(tok.String)
		if err == nil {
			sess.Token = parsed
		} else {
			sess.Token = fallbackToken
		}
	} else if tokHex != "" {
		parsed, err := common.ParseSessionToken(tokHex)
		if err == nil {
			sess.Token = parsed
		} else {
			sess.Token = fallbackToken
		}
	} else {
		sess.Token = fallbackToken
	}

	if sessID != "" {
		sess.SessionID = sessID
	} else {
		sess.SessionID = sess.Token.String()
	}

	sess.Verdict = common.Verdict(verdStr)
	sess.StartTime, _ = time.Parse(time.RFC3339Nano, sTime)
	sess.LastActive, _ = time.Parse(time.RFC3339Nano, lActive)
	sess.Chunks = make(map[uint32]common.ChunkRecord)

	return &sess, nil
}
