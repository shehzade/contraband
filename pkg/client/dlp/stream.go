package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"math/rand"
	"strings"
	"sync"
	"time"
)

const (
	StreamChunkSize = 64 * 1024 // 64KB chunk buffer
)

type GeneratorConfig struct {
	DLPType     string      // pci, ssn, hipaa, keys, pii, all
	CarrierType string      // csv, json, sql, email, syslog, noise
	Domain      string      // e.g. acme-corp.internal
	MinEntropy  float64     // default 3.5
	MaxEntropy  float64     // default 5.5
	Seed        int64       // deterministic seed (0 = random)
	FormatStyle FormatStyle // raw, hyphenated, space
}

type DLPStreamer struct {
	cfg         GeneratorConfig
	targetBytes int64
	bytesRead   int64
	rng         *rand.Rand
	hasher      hash.Hash
	buf         []byte
	bufOffset   int
	curBufPtr   *[]byte
	pool        *sync.Pool
	tuner       *EntropyTuner
	closed      bool
	headerSent  bool
}

// NewDLPStreamer creates a memory-bounded streaming io.Reader.
func NewDLPStreamer(targetBytes int64, cfg GeneratorConfig) *DLPStreamer {
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	minEnt := cfg.MinEntropy
	maxEnt := cfg.MaxEntropy
	if minEnt <= 0 {
		minEnt = 3.5
	}
	if maxEnt <= 0 {
		maxEnt = 5.5
	}

	return &DLPStreamer{
		cfg:         cfg,
		targetBytes: targetBytes,
		rng:         rand.New(rand.NewSource(seed)),
		hasher:      sha256.New(),
		tuner:       NewEntropyTuner(minEnt, maxEnt),
		pool: &sync.Pool{
			New: func() any {
				b := make([]byte, StreamChunkSize)
				return &b
			},
		},
	}
}

// Read satisfies io.Reader, generating streaming data on the fly.
func (s *DLPStreamer) Read(p []byte) (int, error) {
	if s.closed {
		return 0, io.EOF
	}
	if s.bytesRead >= s.targetBytes {
		return 0, io.EOF
	}

	remainingTotal := s.targetBytes - s.bytesRead
	maxToRead := int64(len(p))
	if maxToRead > remainingTotal {
		maxToRead = remainingTotal
	}

	totalWritten := 0

	for totalWritten < int(maxToRead) {
		if s.buf == nil || s.bufOffset >= len(s.buf) {
			s.generateNextChunk()
		}

		avail := len(s.buf) - s.bufOffset
		want := int(maxToRead) - totalWritten
		toCopy := avail
		if toCopy > want {
			toCopy = want
		}

		copy(p[totalWritten:totalWritten+toCopy], s.buf[s.bufOffset:s.bufOffset+toCopy])
		s.bufOffset += toCopy
		totalWritten += toCopy
		s.bytesRead += int64(toCopy)
	}

	if totalWritten > 0 {
		s.hasher.Write(p[:totalWritten])
	}

	if s.bytesRead >= s.targetBytes {
		return totalWritten, io.EOF
	}
	return totalWritten, nil
}

func (s *DLPStreamer) generateNextChunk() {
	if s.curBufPtr != nil {
		s.pool.Put(s.curBufPtr)
		s.curBufPtr = nil
	}
	s.curBufPtr = s.pool.Get().(*[]byte)
	chunk := (*s.curBufPtr)[:0]

	// Send CSV header on first chunk if CSV carrier
	if !s.headerSent && strings.ToLower(s.cfg.CarrierType) == "csv" {
		header := []byte("EmployeeID,FullName,TaxID_SSN,CardNumber,ExpDate,Department,Email,Salary\n")
		chunk = append(chunk, header...)
		s.headerSent = true
	}

	// Fill chunk up to StreamChunkSize
	dlpTypes := []string{"pci", "ssn", "keys", "hipaa", "pii"}
	for len(chunk) < StreamChunkSize {
		typ := s.cfg.DLPType
		if typ == "" || typ == "all" || typ == "mixed" {
			typ = dlpTypes[s.rng.Intn(len(dlpTypes))]
		}
		rec := GenerateCarrierRecord(s.cfg.CarrierType, typ, s.rng, s.cfg.Domain)
		chunk = append(chunk, rec...)
	}

	// Apply entropy tuning if requested
	if s.cfg.MinEntropy > 0 && s.cfg.MaxEntropy > 0 {
		chunk = s.tuner.Modulate(chunk, s.rng)
	}

	s.buf = chunk
	s.bufOffset = 0
}

// Checksum returns the SHA-256 hash of all emitted payload bytes.
func (s *DLPStreamer) Checksum() [32]byte {
	var sum [32]byte
	copy(sum[:], s.hasher.Sum(nil))
	return sum
}

// ChecksumHex returns the lowercase hex representation of the SHA-256 hash.
func (s *DLPStreamer) ChecksumHex() string {
	return hex.EncodeToString(s.hasher.Sum(nil))
}

// BytesRead returns total bytes streamed so far.
func (s *DLPStreamer) BytesRead() int64 {
	return s.bytesRead
}

// TotalTargetBytes returns the configured target volume.
func (s *DLPStreamer) TotalTargetBytes() int64 {
	return s.targetBytes
}

// Close closes the streamer.
func (s *DLPStreamer) Close() error {
	s.closed = true
	s.buf = nil
	if s.curBufPtr != nil {
		s.pool.Put(s.curBufPtr)
		s.curBufPtr = nil
	}
	return nil
}
