package evasion

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"sort"
	"sync"

	"github.com/shehzade/contraband/pkg/common"
)

// StreamChunker provides memory-bounded, sequential chunk framing over an io.Reader.
type StreamChunker struct {
	reader      io.Reader
	token       common.SessionToken
	chunkSize   int
	totalBytes  int64
	totalChunks uint32
	seq         uint32
	buf         []byte
	bufPtr      *[]byte
	pool        *sync.Pool
	hasher      hash.Hash
}

var chunkBufferPools sync.Map // map[int]*sync.Pool

func getChunkBufferPool(size int) *sync.Pool {
	if p, ok := chunkBufferPools.Load(size); ok {
		return p.(*sync.Pool)
	}
	p := &sync.Pool{
		New: func() any {
			b := make([]byte, size)
			return &b
		},
	}
	actual, _ := chunkBufferPools.LoadOrStore(size, p)
	return actual.(*sync.Pool)
}

// NewStreamChunker creates an iterator that reads up to chunkSize bytes and frames with ChunkHeader.
func NewStreamChunker(reader io.Reader, token common.SessionToken, chunkSize int, totalBytes int64) (*StreamChunker, error) {
	if chunkSize <= 0 {
		chunkSize = common.DefaultChunkSize
	}
	if token.IsZero() {
		tok, err := common.NewSessionToken()
		if err != nil {
			return nil, err
		}
		token = tok
	}

	// Auto-detect length if reader is *bytes.Reader or *bytes.Buffer
	if totalBytes <= 0 {
		if br, ok := reader.(*bytes.Reader); ok {
			totalBytes = int64(br.Len())
		} else if bb, ok := reader.(*bytes.Buffer); ok {
			totalBytes = int64(bb.Len())
		}
	}

	totalChunks := uint32(1)
	if totalBytes > 0 {
		totalChunks = uint32((totalBytes + int64(chunkSize) - 1) / int64(chunkSize))
	}

	bufSize := common.ChunkHeaderSize + chunkSize
	pool := getChunkBufferPool(bufSize)
	bufPtr := pool.Get().(*[]byte)
	if len(*bufPtr) < bufSize {
		*bufPtr = make([]byte, bufSize)
	}

	return &StreamChunker{
		reader:      reader,
		token:       token,
		chunkSize:   chunkSize,
		totalBytes:  totalBytes,
		totalChunks: totalChunks,
		buf:         (*bufPtr)[:bufSize],
		bufPtr:      bufPtr,
		pool:        pool,
		hasher:      sha256.New(),
	}, nil
}

func (s *StreamChunker) TotalChunks() uint32 {
	return s.totalChunks
}

// PayloadHashHex returns the lowercase hex-encoded SHA-256 hash of all payload bytes streamed so far.
func (s *StreamChunker) PayloadHashHex() string {
	return hex.EncodeToString(s.hasher.Sum(nil))
}

// Next reads the next chunk slice and returns the framed wire bytes (Header + Payload).
// Returns (chunkFrame, seq, err). At EOF, returns (nil, 0, io.EOF).
func (s *StreamChunker) Next() ([]byte, uint32, error) {
	if s.totalBytes > 0 && s.seq >= s.totalChunks {
		return nil, 0, io.EOF
	}

	payloadBuf := s.buf[common.ChunkHeaderSize : common.ChunkHeaderSize+s.chunkSize]
	n, err := io.ReadFull(s.reader, payloadBuf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, 0, err
	}
	if n == 0 {
		if s.totalBytes == 0 && s.seq == 0 {
			s.seq = 1
			hdr := common.ChunkHeader{
				Magic:       common.MagicHeader,
				Token:       s.token,
				Sequence:    1,
				TotalChunks: 1,
				PayloadLen:  0,
			}
			hdrBytes, err := hdr.MarshalBinary()
			if err != nil {
				return nil, 0, err
			}
			copy(s.buf[:common.ChunkHeaderSize], hdrBytes)
			return s.buf[:common.ChunkHeaderSize], 1, nil
		}
		return nil, 0, io.EOF
	}

	s.hasher.Write(payloadBuf[:n])
	s.seq++
	hdr := common.ChunkHeader{
		Magic:       common.MagicHeader,
		Token:       s.token,
		Sequence:    s.seq,
		TotalChunks: s.totalChunks,
		PayloadLen:  uint32(n),
	}
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		return nil, 0, err
	}
	copy(s.buf[:common.ChunkHeaderSize], hdrBytes)

	return s.buf[:common.ChunkHeaderSize+n], s.seq, nil
}

// Close releases any allocated buffer back to the sync.Pool.
func (s *StreamChunker) Close() error {
	if s.bufPtr != nil && s.pool != nil {
		s.pool.Put(s.bufPtr)
		s.bufPtr = nil
		s.buf = nil
	}
	return nil
}

func ChunkPayload(data []byte, token common.SessionToken, chunkSize int) ([][]byte, error) {
	if chunkSize <= 0 {
		chunkSize = common.DefaultChunkSize
	}
	totalLen := len(data)
	if totalLen == 0 {
		totalChunks := uint32(1)
		hdr := common.ChunkHeader{
			Magic:       common.MagicHeader,
			Token:       token,
			Sequence:    1,
			TotalChunks: totalChunks,
			PayloadLen:  0,
		}
		hdrBytes, _ := hdr.MarshalBinary()
		return [][]byte{hdrBytes}, nil
	}

	totalChunks := uint32((totalLen + chunkSize - 1) / chunkSize)
	chunks := make([][]byte, 0, totalChunks)

	for seq := uint32(1); seq <= totalChunks; seq++ {
		start := int(seq-1) * chunkSize
		end := start + chunkSize
		if end > totalLen {
			end = totalLen
		}
		chunkSlice := data[start:end]

		hdr := common.ChunkHeader{
			Magic:       common.MagicHeader,
			Token:       token,
			Sequence:    seq,
			TotalChunks: totalChunks,
			PayloadLen:  uint32(len(chunkSlice)),
		}
		hdrBytes, err := hdr.MarshalBinary()
		if err != nil {
			return nil, err
		}

		frame := make([]byte, len(hdrBytes)+len(chunkSlice))
		copy(frame[:len(hdrBytes)], hdrBytes)
		copy(frame[len(hdrBytes):], chunkSlice)
		chunks = append(chunks, frame)
	}

	return chunks, nil
}

func ReassembleChunks(frames [][]byte) ([]byte, error) {
	if len(frames) == 0 {
		return nil, fmt.Errorf("no frames provided for reassembly")
	}

	type chunkEntry struct {
		hdr     common.ChunkHeader
		payload []byte
	}

	entries := make([]chunkEntry, 0, len(frames))
	var expectedTotal uint32
	var expectedToken common.SessionToken

	for i, frame := range frames {
		if len(frame) < common.ChunkHeaderSize {
			return nil, fmt.Errorf("frame %d shorter than 32-byte header (%d bytes)", i, len(frame))
		}
		var hdr common.ChunkHeader
		if err := hdr.UnmarshalBinary(frame[:common.ChunkHeaderSize]); err != nil {
			return nil, fmt.Errorf("frame %d has invalid header: %w", i, err)
		}
		if i == 0 {
			expectedTotal = hdr.TotalChunks
			expectedToken = hdr.Token
		} else {
			if hdr.TotalChunks != expectedTotal {
				return nil, fmt.Errorf("mismatched total chunks count in frame %d", i)
			}
			if hdr.Token != expectedToken {
				return nil, fmt.Errorf("mismatched session token in frame %d", i)
			}
		}
		payload := frame[common.ChunkHeaderSize : common.ChunkHeaderSize+hdr.PayloadLen]
		entries = append(entries, chunkEntry{hdr: hdr, payload: payload})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].hdr.Sequence < entries[j].hdr.Sequence
	})

	var buf bytes.Buffer
	for expectedSeq := uint32(1); expectedSeq <= expectedTotal; expectedSeq++ {
		idx := int(expectedSeq - 1)
		if idx >= len(entries) || entries[idx].hdr.Sequence != expectedSeq {
			return nil, fmt.Errorf("missing chunk sequence %d of %d", expectedSeq, expectedTotal)
		}
		buf.Write(entries[idx].payload)
	}

	return buf.Bytes(), nil
}
