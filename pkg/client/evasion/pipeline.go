package evasion

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/shehzade/contraband/pkg/common"
)

type CompressionMethod string

const (
	CompressNone CompressionMethod = "none"
	CompressZlib CompressionMethod = "zlib"
	CompressGzip CompressionMethod = "gzip"
	CompressZstd CompressionMethod = "zstd"
)

type CarrierType string

const (
	CarrierNone    CarrierType = "raw"
	CarrierBMP     CarrierType = "bmp"
	CarrierPNG     CarrierType = "png"
	CarrierWAV     CarrierType = "wav"
	CarrierJPEGZIP CarrierType = "jpeg-zip"
	CarrierPDFJAR  CarrierType = "pdf-jar"
)

type PipelineConfig struct {
	Compression   CompressionMethod
	CompressLevel int // e.g. zlib.DefaultCompression (1-9)
	Encrypt       bool
	Passphrase    string // For PBKDF2 key derivation
	RawKey        []byte // 32-byte raw AES key (optional alternative to Passphrase)
	SessionToken  common.SessionToken
	ChunkSize     int // Default: 1MB (common.DefaultChunkSize)
	Carrier       CarrierType
	Seed          int64 // Deterministic seed for procedural carrier generation
	Transforms    string // Comma-separated transform chain (e.g. "zstd,aes_gcm,base64")
}

type Pipeline struct {
	cfg PipelineConfig
}

func NewPipeline(cfg PipelineConfig) (*Pipeline, error) {
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = common.DefaultChunkSize
	}
	if cfg.SessionToken.IsZero() {
		tok, err := common.NewSessionToken()
		if err != nil {
			return nil, err
		}
		cfg.SessionToken = tok
	}
	return &Pipeline{cfg: cfg}, nil
}

// Transform takes raw payload bytes, compresses, encrypts, chunks with 32B ChunkHeader,
// TransformStream applies compression and encryption to an io.Reader stream without chunking or framing,
// returning an io.Reader suitable for single-layer wire transmission.
func (p *Pipeline) TransformStream(ctx context.Context, reader io.Reader) (io.Reader, error) {
	rawPayload, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read stream for evasion transform: %w", err)
	}
	transformed, err := p.TransformBytes(rawPayload)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(transformed), nil
}

// TransformBytes applies compression and encryption to the raw payload without chunking or framing.
func (p *Pipeline) TransformBytes(rawPayload []byte) ([]byte, error) {
	if p.cfg.Transforms != "" && p.cfg.Transforms != "raw" && p.cfg.Transforms != "none" {
		return p.TransformChain(rawPayload)
	}

	// 1. Compression
	compressed, err := Compress(rawPayload, p.cfg.Compression, p.cfg.CompressLevel)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// 2. Encryption
	var encrypted []byte
	if p.cfg.Encrypt {
		if p.cfg.Passphrase != "" {
			encrypted, err = EncryptWithPassphrase(compressed, p.cfg.Passphrase)
		} else if len(p.cfg.RawKey) == 32 {
			encrypted, err = EncryptAESGCM(compressed, p.cfg.RawKey)
		} else {
			return nil, fmt.Errorf("encryption enabled but neither 32-byte key nor passphrase provided")
		}
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
	} else {
		encrypted = compressed
	}
	return encrypted, nil
}

// Transform compresses, encrypts, chunks, adds 32-byte wire framing,
// and embeds into the configured carrier format.
func (p *Pipeline) Transform(ctx context.Context, rawPayload []byte) ([][]byte, error) {
	transformed, err := p.TransformBytes(rawPayload)
	if err != nil {
		return nil, err
	}

	// Chunking & 32-byte Framing
	framedChunks, err := ChunkPayload(transformed, p.cfg.SessionToken, p.cfg.ChunkSize)
	if err != nil {
		return nil, fmt.Errorf("chunking failed: %w", err)
	}

	// Carrier Embedding
	if p.cfg.Carrier == CarrierNone || p.cfg.Carrier == "" {
		return framedChunks, nil
	}

	embeddedCarriers := make([][]byte, len(framedChunks))
	for i, chunk := range framedChunks {
		carrierBytes, err := EmbedCarrier(chunk, p.cfg.Carrier, p.cfg.Seed+int64(i))
		if err != nil {
			return nil, fmt.Errorf("carrier embedding failed for chunk %d: %w", i+1, err)
		}
		embeddedCarriers[i] = carrierBytes
	}

	return embeddedCarriers, nil
}

// ReverseExtract takes carrier data, extracts chunk payload, verifies ChunkHeader,
// decrypts, and decompresses back to original payload.
func (p *Pipeline) ReverseExtract(ctx context.Context, carrierData []byte) ([]byte, *common.ChunkHeader, error) {
	// 1. Carrier Extraction
	extractedChunk, err := ExtractCarrier(carrierData, p.cfg.Carrier)
	if err != nil {
		return nil, nil, fmt.Errorf("carrier extraction failed: %w", err)
	}

	// 2. Parse 32-byte ChunkHeader
	if len(extractedChunk) < common.ChunkHeaderSize {
		return nil, nil, fmt.Errorf("extracted chunk too short for ChunkHeader (%d < %d)",
			len(extractedChunk), common.ChunkHeaderSize)
	}
	var header common.ChunkHeader
	if err := header.UnmarshalBinary(extractedChunk[:common.ChunkHeaderSize]); err != nil {
		return nil, nil, fmt.Errorf("invalid chunk header: %w", err)
	}

	payloadData := extractedChunk[common.ChunkHeaderSize : common.ChunkHeaderSize+header.PayloadLen]

	if p.cfg.Transforms != "" && p.cfg.Transforms != "raw" && p.cfg.Transforms != "none" {
		decompressed, err := p.ReverseTransformChain(payloadData)
		if err != nil {
			return nil, nil, fmt.Errorf("reverse transform failed: %w", err)
		}
		return decompressed, &header, nil
	}

	// 3. Decryption
	var decrypted []byte
	if p.cfg.Encrypt {
		if p.cfg.Passphrase != "" {
			decrypted, err = DecryptWithPassphrase(payloadData, p.cfg.Passphrase)
		} else if len(p.cfg.RawKey) == 32 {
			decrypted, err = DecryptAESGCM(payloadData, p.cfg.RawKey)
		} else {
			return nil, nil, fmt.Errorf("decryption required but no valid key/passphrase available")
		}
		if err != nil {
			return nil, nil, fmt.Errorf("decryption failed: %w", err)
		}
	} else {
		decrypted = payloadData
	}

	// 4. Decompression
	decompressed, err := Decompress(decrypted, p.cfg.Compression)
	if err != nil {
		return nil, nil, fmt.Errorf("decompression failed: %w", err)
	}

	return decompressed, &header, nil
}

// TransformChain applies the configured transform chain to data.
func (p *Pipeline) TransformChain(data []byte) ([]byte, error) {
	return ApplyTransformChain(data, p.cfg.Transforms, p.cfg.Passphrase, p.cfg.RawKey)
}

// ReverseTransformChain reverses the configured transform chain on data.
func (p *Pipeline) ReverseTransformChain(data []byte) ([]byte, error) {
	return ReverseTransformChain(data, p.cfg.Transforms, p.cfg.Passphrase, p.cfg.RawKey)
}

// ApplyTransformChain transforms payload sequentially according to comma-separated transforms string
// (e.g. "zstd,aes_gcm,base64").
func ApplyTransformChain(data []byte, transforms string, passphrase string, rawKey []byte) ([]byte, error) {
	if transforms == "" || transforms == "raw" || transforms == "none" {
		return data, nil
	}
	steps := strings.Split(transforms, ",")
	cur := data
	for _, rawStep := range steps {
		step := strings.ToLower(strings.TrimSpace(rawStep))
		if step == "" || step == "raw" || step == "none" {
			continue
		}
		var err error
		switch step {
		case "zstd":
			cur, err = CompressBytes(cur, CompressZstd)
		case "gzip":
			cur, err = CompressBytes(cur, CompressGzip)
		case "zlib":
			cur, err = CompressBytes(cur, CompressZlib)
		case "aes", "aes_gcm", "aes-256-gcm", "encrypt":
			if passphrase != "" {
				cur, err = EncryptWithPassphrase(cur, passphrase)
			} else if len(rawKey) == 32 {
				cur, err = EncryptAESGCM(cur, rawKey)
			} else {
				return nil, fmt.Errorf("encryption step %q requires passphrase or 32-byte raw key", step)
			}
		case "base64", "b64":
			cur = []byte(EncodeBase64(cur))
		case "hex":
			cur = []byte(EncodeHex(cur))
		default:
			return nil, fmt.Errorf("unsupported transform: %s", step)
		}
		if err != nil {
			return nil, fmt.Errorf("transform step %q failed: %w", step, err)
		}
	}
	return cur, nil
}

// ReverseTransformChain reverses a comma-separated transform chain in reverse order.
func ReverseTransformChain(data []byte, transforms string, passphrase string, rawKey []byte) ([]byte, error) {
	if transforms == "" || transforms == "raw" || transforms == "none" {
		return data, nil
	}
	steps := strings.Split(transforms, ",")
	cur := data
	for i := len(steps) - 1; i >= 0; i-- {
		step := strings.ToLower(strings.TrimSpace(steps[i]))
		if step == "" || step == "raw" || step == "none" {
			continue
		}
		var err error
		switch step {
		case "base64", "b64":
			cur, err = DecodeBase64(string(cur))
		case "hex":
			cur, err = DecodeHex(string(cur))
		case "aes", "aes_gcm", "aes-256-gcm", "encrypt":
			if passphrase != "" {
				cur, err = DecryptWithPassphrase(cur, passphrase)
			} else if len(rawKey) == 32 {
				cur, err = DecryptAESGCM(cur, rawKey)
			} else {
				return nil, fmt.Errorf("decryption step %q requires passphrase or 32-byte raw key", step)
			}
		case "zstd":
			cur, err = DecompressBytes(cur, CompressZstd)
		case "gzip":
			cur, err = DecompressBytes(cur, CompressGzip)
		case "zlib":
			cur, err = DecompressBytes(cur, CompressZlib)
		default:
			return nil, fmt.Errorf("unsupported reverse transform: %s", step)
		}
		if err != nil {
			return nil, fmt.Errorf("reverse transform step %q failed: %w", step, err)
		}
	}
	return cur, nil
}
