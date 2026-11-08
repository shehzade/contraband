package evasion

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

func Compress(data []byte, method CompressionMethod, level int) ([]byte, error) {
	switch method {
	case CompressNone, "":
		return data, nil
	case CompressZlib:
		var buf bytes.Buffer
		if level < zlib.DefaultCompression || level > zlib.BestCompression {
			level = zlib.DefaultCompression
		}
		w, err := zlib.NewWriterLevel(&buf, level)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case CompressGzip:
		var buf bytes.Buffer
		if level < gzip.DefaultCompression || level > gzip.BestCompression {
			level = gzip.DefaultCompression
		}
		w, err := gzip.NewWriterLevel(&buf, level)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case CompressZstd:
		var buf bytes.Buffer
		enc, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		if _, err := enc.Write(data); err != nil {
			_ = enc.Close()
			return nil, err
		}
		if err := enc.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported compression method: %s", method)
	}
}

func Decompress(data []byte, method CompressionMethod) ([]byte, error) {
	switch method {
	case CompressNone, "":
		return data, nil
	case CompressZlib:
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case CompressGzip:
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case CompressZstd:
		dec, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer dec.Close()
		return io.ReadAll(dec)
	default:
		return nil, fmt.Errorf("unsupported decompression method: %s", method)
	}
}

// CompressBytes compresses data using the specified compression method.
func CompressBytes(data []byte, method CompressionMethod) ([]byte, error) {
	return Compress(data, method, 0)
}

// DecompressBytes decompresses data using the specified compression method.
func DecompressBytes(data []byte, method CompressionMethod) ([]byte, error) {
	return Decompress(data, method)
}
