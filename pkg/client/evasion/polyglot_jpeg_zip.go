package evasion

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"math/rand"
)

// GenerateProceduralJPEG creates a valid, clean-rendering JPEG image with procedural gradient.
func GenerateProceduralJPEG(width, height int, seed int64) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	rng := rand.New(rand.NewSource(seed))

	baseR := uint8(rng.Intn(120) + 40)
	baseG := uint8(rng.Intn(120) + 40)
	baseB := uint8(rng.Intn(120) + 40)

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			c := color.RGBA{
				R: uint8((int(baseR) + x*200/width) % 256),
				G: uint8((int(baseG) + y*200/height) % 256),
				B: uint8((int(baseB) + (x*y)*100/(width*height)) % 256),
				A: 255,
			}
			img.SetRGBA(x, y, c)
		}
	}

	var buf bytes.Buffer
	opt := &jpeg.Options{Quality: 85}
	if err := jpeg.Encode(&buf, img, opt); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BuildJPEGZIPPolyglot combines a valid JPEG with an offset-adjusted ZIP archive.
func BuildJPEGZIPPolyglot(jpegBytes []byte, payload []byte, payloadFilename string) ([]byte, error) {
	if len(jpegBytes) < 4 || jpegBytes[0] != 0xFF || jpegBytes[1] != 0xD8 {
		return nil, errors.New("invalid JPEG data (missing SOI)")
	}

	// Verify JPEG ends with EOI \xFF\xD9
	if jpegBytes[len(jpegBytes)-2] != 0xFF || jpegBytes[len(jpegBytes)-1] != 0xD9 {
		return nil, errors.New("invalid JPEG data (missing EOI)")
	}

	if payloadFilename == "" {
		payloadFilename = "contraband_data.bin"
	}

	// 1. Build standard ZIP archive in memory
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)

	// Add procedural decoy file
	decoyW, err := zw.Create("document_metadata.xml")
	if err != nil {
		return nil, err
	}
	if _, err := decoyW.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?><metadata><status>verified</status></metadata>")); err != nil {
		return nil, err
	}

	// Add payload file
	payloadW, err := zw.Create(payloadFilename)
	if err != nil {
		return nil, err
	}
	if _, err := payloadW.Write(payload); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	rawZIP := zipBuf.Bytes()
	jpegLen := uint32(len(jpegBytes))

	// 2. Adjust Central Directory offsets for prefix length N
	adjustedZIP, err := adjustZIPOffsets(rawZIP, jpegLen)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust ZIP offsets: %w", err)
	}

	// 3. Concatenate JPEG + Adjusted ZIP
	var polyglot bytes.Buffer
	polyglot.Write(jpegBytes)
	polyglot.Write(adjustedZIP)

	return polyglot.Bytes(), nil
}

func adjustZIPOffsets(zipData []byte, prefixLen uint32) ([]byte, error) {
	out := make([]byte, len(zipData))
	copy(out, zipData)

	// Locate EOCD signature 0x06054b50 ("PK\x05\x06") from the end
	eocdSig := []byte{0x50, 0x4B, 0x05, 0x06}
	eocdOffset := bytes.LastIndex(out, eocdSig)
	if eocdOffset == -1 || eocdOffset+22 > len(out) {
		return nil, errors.New("cannot locate ZIP EOCD record")
	}

	cdSize := binary.LittleEndian.Uint32(out[eocdOffset+12 : eocdOffset+16])
	cdOffset := binary.LittleEndian.Uint32(out[eocdOffset+16 : eocdOffset+20])

	// Walk through Central Directory entries: signature 0x02014b50 ("PK\x01\x02")
	cdSig := []byte{0x50, 0x4B, 0x01, 0x02}
	curr := int(cdOffset)
	cdEnd := curr + int(cdSize)

	for curr < cdEnd && curr+46 <= len(out) {
		if !bytes.Equal(out[curr:curr+4], cdSig) {
			break
		}
		fnLen := binary.LittleEndian.Uint16(out[curr+28 : curr+30])
		extraLen := binary.LittleEndian.Uint16(out[curr+30 : curr+32])
		commentLen := binary.LittleEndian.Uint16(out[curr+32 : curr+34])

		localOffset := binary.LittleEndian.Uint32(out[curr+42 : curr+46])
		binary.LittleEndian.PutUint32(out[curr+42:curr+46], localOffset+prefixLen)

		curr += 46 + int(fnLen) + int(extraLen) + int(commentLen)
	}

	// Update EOCD start of CD offset
	binary.LittleEndian.PutUint32(out[eocdOffset+16:eocdOffset+20], cdOffset+prefixLen)

	return out, nil
}

// ExtractJPEGZIP extracts payload from a JPEG+ZIP polyglot.
func ExtractJPEGZIP(polyglotBytes []byte, payloadFilename string) ([]byte, error) {
	if payloadFilename == "" {
		payloadFilename = "contraband_data.bin"
	}

	reader, err := zip.NewReader(bytes.NewReader(polyglotBytes), int64(len(polyglotBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to open ZIP reader on polyglot: %w", err)
	}

	for _, file := range reader.File {
		if file.Name == payloadFilename {
			rc, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("file %q not found in polyglot ZIP archive", payloadFilename)
}
