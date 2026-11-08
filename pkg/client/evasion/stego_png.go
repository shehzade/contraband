package evasion

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/rand"
)

var (
	PNGSignature  = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	ChunkTypeCtRB = []byte("ctRB")
)

// GenerateProceduralPNG creates a dynamic, procedural RGBA PNG image with unique entropy.
func GenerateProceduralPNG(width, height int, seed int64) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	rng := rand.New(rand.NewSource(seed))

	baseR := uint8(rng.Intn(128) + 64)
	baseG := uint8(rng.Intn(128) + 64)
	baseB := uint8(rng.Intn(128) + 64)

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			c := color.RGBA{
				R: uint8((int(baseR) + x*128/width) % 256),
				G: uint8((int(baseG) + y*128/height) % 256),
				B: uint8((int(baseB) + (x+y)*64/width) % 256),
				A: 255,
			}
			img.SetRGBA(x, y, c)
		}
	}

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.DefaultCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EmbedPNGAncillary embeds payload into an ancillary ctRB PNG chunk.
func EmbedPNGAncillary(pngData []byte, payload []byte) ([]byte, error) {
	if len(pngData) < 8 || !bytes.Equal(pngData[:8], PNGSignature) {
		return nil, errors.New("invalid PNG signature")
	}

	// Build ctRB chunk: [Length 4B][Type 4B][Data][CRC 4B]
	chunkLen := uint32(len(payload))
	crcPayload := append(ChunkTypeCtRB, payload...)
	crcVal := crc32.ChecksumIEEE(crcPayload)

	var chunk bytes.Buffer
	binary.Write(&chunk, binary.BigEndian, chunkLen)
	chunk.Write(ChunkTypeCtRB)
	chunk.Write(payload)
	binary.Write(&chunk, binary.BigEndian, crcVal)

	// Insert chunk right after IHDR chunk
	offset := 8
	ihdrEnd := -1
	for offset < len(pngData) {
		length := binary.BigEndian.Uint32(pngData[offset : offset+4])
		chunkType := string(pngData[offset+4 : offset+8])
		nextOffset := offset + 8 + int(length) + 4
		if chunkType == "IHDR" {
			ihdrEnd = nextOffset
			break
		}
		offset = nextOffset
	}

	if ihdrEnd == -1 || ihdrEnd > len(pngData) {
		return nil, errors.New("could not locate IHDR chunk in PNG")
	}

	var out bytes.Buffer
	out.Write(pngData[:ihdrEnd])
	out.Write(chunk.Bytes())
	out.Write(pngData[ihdrEnd:])
	return out.Bytes(), nil
}

// ExtractPNGAncillary extracts payload from ctRB ancillary chunk.
func ExtractPNGAncillary(pngData []byte) ([]byte, error) {
	if len(pngData) < 8 || !bytes.Equal(pngData[:8], PNGSignature) {
		return nil, errors.New("invalid PNG signature")
	}

	offset := 8
	for offset+8 <= len(pngData) {
		length := binary.BigEndian.Uint32(pngData[offset : offset+4])
		chunkType := pngData[offset+4 : offset+8]
		dataStart := offset + 8
		dataEnd := dataStart + int(length)
		crcEnd := dataEnd + 4

		if crcEnd > len(pngData) {
			return nil, errors.New("malformed PNG: chunk extends beyond file length")
		}

		if bytes.Equal(chunkType, ChunkTypeCtRB) {
			payload := pngData[dataStart:dataEnd]
			crcVal := binary.BigEndian.Uint32(pngData[dataEnd:crcEnd])
			computedCRC := crc32.ChecksumIEEE(pngData[offset+4 : dataEnd])
			if crcVal != computedCRC {
				return nil, errors.New("CRC mismatch in ctRB chunk")
			}
			return payload, nil
		}
		offset = crcEnd
	}

	return nil, errors.New("no ctRB ancillary chunk found in PNG")
}

// EmbedPNGLSB embeds payload into RGB pixel LSBs of a PNG.
func EmbedPNGLSB(pngData []byte, payload []byte) ([]byte, error) {
	srcImg, err := png.Decode(bytes.NewReader(pngData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PNG: %w", err)
	}

	bounds := srcImg.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	rgba := image.NewRGBA(bounds)
	draw.Draw(rgba, bounds, srcImg, bounds.Min, draw.Src)

	usableChannels := width * height * 3 // R, G, B
	maxCapacity := (usableChannels / 8) - 4
	if len(payload) > maxCapacity {
		return nil, fmt.Errorf("payload (%d bytes) exceeds PNG LSB capacity (%d bytes)", len(payload), maxCapacity)
	}

	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed[0:4], uint32(len(payload)))
	copy(framed[4:], payload)

	totalBits := len(framed) * 8
	bitIdx := 0

outerPixel:
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			c := rgba.RGBAAt(x, y)

			// Red channel
			if bitIdx < totalBits {
				bit := (framed[bitIdx/8] >> (7 - (bitIdx % 8))) & 0x01
				c.R = (c.R & 0xFE) | bit
				bitIdx++
			}
			// Green channel
			if bitIdx < totalBits {
				bit := (framed[bitIdx/8] >> (7 - (bitIdx % 8))) & 0x01
				c.G = (c.G & 0xFE) | bit
				bitIdx++
			}
			// Blue channel
			if bitIdx < totalBits {
				bit := (framed[bitIdx/8] >> (7 - (bitIdx % 8))) & 0x01
				c.B = (c.B & 0xFE) | bit
				bitIdx++
			}

			rgba.SetRGBA(x, y, c)
			if bitIdx >= totalBits {
				break outerPixel
			}
		}
	}

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.DefaultCompression}
	if err := enc.Encode(&buf, rgba); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExtractPNGLSB extracts payload embedded via EmbedPNGLSB.
func ExtractPNGLSB(pngData []byte) ([]byte, error) {
	srcImg, err := png.Decode(bytes.NewReader(pngData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PNG: %w", err)
	}

	bounds := srcImg.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	rgba, ok := srcImg.(*image.RGBA)
	if !ok {
		rgba = image.NewRGBA(bounds)
		draw.Draw(rgba, bounds, srcImg, bounds.Min, draw.Src)
	}

	// Extract first 32 bits (4 bytes) to read length header
	var lengthBuf [4]byte
	bitIdx := 0

	for y := 0; y < height && bitIdx < 32; y++ {
		for x := 0; x < width && bitIdx < 32; x++ {
			c := rgba.RGBAAt(x, y)
			for _, channelVal := range []uint8{c.R, c.G, c.B} {
				if bitIdx >= 32 {
					break
				}
				bit := channelVal & 0x01
				lengthBuf[bitIdx/8] |= (bit << (7 - (bitIdx % 8)))
				bitIdx++
			}
		}
	}

	payloadLen := int(binary.BigEndian.Uint32(lengthBuf[:]))
	usableChannels := width * height * 3
	maxCapacity := (usableChannels / 8) - 4
	if payloadLen <= 0 || payloadLen > maxCapacity {
		return nil, fmt.Errorf("invalid extracted PNG LSB payload length %d (capacity: %d)", payloadLen, maxCapacity)
	}

	payload := make([]byte, payloadLen)
	totalBits := (4 + payloadLen) * 8
	currBit := 0

outerExtract:
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			c := rgba.RGBAAt(x, y)
			for _, channelVal := range []uint8{c.R, c.G, c.B} {
				if currBit < 32 {
					currBit++
					continue
				}
				if currBit >= totalBits {
					break outerExtract
				}
				bit := channelVal & 0x01
				targetBit := currBit - 32
				payload[targetBit/8] |= (bit << (7 - (targetBit % 8)))
				currBit++
			}
		}
	}

	return payload, nil
}
