package evasion

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
)

// GenerateProceduralBMP synthesizes a valid 24-bit uncompressed BMP image.
func GenerateProceduralBMP(width, height int, seed int64) []byte {
	rowSize := ((width*3 + 3) / 4) * 4
	imageSize := rowSize * height
	fileSize := 14 + 40 + imageSize

	buf := make([]byte, fileSize)

	// BITMAPFILEHEADER (14 bytes)
	buf[0] = 'B'
	buf[1] = 'M'
	binary.LittleEndian.PutUint32(buf[2:6], uint32(fileSize))
	binary.LittleEndian.PutUint32(buf[10:14], 54) // offset to pixel data

	// BITMAPINFOHEADER (40 bytes)
	binary.LittleEndian.PutUint32(buf[14:18], 40)
	binary.LittleEndian.PutUint32(buf[18:22], uint32(width))
	binary.LittleEndian.PutUint32(buf[22:26], uint32(height))
	binary.LittleEndian.PutUint16(buf[26:28], 1)  // planes
	binary.LittleEndian.PutUint16(buf[28:30], 24) // 24-bit BGR
	binary.LittleEndian.PutUint32(buf[30:34], 0)  // BI_RGB uncompressed
	binary.LittleEndian.PutUint32(buf[34:38], uint32(imageSize))
	binary.LittleEndian.PutUint32(buf[38:42], 2835)
	binary.LittleEndian.PutUint32(buf[42:46], 2835)

	// Fill pixel array with smooth deterministic procedural color gradient
	rng := rand.New(rand.NewSource(seed))
	baseR := uint8(rng.Intn(100) + 50)
	baseG := uint8(rng.Intn(100) + 50)
	baseB := uint8(rng.Intn(100) + 50)

	pixelStart := 54
	for y := 0; y < height; y++ {
		rowOffset := pixelStart + y*rowSize
		for x := 0; x < width; x++ {
			idx := rowOffset + x*3
			buf[idx] = uint8((int(baseB) + x*255/width) % 256)       // Blue
			buf[idx+1] = uint8((int(baseG) + y*255/height) % 256)    // Green
			buf[idx+2] = uint8((int(baseR) + (x+y)*128/width) % 256) // Red
		}
		// Row padding is already 0x00
	}

	return buf
}

// EmbedBMP embeds payload into 24-bit BMP pixels using 1-bit LSB steganography.
func EmbedBMP(bmpData []byte, payload []byte) ([]byte, error) {
	if len(bmpData) < 54 || bmpData[0] != 'B' || bmpData[1] != 'M' {
		return nil, errors.New("invalid BMP header")
	}

	width := int(binary.LittleEndian.Uint32(bmpData[18:22]))
	height := int(binary.LittleEndian.Uint32(bmpData[22:26]))
	bitCount := binary.LittleEndian.Uint16(bmpData[28:30])
	compression := binary.LittleEndian.Uint32(bmpData[30:34])

	if bitCount != 24 || compression != 0 {
		return nil, fmt.Errorf("unsupported BMP format: bitCount=%d, compression=%d (requires 24-bit uncompressed)", bitCount, compression)
	}

	usablePixels := width * height * 3
	maxCapacity := (usablePixels / 8) - 4 // minus 4 bytes for length header
	if len(payload) > maxCapacity {
		return nil, fmt.Errorf("payload size (%d bytes) exceeds BMP capacity (%d bytes)", len(payload), maxCapacity)
	}

	// Prepare framed payload: [Length uint32 (4B)][Payload]
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed[0:4], uint32(len(payload)))
	copy(framed[4:], payload)

	out := make([]byte, len(bmpData))
	copy(out, bmpData)

	rowSize := ((width*3 + 3) / 4) * 4
	pixelStart := int(binary.LittleEndian.Uint32(bmpData[10:14]))

	bitTotal := len(framed) * 8
	bitIdx := 0

outer:
	for y := 0; y < height; y++ {
		rowOffset := pixelStart + y*rowSize
		for x := 0; x < width*3; x++ {
			if bitIdx >= bitTotal {
				break outer
			}
			byteVal := framed[bitIdx/8]
			bit := (byteVal >> (7 - (bitIdx % 8))) & 0x01

			targetByte := out[rowOffset+x]
			out[rowOffset+x] = (targetByte & 0xFE) | bit
			bitIdx++
		}
	}

	return out, nil
}

// ExtractBMP extracts payload embedded via EmbedBMP.
func ExtractBMP(bmpData []byte) ([]byte, error) {
	if len(bmpData) < 54 || bmpData[0] != 'B' || bmpData[1] != 'M' {
		return nil, errors.New("invalid BMP header")
	}

	width := int(binary.LittleEndian.Uint32(bmpData[18:22]))
	height := int(binary.LittleEndian.Uint32(bmpData[22:26]))
	rowSize := ((width*3 + 3) / 4) * 4
	pixelStart := int(binary.LittleEndian.Uint32(bmpData[10:14]))

	// First extract 32 bits (4 bytes) to read length header
	lengthBits := 32
	var lengthBuf [4]byte
	bitIdx := 0

	for y := 0; y < height && bitIdx < lengthBits; y++ {
		rowOffset := pixelStart + y*rowSize
		for x := 0; x < width*3 && bitIdx < lengthBits; x++ {
			bit := bmpData[rowOffset+x] & 0x01
			lengthBuf[bitIdx/8] |= (bit << (7 - (bitIdx % 8)))
			bitIdx++
		}
	}

	payloadLen := int(binary.BigEndian.Uint32(lengthBuf[:]))
	usablePixels := width * height * 3
	maxCapacity := (usablePixels / 8) - 4
	if payloadLen <= 0 || payloadLen > maxCapacity {
		return nil, fmt.Errorf("invalid extracted payload length %d (capacity: %d)", payloadLen, maxCapacity)
	}

	// Extract payload bits
	totalBits := (4 + payloadLen) * 8
	payload := make([]byte, payloadLen)

outerExtract:
	for y := 0; y < height; y++ {
		rowOffset := pixelStart + y*rowSize
		for x := 0; x < width*3; x++ {
			currBit := y*(width*3) + x
			if currBit < 32 {
				continue
			}
			if currBit >= totalBits {
				break outerExtract
			}
			bit := bmpData[rowOffset+x] & 0x01
			targetBit := currBit - 32
			payload[targetBit/8] |= (bit << (7 - (targetBit % 8)))
		}
	}

	return payload, nil
}
