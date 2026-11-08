package evasion

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
)

// GenerateProceduralWAV generates a valid 16-bit stereo PCM WAV audio file with realistic tone + noise.
func GenerateProceduralWAV(durationSeconds int, sampleRate int, seed int64) []byte {
	if sampleRate <= 0 {
		sampleRate = 44100
	}
	if durationSeconds <= 0 {
		durationSeconds = 2
	}

	numChannels := 2
	bitsPerSample := 16
	bytesPerSample := bitsPerSample / 8
	blockAlign := numChannels * bytesPerSample
	byteRate := sampleRate * blockAlign
	totalSamples := durationSeconds * sampleRate
	dataSize := totalSamples * blockAlign
	fileSize := 36 + dataSize

	buf := make([]byte, 44+dataSize)

	// RIFF header
	copy(buf[0:4], "RIFF")
	binary.LittleEndian.PutUint32(buf[4:8], uint32(fileSize))
	copy(buf[8:12], "WAVE")

	// fmt subchunk
	copy(buf[12:16], "fmt ")
	binary.LittleEndian.PutUint32(buf[16:20], 16) // PCM format size
	binary.LittleEndian.PutUint16(buf[20:22], 1)  // audio format 1 = PCM
	binary.LittleEndian.PutUint16(buf[22:24], uint16(numChannels))
	binary.LittleEndian.PutUint32(buf[24:28], uint32(sampleRate))
	binary.LittleEndian.PutUint32(buf[28:32], uint32(byteRate))
	binary.LittleEndian.PutUint16(buf[32:34], uint16(blockAlign))
	binary.LittleEndian.PutUint16(buf[34:36], uint16(bitsPerSample))

	// data subchunk
	copy(buf[36:40], "data")
	binary.LittleEndian.PutUint32(buf[40:44], uint32(dataSize))

	// Synthesize gentle ambient harmonic tone (e.g. 440 Hz + 880 Hz) with dither
	rng := rand.New(rand.NewSource(seed))
	freq1 := 440.0
	freq2 := 880.0

	for i := 0; i < totalSamples; i++ {
		t := float64(i) / float64(sampleRate)
		v1 := math.Sin(2.0*math.Pi*freq1*t) * 6000.0
		v2 := math.Sin(2.0*math.Pi*freq2*t) * 2000.0
		noise := (rng.Float64() - 0.5) * 200.0
		sampleVal := int16(v1 + v2 + noise)

		// Left channel
		offset := 44 + i*blockAlign
		binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(sampleVal))
		// Right channel (slight stereo pan)
		binary.LittleEndian.PutUint16(buf[offset+2:offset+4], uint16(sampleVal+int16(noise)))
	}

	return buf
}

// EmbedWAV embeds payload into 16-bit PCM WAV samples using 1-bit LSB.
func EmbedWAV(wavData []byte, payload []byte) ([]byte, error) {
	if len(wavData) < 44 || string(wavData[0:4]) != "RIFF" || string(wavData[8:12]) != "WAVE" {
		return nil, errors.New("invalid WAV file header")
	}

	// Find data chunk
	offset := 12
	dataOffset := -1
	dataSize := 0
	for offset+8 <= len(wavData) {
		subID := string(wavData[offset : offset+4])
		subSize := int(binary.LittleEndian.Uint32(wavData[offset+4 : offset+8]))
		if subID == "data" {
			dataOffset = offset + 8
			dataSize = subSize
			break
		}
		offset += 8 + subSize
	}

	if dataOffset == -1 || dataOffset+dataSize > len(wavData) {
		return nil, errors.New("data subchunk not found in WAV")
	}

	total16BitSamples := dataSize / 2
	maxCapacity := (total16BitSamples / 8) - 4
	if len(payload) > maxCapacity {
		return nil, fmt.Errorf("payload size (%d bytes) exceeds WAV capacity (%d bytes)", len(payload), maxCapacity)
	}

	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed[0:4], uint32(len(payload)))
	copy(framed[4:], payload)

	out := make([]byte, len(wavData))
	copy(out, wavData)

	totalBits := len(framed) * 8
	for bitIdx := 0; bitIdx < totalBits; bitIdx++ {
		sampleByteOffset := dataOffset + bitIdx*2
		sample := int16(binary.LittleEndian.Uint16(out[sampleByteOffset : sampleByteOffset+2]))

		payloadBit := (framed[bitIdx/8] >> (7 - (bitIdx % 8))) & 0x01
		sample = (sample &^ 1) | int16(payloadBit)
		binary.LittleEndian.PutUint16(out[sampleByteOffset:sampleByteOffset+2], uint16(sample))
	}

	return out, nil
}

// ExtractWAV extracts payload embedded via EmbedWAV.
func ExtractWAV(wavData []byte) ([]byte, error) {
	if len(wavData) < 44 || string(wavData[0:4]) != "RIFF" || string(wavData[8:12]) != "WAVE" {
		return nil, errors.New("invalid WAV file header")
	}

	offset := 12
	dataOffset := -1
	dataSize := 0
	for offset+8 <= len(wavData) {
		subID := string(wavData[offset : offset+4])
		subSize := int(binary.LittleEndian.Uint32(wavData[offset+4 : offset+8]))
		if subID == "data" {
			dataOffset = offset + 8
			dataSize = subSize
			break
		}
		offset += 8 + subSize
	}

	if dataOffset == -1 {
		return nil, errors.New("data subchunk not found in WAV")
	}

	// Extract 32 bits (4 bytes) length header
	var lengthBuf [4]byte
	for bitIdx := 0; bitIdx < 32; bitIdx++ {
		sampleByteOffset := dataOffset + bitIdx*2
		sample := binary.LittleEndian.Uint16(wavData[sampleByteOffset : sampleByteOffset+2])
		bit := sample & 0x01
		lengthBuf[bitIdx/8] |= byte(bit << (7 - (bitIdx % 8)))
	}

	payloadLen := int(binary.BigEndian.Uint32(lengthBuf[:]))
	total16BitSamples := dataSize / 2
	maxCapacity := (total16BitSamples / 8) - 4
	if payloadLen <= 0 || payloadLen > maxCapacity {
		return nil, fmt.Errorf("invalid extracted WAV payload length %d (capacity: %d)", payloadLen, maxCapacity)
	}

	payload := make([]byte, payloadLen)
	totalBits := (4 + payloadLen) * 8
	for currBit := 32; currBit < totalBits; currBit++ {
		sampleByteOffset := dataOffset + currBit*2
		sample := binary.LittleEndian.Uint16(wavData[sampleByteOffset : sampleByteOffset+2])
		bit := sample & 0x01
		targetBit := currBit - 32
		payload[targetBit/8] |= byte(bit << (7 - (targetBit % 8)))
	}

	return payload, nil
}
