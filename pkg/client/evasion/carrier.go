package evasion

import (
	"fmt"
	"math"
)

// EmbedCarrier embeds a framed chunk into the designated carrier medium.
func EmbedCarrier(chunk []byte, carrier CarrierType, seed int64) ([]byte, error) {
	switch carrier {
	case CarrierNone, "":
		return chunk, nil

	case CarrierBMP:
		neededPixels := ((len(chunk)+16)*8)/3 + 100
		dim := int(math.Sqrt(float64(neededPixels))) + 1
		if dim < 64 {
			dim = 64
		}
		bmpData := GenerateProceduralBMP(dim, dim, seed)
		return EmbedBMP(bmpData, chunk)

	case CarrierPNG:
		pngData, err := GenerateProceduralPNG(128, 128, seed)
		if err != nil {
			return nil, fmt.Errorf("failed to generate procedural PNG: %w", err)
		}
		return EmbedPNGAncillary(pngData, chunk)

	case CarrierWAV:
		sampleRate := 44100
		neededSamples := (len(chunk) + 16) * 8
		durationSec := (neededSamples / (sampleRate * 2)) + 2
		if durationSec < 2 {
			durationSec = 2
		}
		wavData := GenerateProceduralWAV(durationSec, sampleRate, seed)
		return EmbedWAV(wavData, chunk)

	case CarrierJPEGZIP:
		jpegData, err := GenerateProceduralJPEG(128, 128, seed)
		if err != nil {
			return nil, fmt.Errorf("failed to generate procedural JPEG: %w", err)
		}
		return BuildJPEGZIPPolyglot(jpegData, chunk, "contraband_data.bin")

	case CarrierPDFJAR:
		pdfData := GenerateProceduralPDF("Contraband Assessment Report", seed)
		return BuildPDFJARPolyglot(pdfData, chunk, "contraband_data.bin")

	default:
		return nil, fmt.Errorf("unsupported carrier type: %s", carrier)
	}
}

// ExtractCarrier extracts the chunk bytes from the designated carrier medium.
func ExtractCarrier(carrierData []byte, carrier CarrierType) ([]byte, error) {
	switch carrier {
	case CarrierNone, "":
		return carrierData, nil

	case CarrierBMP:
		return ExtractBMP(carrierData)

	case CarrierPNG:
		return ExtractPNGAncillary(carrierData)

	case CarrierWAV:
		return ExtractWAV(carrierData)

	case CarrierJPEGZIP:
		return ExtractJPEGZIP(carrierData, "contraband_data.bin")

	case CarrierPDFJAR:
		return ExtractPDFJAR(carrierData, "contraband_data.bin")

	default:
		return nil, fmt.Errorf("unsupported carrier type: %s", carrier)
	}
}
