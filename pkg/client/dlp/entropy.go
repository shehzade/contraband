package dlp

import (
	"math"
	"math/rand"
)

// CalculateShannonEntropy calculates Shannon entropy in bits per byte with 0 heap allocations.
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]uint32
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

type EntropyTuner struct {
	MinEntropy float64
	MaxEntropy float64
}

func NewEntropyTuner(min, max float64) *EntropyTuner {
	if min <= 0 {
		min = 3.5
	}
	if max <= 0 {
		max = 5.5
	}
	return &EntropyTuner{
		MinEntropy: min,
		MaxEntropy: max,
	}
}

var ProseReservoir = []string{
	"The system architecture employs microservices communicating through secure channels. Enterprise egress testing requires rigorous verification of transport layer filters and proxy inspection policies.",
	"Information security management systems mandate comprehensive data loss prevention controls across all corporate network boundaries and endpoints.",
	"Network perimeter defenses inspect outbound application layer traffic for unauthorized cryptographic encapsulation and unexpected protocol tunneling.",
	"Audit logging standards require microsecond timestamp synchronization across distributed logging servers and forensic collectors.",
	"Compliance guidelines mandate annual assessment of data encryption in transit and confidential record handling procedures.",
}

var HighEntropyReservoir = []string{
	"7f8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a",
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"MIIEowIBAAKCAQEA0rK1Z5mNq7Y/9K1tHj0kXfQzL0u8vV2W4y5b9a8c7d6e5f4a",
	"3f5b7d9a1c2e4f6a8b0c2d4e6f8a0b1c3d5e7f9a1b2c3d4e5f6a7b8c9d0e1f2a",
	"c0e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8",
}

// Modulate adjusts the byte slice so its Shannon entropy lies within [MinEntropy, MaxEntropy].
func (t *EntropyTuner) Modulate(data []byte, r *rand.Rand) []byte {
	current := CalculateShannonEntropy(data)
	if current >= t.MinEntropy && current <= t.MaxEntropy {
		return data
	}

	result := append([]byte(nil), data...)
	maxIterations := 40

	for i := 0; i < maxIterations; i++ {
		if current >= t.MinEntropy && current <= t.MaxEntropy {
			break
		}

		vol := len(result)
		if vol < 150 {
			vol = 150
		}

		if current < t.MinEntropy {
			// Inject high entropy tokens scaled to volume
			for added := 0; added < vol; {
				token := HighEntropyReservoir[r.Intn(len(HighEntropyReservoir))]
				result = append(result, '\n')
				result = append(result, token...)
				added += len(token) + 1
			}
		} else if current > t.MaxEntropy {
			// Inject low entropy prose or filler scaled to volume
			if t.MaxEntropy < 4.16 {
				pad := "                                                                                \n"
				for added := 0; added < vol; {
					result = append(result, pad...)
					added += len(pad)
				}
			} else {
				for added := 0; added < vol; {
					prose := ProseReservoir[r.Intn(len(ProseReservoir))]
					result = append(result, '\n')
					result = append(result, prose...)
					added += len(prose) + 1
				}
			}
		}
		current = CalculateShannonEntropy(result)
	}
	return result
}
