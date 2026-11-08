package common

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	Byte     int64 = 1
	Kilobyte       = 1024 * Byte
	Megabyte       = 1024 * Kilobyte
	Gigabyte       = 1024 * Megabyte
	Terabyte       = 1024 * Gigabyte
)

// ParseBytes converts human strings like "100KB", "50MB", "2GB", "1.5MB", "512B", "1024" into int64 bytes.
func ParseBytes(s string) (int64, error) {
	// Reject any string containing control characters, newlines, or non-space whitespace
	for _, r := range s {
		if unicode.IsSpace(r) && r != ' ' {
			return 0, fmt.Errorf("invalid byte size string %q: contains invalid whitespace or newline", s)
		}
	}

	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty byte size string")
	}

	// Find boundary between numeric value and unit suffix
	idx := 0
	hasDot := false
	for i, r := range s {
		if unicode.IsDigit(r) {
			idx = i + 1
		} else if r == '.' && !hasDot {
			hasDot = true
			idx = i + 1
		} else {
			break
		}
	}

	if idx == 0 {
		return 0, fmt.Errorf("invalid byte size prefix: %q", s)
	}

	numStr := s[:idx]
	unitStr := strings.ToUpper(strings.Trim(s[idx:], " "))

	var multiplier int64
	switch unitStr {
	case "", "B":
		multiplier = Byte
	case "K", "KB", "KIB":
		multiplier = Kilobyte
	case "M", "MB", "MIB":
		multiplier = Megabyte
	case "G", "GB", "GIB":
		multiplier = Gigabyte
	case "T", "TB", "TIB":
		multiplier = Terabyte
	default:
		return 0, fmt.Errorf("unrecognized byte size unit: %q", unitStr)
	}

	// If numeric part is an integer, perform exact integer arithmetic with overflow check
	if !strings.Contains(numStr, ".") {
		val, err := strconv.ParseUint(numStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("byte size %q exceeds maximum allowable value: %w", s, err)
		}
		if val > uint64(math.MaxInt64)/uint64(multiplier) {
			return 0, fmt.Errorf("byte size %q exceeds maximum allowable value (integer overflow)", s)
		}
		return int64(val * uint64(multiplier)), nil
	}

	// Floating point path for decimal values like "1.5MB"
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse numeric value %q: %w", numStr, err)
	}
	if num < 0 {
		return 0, fmt.Errorf("negative byte size not allowed: %f", num)
	}
	if math.IsNaN(num) || math.IsInf(num, 0) {
		return 0, fmt.Errorf("invalid numeric value %q", numStr)
	}

	f := num * float64(multiplier)
	if math.IsNaN(f) || math.IsInf(f, 0) || f >= float64(math.MaxInt64) {
		return 0, fmt.Errorf("byte size %q exceeds maximum allowable value", s)
	}

	total := int64(f)
	if total < 0 {
		return 0, fmt.Errorf("byte size %q caused integer overflow", s)
	}
	return total, nil
}

// FormatBytes converts raw bytes into a human-readable string (e.g. "50.00 MB", "1.50 GB").
func FormatBytes(b int64) string {
	if b < 0 {
		return fmt.Sprintf("%d B", b)
	}
	switch {
	case b >= Terabyte:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(Terabyte))
	case b >= Gigabyte:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(Gigabyte))
	case b >= Megabyte:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(Megabyte))
	case b >= Kilobyte:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(Kilobyte))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ParseBandwidthRate converts rate strings like "100KB/s", "5MB/sec", "unlimited", "0", "none" into bytes per second.
// Returns 0.0 for unlimited bandwidth.
func ParseBandwidthRate(s string) (float64, error) {
	for _, r := range s {
		if unicode.IsSpace(r) && r != ' ' {
			return 0.0, fmt.Errorf("invalid bandwidth rate %q: contains invalid whitespace or newline", s)
		}
	}

	s = strings.TrimSpace(s)
	lower := strings.ToLower(s)
	if lower == "" || lower == "unlimited" || lower == "0" || lower == "none" || lower == "0/s" {
		return 0.0, nil
	}

	// Strip trailing /s or /sec if present
	clean := s
	if strings.HasSuffix(lower, "/sec") {
		clean = s[:len(s)-4]
	} else if strings.HasSuffix(lower, "/s") {
		clean = s[:len(s)-2]
	}

	bytes, err := ParseBytes(clean)
	if err != nil {
		return 0.0, fmt.Errorf("invalid bandwidth rate %q: %w", s, err)
	}
	if bytes < 0 {
		return 0.0, fmt.Errorf("bandwidth rate cannot be negative: %q", s)
	}

	return float64(bytes), nil
}

// FormatBandwidthRate converts bytes per second into human-readable rate string (e.g. "5.00 MB/s", "unlimited").
func FormatBandwidthRate(bytesPerSec float64) string {
	if bytesPerSec <= 0 || math.IsNaN(bytesPerSec) {
		return "unlimited"
	}
	if math.IsInf(bytesPerSec, 0) || bytesPerSec >= float64(math.MaxInt64) {
		return "unlimited"
	}
	return fmt.Sprintf("%s/s", FormatBytes(int64(bytesPerSec)))
}

// ParseDuration parses strings like "500ms", "1.5s", "10s", "1m".
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration string")
	}
	// If bare integer is provided, treat as seconds
	if val, err := strconv.Atoi(s); err == nil {
		return time.Duration(val) * time.Second, nil
	}
	return time.ParseDuration(s)
}
