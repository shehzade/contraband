package common

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SanitizeProtocolName cleans an untrusted protocol string ensuring it only contains
// safe alphanumeric characters, dashes, and underscores, preventing path traversal attacks.
func SanitizeProtocolName(proto string) string {
	cleaned := filepath.Base(filepath.Clean(proto))
	var b strings.Builder
	for _, r := range cleaned {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	res := b.String()
	if res == "" || res == "." {
		return "unknown"
	}
	return res
}

// DumpWithOffset formats data into canonical hex/ASCII dump format matching hexdump -C,
// using baseOffset as the starting offset printed in the leftmost column.
func DumpWithOffset(data []byte, baseOffset int) string {
	if len(data) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		chunk := data[i:]
		if len(chunk) > 16 {
			chunk = chunk[:16]
		}
		// 8-digit hexadecimal offset + 2 spaces
		b.WriteString(fmt.Sprintf("%08x  ", baseOffset+i))

		// 16 hex byte fields with space separator; extra space between byte 7 and 8
		for j := 0; j < 16; j++ {
			if j == 8 {
				b.WriteByte(' ')
			}
			if j < len(chunk) {
				b.WriteString(fmt.Sprintf("%02x ", chunk[j]))
			} else {
				b.WriteString("   ")
			}
		}

		// ASCII representation enclosed in pipe delimiters
		b.WriteString(" |")
		for _, c := range chunk {
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return b.String()
}

// FormatBoundedRawEvidence generates a bounded forensic hex/ASCII preview
// (first 512 bytes header and last 256 bytes footer) for ProbeResult.RawEvidence
// for evidence retention.
//
// Behavior:
//  1. If len(data) == 0, returns an empty string.
//  2. If len(data) <= 768 (512 header + 256 footer), formats the entire payload
//     using standard canonical hex/ASCII dump format (matching hexdump -C).
//  3. If len(data) > 768, formats the first 512 bytes header, followed by a
//     separator line "\n... [snip %d bytes] ...\n\n", followed by the last 256 bytes
//     footer formatted with its true byte offset (len(data) - 256).
func FormatBoundedRawEvidence(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	const (
		headerLimit = 512
		footerLimit = 256
		threshold   = headerLimit + footerLimit // 768
	)

	if len(data) <= threshold {
		return DumpWithOffset(data, 0)
	}

	header := data[:headerLimit]
	footer := data[len(data)-footerLimit:]
	snipBytes := len(data) - threshold

	var b strings.Builder
	b.WriteString(DumpWithOffset(header, 0))
	b.WriteString(fmt.Sprintf("\n... [snip %d bytes] ...\n\n", snipBytes))
	b.WriteString(DumpWithOffset(footer, len(data)-footerLimit))
	return b.String()
}

// FormatBoundedRawEvidenceStream generates a bounded forensic hex/ASCII preview
// from streaming head (up to 512B) and tail (up to 256B) buffers along with totalBytes.
// This allows streaming exfiltrators to produce byte-identical evidence
// previews without buffering large (50MB - 1GB+) payloads in memory.
func FormatBoundedRawEvidenceStream(head []byte, tail []byte, totalBytes int64) string {
	if totalBytes <= 0 {
		return ""
	}
	const (
		headerLimit = 512
		footerLimit = 256
		threshold   = headerLimit + footerLimit // 768
	)

	if totalBytes <= threshold {
		if int64(len(head)) > totalBytes {
			head = head[:totalBytes]
		}
		return DumpWithOffset(head, 0)
	}

	if len(head) > headerLimit {
		head = head[:headerLimit]
	}
	if len(tail) > footerLimit {
		tail = tail[len(tail)-footerLimit:]
	}
	snipBytes := totalBytes - threshold

	var b strings.Builder
	b.WriteString(DumpWithOffset(head, 0))
	b.WriteString(fmt.Sprintf("\n... [snip %d bytes] ...\n\n", snipBytes))
	b.WriteString(DumpWithOffset(tail, int(totalBytes)-footerLimit))
	return b.String()
}
