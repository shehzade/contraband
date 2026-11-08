package evasion

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// GenerateProceduralPDF generates a minimalist, fully valid %PDF-1.4 single-page invoice document.
func GenerateProceduralPDF(title string, seed int64) []byte {
	if title == "" {
		title = "Contraband Security Audit Invoice"
	}

	var buf bytes.Buffer
	// Minimal valid PDF-1.4 structure
	buf.WriteString("%PDF-1.4\n")
	buf.WriteString("%\xE2\xE3\xCF\xD3\n") // Binary comment

	// Object 1: Catalog
	offObj1 := buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	// Object 2: Pages
	offObj2 := buf.Len()
	buf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	// Object 3: Page
	offObj3 := buf.Len()
	buf.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << >> >>\nendobj\n")

	// Object 4: Content stream
	streamContent := fmt.Sprintf("BT /F1 18 Tf 50 700 Td (%s) Tj ET", title)
	offObj4 := buf.Len()
	buf.WriteString(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(streamContent), streamContent))

	// xref table
	offXref := buf.Len()
	buf.WriteString("xref\n0 5\n")
	buf.WriteString("0000000000 65535 f \n")
	buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offObj1))
	buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offObj2))
	buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offObj3))
	buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offObj4))

	// trailer
	buf.WriteString(fmt.Sprintf("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", offXref))

	return buf.Bytes()
}

// BuildPDFJARPolyglot creates a polyglot file valid as both a PDF document and a JAR/ZIP archive.
func BuildPDFJARPolyglot(pdfBytes []byte, payload []byte, payloadFilename string) ([]byte, error) {
	if len(pdfBytes) < 8 || !bytes.HasPrefix(pdfBytes, []byte("%PDF-")) {
		return nil, errors.New("invalid PDF data (missing %PDF- header)")
	}

	if payloadFilename == "" {
		payloadFilename = "contraband_data.bin"
	}

	// 1. Build valid JAR/ZIP archive in memory
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)

	// Required for valid JAR: META-INF/MANIFEST.MF
	manifestW, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		return nil, err
	}
	if _, err := manifestW.Write([]byte("Manifest-Version: 1.0\r\nCreated-By: Contraband Egress Agent\r\nMain-Class: com.contraband.Agent\r\n\r\n")); err != nil {
		return nil, err
	}

	// Payload file
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
	pdfLen := uint32(len(pdfBytes))

	// 2. Adjust ZIP offsets to account for PDF prefix
	adjustedZIP, err := adjustZIPOffsets(rawZIP, pdfLen)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust ZIP offsets in PDF-JAR polyglot: %w", err)
	}

	// 3. Concatenate PDF + Adjusted JAR/ZIP
	var polyglot bytes.Buffer
	polyglot.Write(pdfBytes)
	polyglot.Write(adjustedZIP)

	return polyglot.Bytes(), nil
}

// ExtractPDFJAR extracts payload from a PDF+JAR polyglot.
func ExtractPDFJAR(polyglotBytes []byte, payloadFilename string) ([]byte, error) {
	if payloadFilename == "" {
		payloadFilename = "contraband_data.bin"
	}

	reader, err := zip.NewReader(bytes.NewReader(polyglotBytes), int64(len(polyglotBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to open JAR/ZIP reader on PDF polyglot: %w", err)
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

	return nil, fmt.Errorf("payload %q not found in PDF-JAR polyglot", payloadFilename)
}
