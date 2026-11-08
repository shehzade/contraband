package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/shehzade/contraband/pkg/client/dlp"
	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/spf13/cobra"
)

var (
	genType        string
	genSize        string
	genEntropy     float64
	genCarrier     string
	genCarrierType string
	genOutput      string
	genCompress    string
	genEncrypt     string
	genPassphrase  string
	genTransforms  string
)

var generateCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"dlp"},
	Short:   "Synthesize procedural DLP data and embed into evasion carriers",
	Long: `Generate mathematically valid synthetic secrets (PCI Luhn, SSN, HIPAA, Cloud API keys)
and embed them into covert media carriers (BMP, PNG, WAV, JPEG-ZIP, PDF-JAR).`,
	RunE: runGenerate,
}

func init() {
	generateCmd.Flags().StringVarP(&genType, "type", "t", "all", "DLP payload type: 'pci', 'pii', 'hipaa', 'keys', 'all'")
	generateCmd.Flags().StringVarP(&genSize, "size", "s", "1MB", "Data volume to generate (e.g. '100KB', '10MB', '1GB')")
	generateCmd.Flags().Float64Var(&genEntropy, "entropy", 0.0, "Target Shannon entropy float (optional)")
	generateCmd.Flags().StringVar(&genCarrier, "carrier", "raw", "Carrier format: 'raw', 'bmp', 'png', 'wav', 'jpeg-zip', 'pdf-jar'")
	generateCmd.Flags().StringVar(&genCarrierType, "carrier-type", "", "Procedural text carrier: 'csv', 'json', 'sql', 'email', 'syslog', 'noise'")
	generateCmd.Flags().StringVarP(&genOutput, "output", "o", "", "Output file path (default: stdout summary)")
	generateCmd.Flags().StringVar(&genCompress, "compress", "none", "Compression: 'none', 'zlib', 'gzip', 'zstd'")
	generateCmd.Flags().StringVar(&genEncrypt, "encrypt", "none", "Encryption: 'none', 'aes_gcm'")
	generateCmd.Flags().StringVar(&genPassphrase, "passphrase", "", "Passphrase for AES-256-GCM key derivation")
	generateCmd.Flags().StringVar(&genTransforms, "transforms", "", "Evasion chain: comma-separated 'raw', 'base64', 'hex', 'gzip', 'zstd', 'aes_gcm'")

	rootCmd.AddCommand(generateCmd)
}

func runGenerate(cmd *cobra.Command, args []string) error {
	targetBytes, err := common.ParseBytes(genSize)
	if err != nil {
		return fmt.Errorf("invalid --size: %w", err)
	}

	// Pre-Flight Dry Run Check
	if flagDryRun {
		return RunGenerateDryRun(genType, targetBytes, genCarrier, genOutput, genCompress, genEncrypt)
	}

	// 1. Procedural DLP Data Generation
	appLogger.Info(fmt.Sprintf("Generating %s of synthetic DLP data (type: %s, carrier: %s)...",
		common.FormatBytes(targetBytes), genType, genCarrier))

	minEnt := genEntropy
	maxEnt := 0.0
	if minEnt > 0 {
		maxEnt = minEnt + 0.8
		if maxEnt > 8.0 {
			maxEnt = 8.0
		}
	}

	dlpCfg := dlp.GeneratorConfig{
		DLPType:     genType,
		CarrierType: genCarrierType,
		MinEntropy:  minEnt,
		MaxEntropy:  maxEnt,
		Seed:        flagSeed,
	}
	generator := dlp.NewGenerator(dlpCfg)
	syntheticData, err := generator.GeneratePayload(targetBytes)
	if err != nil {
		return fmt.Errorf("failed to generate synthetic DLP data: %w", err)
	}

	hash := sha256.Sum256(syntheticData)
	appLogger.Debug(fmt.Sprintf("Generated payload SHA-256: %s", hex.EncodeToString(hash[:])))

	// 2. Evasion Pipeline
	pipeCfg := evasion.PipelineConfig{
		Compression: evasion.CompressionMethod(genCompress),
		Encrypt:     genEncrypt == "aes_gcm" || genEncrypt == "aes-256-gcm",
		Passphrase:  genPassphrase,
		Carrier:     evasion.CarrierType(genCarrier),
		Seed:        flagSeed,
		Transforms:  genTransforms,
	}

	pipe, err := evasion.NewPipeline(pipeCfg)
	if err != nil {
		return fmt.Errorf("pipeline configuration error: %w", err)
	}

	transformedChunks, err := pipe.Transform(context.Background(), syntheticData)
	if err != nil {
		return fmt.Errorf("transformation pipeline failed: %w", err)
	}

	// 3. Output Delivery
	if genOutput != "" {
		if _, err := os.Stat(genOutput); err == nil {
			return fmt.Errorf("ABSOLUTE ZERO DELETION VIOLATION: Output file %s already exists", genOutput)
		}
		f, err := os.OpenFile(genOutput, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", genOutput, err)
		}
		defer f.Close()
		totalBytes := 0
		for _, chunk := range transformedChunks {
			n, err := f.Write(chunk)
			if err != nil {
				return fmt.Errorf("failed writing to output file: %w", err)
			}
			totalBytes += n
		}
		appLogger.Success(fmt.Sprintf("Wrote %d bytes to %s", totalBytes, genOutput))
	} else {
		appLogger.Success(fmt.Sprintf("Generated %d chunks successfully. Payload SHA-256: %s",
			len(transformedChunks), hex.EncodeToString(hash[:])))
	}

	return nil
}
