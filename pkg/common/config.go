package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ProfileConfig encapsulates full assessment configurations for the Contraband client engine.
type ProfileConfig struct {
	Target  TargetConfig  `yaml:"target" json:"target"`
	DLP     DLPConfig     `yaml:"dlp" json:"dlp"`
	Evasion EvasionConfig `yaml:"evasion" json:"evasion"`
	Traffic TrafficConfig `yaml:"traffic" json:"traffic"`
	Proxy   ProxyConfig   `yaml:"proxy" json:"proxy"`
	Sweep   SweepConfig   `yaml:"sweep" json:"sweep"`
	Output  OutputConfig  `yaml:"output" json:"output"`
	Destroy bool          `yaml:"destroy" json:"destroy"`
}

type TargetConfig struct {
	Server    string   `yaml:"server" json:"server"`
	Ports     string   `yaml:"ports" json:"ports"`         // 'quick', 'standard', 'full', or comma/range
	Protocols []string `yaml:"protocols" json:"protocols"` // 'all', 'web', 'dns', etc.
}

type DLPConfig struct {
	Payloads    []string `yaml:"payloads" json:"payloads"`         // 'all', 'pci', 'pii', 'hipaa', 'secrets'
	CarrierType string   `yaml:"carrier_type" json:"carrier_type"` // 'csv', 'json', 'sql', 'email', 'syslog', 'noise'
	Size        string   `yaml:"size" json:"size"`                 // '100KB', '50MB', '2GB'
	ChunkSize   string   `yaml:"chunk_size" json:"chunk_size"`     // '64KB', '1MB', '10MB'
}

type EvasionConfig struct {
	Transforms     []string `yaml:"transforms" json:"transforms"`           // 'raw', 'base64', 'hex', 'gzip', 'zstd', 'aes_gcm'
	Stego          string   `yaml:"stego" json:"stego"`                     // 'none', 'png', 'jpeg', 'pdf', 'zip'
	TLSFingerprint string   `yaml:"tls_fingerprint" json:"tls_fingerprint"` // 'chrome', 'edge', 'safari', 'firefox', 'curl', 'default'
}

type TrafficConfig struct {
	Threads     int     `yaml:"threads" json:"threads"`                   // 1–64
	Throughput  string  `yaml:"throughput" json:"throughput"`             // '100KB/s', '5MB/s', 'unlimited'
	Cadence     string  `yaml:"cadence" json:"cadence"`                   // 'burst', 'steady', 'jittered', 'office-hours', 'low-and-slow'
	IntervalMin string  `yaml:"interval_min" json:"interval_min"`         // e.g. '500ms'
	IntervalMax string  `yaml:"interval_max" json:"interval_max"`         // e.g. '4s'
	Jitter      float64 `yaml:"jitter,omitempty" json:"jitter,omitempty"` // 0.0–1.0 (ratio) or 0–100 (percentage)
}

type ProxyConfig struct {
	Mode     string `yaml:"mode" json:"mode"`           // 'auto', 'direct', or URL
	AuthType string `yaml:"auth_type" json:"auth_type"` // 'basic', 'ntlm', 'negotiate'
}

type SweepConfig struct {
	Concurrency int `yaml:"concurrency" json:"concurrency"` // 1–1000
	RateLimit   int `yaml:"rate_limit" json:"rate_limit"`   // packets/sec
}

type OutputConfig struct {
	JSONPath string `yaml:"json_path" json:"json_path"`
	HTMLPath string `yaml:"html_path" json:"html_path"`
}

// NewDefaultProfileConfig initializes a ProfileConfig with safe, production-grade defaults.
func NewDefaultProfileConfig() *ProfileConfig {
	return &ProfileConfig{
		Target: TargetConfig{
			Server:    "127.0.0.1",
			Ports:     PortPresetQuick,
			Protocols: []string{CategoryAll},
		},
		DLP: DLPConfig{
			Payloads:    []string{DLPTypeAll},
			CarrierType: CarrierCSV,
			Size:        "1MB",
			ChunkSize:   "1MB",
		},
		Evasion: EvasionConfig{
			Transforms:     []string{TransformRaw},
			Stego:          StegoNone,
			TLSFingerprint: TLSFingerprintChrome,
		},
		Traffic: TrafficConfig{
			Threads:     DefaultThreads,
			Throughput:  "unlimited",
			Cadence:     CadenceSteady,
			IntervalMin: "500ms",
			IntervalMax: "4s",
		},
		Proxy: ProxyConfig{
			Mode:     "auto",
			AuthType: "basic",
		},
		Sweep: SweepConfig{
			Concurrency: DefaultConcurrency,
			RateLimit:   DefaultRateLimit,
		},
		Output: OutputConfig{
			JSONPath: "results.json",
			HTMLPath: "report.html",
		},
		Destroy: false,
	}
}

// NewStealthProfileConfig creates a low-and-slow, obfuscated profile.
func NewStealthProfileConfig() *ProfileConfig {
	cfg := NewDefaultProfileConfig()
	cfg.Traffic.Threads = 1
	cfg.Traffic.Throughput = "50KB/s"
	cfg.Traffic.Cadence = CadenceLowAndSlow
	cfg.Traffic.IntervalMin = "2s"
	cfg.Traffic.IntervalMax = "10s"
	cfg.Evasion.Transforms = []string{TransformGzip, TransformAESGCM}
	cfg.Evasion.Stego = StegoPNG
	cfg.Evasion.TLSFingerprint = TLSFingerprintChrome
	cfg.Sweep.Concurrency = 10
	cfg.Sweep.RateLimit = 20
	return cfg
}

// NewAggressiveProfileConfig creates a high-throughput, maximum-concurrency profile.
func NewAggressiveProfileConfig() *ProfileConfig {
	cfg := NewDefaultProfileConfig()
	cfg.Target.Ports = PortPresetStandard
	cfg.Traffic.Threads = 32
	cfg.Traffic.Throughput = "unlimited"
	cfg.Traffic.Cadence = CadenceBurst
	cfg.Sweep.Concurrency = 500
	cfg.Sweep.RateLimit = 1000
	return cfg
}

// NewComplianceProfileConfig creates a multi-DLP comprehensive audit profile.
func NewComplianceProfileConfig() *ProfileConfig {
	cfg := NewDefaultProfileConfig()
	cfg.DLP.Payloads = []string{DLPTypePCI, DLPTypePII, DLPTypeHIPAA, DLPTypeSecrets}
	cfg.DLP.Size = "10MB"
	cfg.DLP.CarrierType = CarrierJSON
	return cfg
}

// LoadProfileConfig reads, deserializes, and validates a YAML or JSON profile file.
func LoadProfileConfig(path string) (*ProfileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile config file: %w", err)
	}

	cfg := NewDefaultProfileConfig()
	ext := strings.ToLower(filepath.Ext(path))

	if ext == ".json" {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON profile config: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML profile config: %w", err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("profile config validation error: %w", err)
	}

	return cfg, nil
}

// Validate executes strict semantic validation against all profile configuration fields.
func (c *ProfileConfig) Validate() error {
	// Validate Ports
	if err := validatePortsField(c.Target.Ports); err != nil {
		return fmt.Errorf("invalid target ports: %w", err)
	}

	// Validate Protocols
	if len(c.Target.Protocols) == 0 {
		return errors.New("at least one protocol must be specified")
	}
	validProtocols := map[string]bool{
		"all": true, "web": true, "dns": true, "file": true, "mail": true, "smb": true, "cloud": true, "covert": true,
		ProtoHTTP1: true, ProtoHTTP2: true, ProtoHTTP3: true, ProtoWebSocket: true, ProtoGRPC: true, ProtoWebDAV: true,
		ProtoDNSA: true, ProtoDNSTXT: true, ProtoDoH: true, ProtoDoT: true,
		ProtoFTP: true, ProtoFTPS: true, ProtoSFTP: true, ProtoSMTP: true,
		ProtoSMBFile: true, ProtoSMBHash: true, ProtoSMBQUIC: true,
		ProtoAWSS3: true, ProtoGCPGCS: true, ProtoAzureBlob: true,
		ProtoICMPEcho: true, ProtoNTPTime: true, ProtoSyslog: true, ProtoMQTT: true,
	}
	for _, p := range c.Target.Protocols {
		if !validProtocols[strings.ToLower(p)] {
			return fmt.Errorf("unsupported protocol or category: '%s'", p)
		}
	}

	// Validate DLP Payloads
	validDLP := map[string]bool{"all": true, DLPTypePCI: true, DLPTypePII: true, DLPTypeHIPAA: true, DLPTypeSecrets: true}
	for _, d := range c.DLP.Payloads {
		if !validDLP[strings.ToLower(d)] {
			return fmt.Errorf("unsupported DLP payload type: '%s'", d)
		}
	}

	// Validate Carrier Type
	validCarriers := map[string]bool{
		CarrierCSV: true, CarrierJSON: true, CarrierSQL: true, CarrierEmail: true, CarrierSyslog: true, CarrierNoise: true,
	}
	if !validCarriers[strings.ToLower(c.DLP.CarrierType)] {
		return fmt.Errorf("unsupported carrier type: '%s'", c.DLP.CarrierType)
	}

	// Validate Transforms
	validTransforms := map[string]bool{
		TransformRaw: true, TransformBase64: true, TransformHex: true,
		TransformGzip: true, TransformZlib: true, TransformZstd: true, TransformAESGCM: true,
	}
	for _, t := range c.Evasion.Transforms {
		if !validTransforms[strings.ToLower(t)] {
			return fmt.Errorf("unsupported evasion transform: '%s'", t)
		}
	}

	// Validate Stego
	validStego := map[string]bool{
		StegoNone: true, StegoPNG: true, StegoJPEG: true, StegoPDF: true, StegoZIP: true,
	}
	if !validStego[strings.ToLower(c.Evasion.Stego)] {
		return fmt.Errorf("unsupported stego embedding: '%s'", c.Evasion.Stego)
	}

	// Validate TLS Fingerprint
	validTLS := map[string]bool{
		TLSFingerprintChrome: true, TLSFingerprintEdge: true, TLSFingerprintSafari: true,
		TLSFingerprintFirefox: true, TLSFingerprintCurl: true, TLSFingerprintDefault: true,
	}
	if !validTLS[strings.ToLower(c.Evasion.TLSFingerprint)] {
		return fmt.Errorf("unsupported uTLS fingerprint preset: '%s'", c.Evasion.TLSFingerprint)
	}

	// Validate Threads
	if c.Traffic.Threads < 1 || c.Traffic.Threads > MaxThreads {
		return fmt.Errorf("threads must be between 1 and %d (got %d)", MaxThreads, c.Traffic.Threads)
	}

	// Validate Cadence
	validCadence := map[string]bool{
		CadenceBurst: true, CadenceSteady: true, CadenceJittered: true,
		CadenceOfficeHours: true, CadenceLowAndSlow: true,
	}
	if !validCadence[strings.ToLower(c.Traffic.Cadence)] {
		return fmt.Errorf("unsupported cadence profile: '%s'", c.Traffic.Cadence)
	}

	// Validate Cadence Intervals
	var minDur, maxDur time.Duration
	var hasMin, hasMax bool

	if c.Traffic.IntervalMin != "" {
		d, err := ParseDuration(c.Traffic.IntervalMin)
		if err != nil {
			return fmt.Errorf("invalid interval_min %q: %w", c.Traffic.IntervalMin, err)
		}
		if d <= 0 {
			return fmt.Errorf("interval_min must be greater than zero: %s", c.Traffic.IntervalMin)
		}
		minDur = d
		hasMin = true
	}

	if c.Traffic.IntervalMax != "" {
		d, err := ParseDuration(c.Traffic.IntervalMax)
		if err != nil {
			return fmt.Errorf("invalid interval_max %q: %w", c.Traffic.IntervalMax, err)
		}
		if d <= 0 {
			return fmt.Errorf("interval_max must be greater than zero: %s", c.Traffic.IntervalMax)
		}
		maxDur = d
		hasMax = true
	}

	if hasMin && hasMax && minDur > maxDur {
		return fmt.Errorf("interval_min (%v) cannot be greater than interval_max (%v)", minDur, maxDur)
	}

	// Validate Jitter percentage bounds (0.0 <= Jitter <= 1.0 or 0 <= Jitter <= 100)
	if c.Traffic.Jitter < 0.0 || (c.Traffic.Jitter > 1.0 && c.Traffic.Jitter > 100.0) {
		return fmt.Errorf("jitter percentage must be between 0.0 and 1.0 or 0 and 100 (got %v)", c.Traffic.Jitter)
	}

	// Validate Proxy Mode
	if c.Proxy.Mode != "auto" && c.Proxy.Mode != "direct" {
		if _, err := url.Parse(c.Proxy.Mode); err != nil {
			return fmt.Errorf("invalid proxy URL '%s': %w", c.Proxy.Mode, err)
		}
	}

	// Validate Sweep
	if c.Sweep.Concurrency < 1 || c.Sweep.Concurrency > MaxConcurrency {
		return fmt.Errorf("concurrency must be between 1 and %d (got %d)", MaxConcurrency, c.Sweep.Concurrency)
	}
	if c.Sweep.RateLimit < 1 {
		return fmt.Errorf("rate_limit must be >= 1 (got %d)", c.Sweep.RateLimit)
	}

	return nil
}

func validatePortsField(ports string) error {
	_, err := ParsePortsField(ports)
	return err
}

// ClientFlags captures CLI flag values provided by the Cobra command hierarchy.
type ClientFlags struct {
	Server         string
	Ports          string
	Protocols      []string
	DLP            []string
	CarrierType    string
	Size           string
	ChunkSize      string
	Threads        int
	Throughput     string
	Cadence        string
	IntervalMin    string
	IntervalMax    string
	Jitter         float64
	Transforms     []string
	Stego          string
	TLSFingerprint string
	Proxy          string
	Concurrency    int
	RateLimit      int
	OutputJSON     string
	OutputHTML     string
	Destroy        bool
}

// MergeWithFlags overlays explicitly provided CLI flags onto ProfileConfig.
// The isChanged function wraps Cobra's cmd.Flags().Changed(flagName).
func (c *ProfileConfig) MergeWithFlags(flags ClientFlags, isChanged func(string) bool) {
	if isChanged("server") && flags.Server != "" {
		c.Target.Server = flags.Server
	}
	if isChanged("ports") && flags.Ports != "" {
		c.Target.Ports = flags.Ports
	}
	if isChanged("protocols") && len(flags.Protocols) > 0 {
		c.Target.Protocols = flags.Protocols
	}
	if isChanged("dlp") && len(flags.DLP) > 0 {
		c.DLP.Payloads = flags.DLP
	}
	if isChanged("carrier-type") && flags.CarrierType != "" {
		c.DLP.CarrierType = flags.CarrierType
	}
	if isChanged("size") && flags.Size != "" {
		c.DLP.Size = flags.Size
	}
	if isChanged("chunk-size") && flags.ChunkSize != "" {
		c.DLP.ChunkSize = flags.ChunkSize
	}
	if isChanged("threads") && flags.Threads > 0 {
		c.Traffic.Threads = flags.Threads
	}
	if isChanged("throughput") && flags.Throughput != "" {
		c.Traffic.Throughput = flags.Throughput
	}
	if isChanged("cadence") && flags.Cadence != "" {
		c.Traffic.Cadence = flags.Cadence
	}
	if isChanged("interval-min") && flags.IntervalMin != "" {
		c.Traffic.IntervalMin = flags.IntervalMin
	}
	if isChanged("interval-max") && flags.IntervalMax != "" {
		c.Traffic.IntervalMax = flags.IntervalMax
	}
	if isChanged("jitter") {
		c.Traffic.Jitter = flags.Jitter
	}
	if isChanged("transforms") && len(flags.Transforms) > 0 {
		c.Evasion.Transforms = flags.Transforms
	}
	if isChanged("stego") && flags.Stego != "" {
		c.Evasion.Stego = flags.Stego
	}
	if isChanged("tls-fingerprint") && flags.TLSFingerprint != "" {
		c.Evasion.TLSFingerprint = flags.TLSFingerprint
	}
	if isChanged("proxy") && flags.Proxy != "" {
		c.Proxy.Mode = flags.Proxy
	}
	if isChanged("concurrency") && flags.Concurrency > 0 {
		c.Sweep.Concurrency = flags.Concurrency
	}
	if isChanged("rate-limit") && flags.RateLimit > 0 {
		c.Sweep.RateLimit = flags.RateLimit
	}
	if isChanged("output-json") && flags.OutputJSON != "" {
		c.Output.JSONPath = flags.OutputJSON
	}
	if isChanged("output-html") && flags.OutputHTML != "" {
		c.Output.HTMLPath = flags.OutputHTML
	}
	if isChanged("destroy") {
		c.Destroy = flags.Destroy
	}
}

// ServerConfig models server listener configuration parameters for 'contraband server'.
type ServerConfig struct {
	Bind       string   `yaml:"bind" json:"bind"`
	Domain     string   `yaml:"domain" json:"domain"`
	Ports      string   `yaml:"ports" json:"ports"`
	Protocols  []string `yaml:"protocols" json:"protocols"`
	SMBMode    string   `yaml:"smb_mode" json:"smb_mode"` // 'file-transfer' or 'hash-capture'
	CertPath   string   `yaml:"cert" json:"cert"`
	KeyPath    string   `yaml:"key" json:"key"`
	EnableEBPF bool     `yaml:"enable_ebpf" json:"enable_ebpf"`
	Database   string   `yaml:"db" json:"db"`
}

// NewDefaultServerConfig returns standard defaults for the server engine.
func NewDefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Bind:      DefaultServerBind,
		Domain:    "contraband.example.com",
		Ports:     PortPresetQuick,
		Protocols: []string{CategoryAll},
		SMBMode:   "hash-capture",
		Database:  "", // in-memory by default
	}
}

// Validate checks ServerConfig parameters.
func (s *ServerConfig) Validate() error {
	if s.Bind == "" {
		return errors.New("server bind address cannot be empty")
	}
	if err := validatePortsField(s.Ports); err != nil {
		return fmt.Errorf("invalid server ports: %w", err)
	}
	if len(s.Protocols) == 0 {
		return errors.New("at least one protocol must be specified")
	}
	if s.SMBMode != "file-transfer" && s.SMBMode != "hash-capture" {
		return fmt.Errorf("invalid smb_mode %q (must be 'file-transfer' or 'hash-capture')", s.SMBMode)
	}
	return nil
}
