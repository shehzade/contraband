package common

import (
	"time"
)

// Build metadata injected via Makefile -ldflags
var (
	Version   = "1.0.0"
	Commit    = "standalone"
	BuildDate = "2026-11-06T00:00:00Z"
	BuiltBy   = "shehzade"
)

// Magic numbers and framing identifiers
const (
	// MagicHeader is the 4-byte signature "CTRB" (0x43545242)
	MagicHeader     uint32 = 0x43545242
	MagicICMP       uint32 = 0x43545242
	UDPProbeToken          = "CTRB_UDP_PROBE\n"
	ChunkHeaderSize        = 32 // 4B Magic + 16B Token + 4B Seq + 4B Total + 4B Length
)

var (
	MagicHeaderBytes = []byte{0x43, 0x54, 0x52, 0x42}
)

// Protocol Header Names
const (
	HeaderSessionID     = "X-CTRB-Session-ID"
	HeaderSequence      = "X-CTRB-Sequence"
	HeaderTotalChunks   = "X-CTRB-Total-Chunks"
	HeaderPayloadLength = "X-CTRB-Payload-Length"
	HeaderWireHash      = "X-CTRB-Wire-Hash"
	HeaderPayloadHash   = "X-CTRB-Payload-Hash"
	HeaderClientIP      = "X-CTRB-Client-IP"
	HeaderClientHost    = "X-CTRB-Client-Host"
	HeaderNetworkZone   = "X-CTRB-Network-Zone"
	HeaderProtocol      = "X-CTRB-Protocol"
)

// Port Presets
const (
	PortPresetQuick    = "quick"
	PortPresetStandard = "standard"
	PortPresetFull     = "full"

	PortMin = 1
	PortMax = 65535
)

// QuickPorts contains the top 25 enterprise firewall egress ports
var QuickPorts = []int{
	21, 22, 23, 25, 53, 80, 88, 110, 123, 135,
	139, 143, 389, 443, 445, 465, 587, 853, 990, 993,
	995, 1433, 3389, 8080, 8443,
}

// StandardPorts contains the top 200 enterprise firewall egress ports (sorted and deduplicated)
var StandardPorts = []int{
	20, 21, 22, 23, 25, 43, 53, 67, 68, 69,
	79, 80, 81, 82, 84, 88, 110, 111, 119, 123,
	135, 137, 138, 139, 143, 161, 162, 179, 194, 389,
	411, 412, 443, 444, 445, 446, 464, 465, 500, 513,
	514, 515, 520, 524, 548, 554, 587, 631, 636, 688,
	853, 854, 873, 902, 989, 990, 992, 993, 995, 1025,
	1026, 1080, 1099, 1194, 1214, 1241, 1352, 1433, 1434, 1512,
	1521, 1522, 1527, 1701, 1723, 1755, 1812, 1813, 1883, 1900,
	1935, 2000, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375,
	2376, 2379, 2380, 2483, 2484, 2525, 2526, 2809, 3000, 3128,
	3260, 3268, 3269, 3306, 3389, 3478, 3690, 4000, 4200, 4333,
	4369, 4500, 5000, 5001, 5060, 5061, 5173, 5222, 5223, 5269,
	5353, 5432, 5433, 5555, 5601, 5671, 5672, 5800, 5900, 5901,
	5984, 5985, 5986, 5988, 5989, 6000, 6379, 6443, 6514, 6666,
	6667, 7000, 7001, 7002, 7077, 7474, 8000, 8001, 8008, 8009,
	8080, 8081, 8082, 8083, 8085, 8086, 8087, 8088, 8089, 8090,
	8123, 8181, 8243, 8280, 8333, 8443, 8500, 8600, 8843, 8883,
	8888, 9000, 9001, 9002, 9042, 9080, 9090, 9092, 9093, 9100,
	9200, 9300, 9418, 9443, 9444, 9999, 10000, 10022, 10443, 11211,
	15672, 18080, 18081, 27017, 27018, 28017, 50000, 50070, 51820, 61616,
}

// 20 Core Protocol Identifiers
const (
	// Web & Modern L7
	ProtoHTTP1     = "http_post"
	ProtoHTTP2     = "https_post"
	ProtoHTTP3     = "http3_quic"
	ProtoWebSocket = "websocket_binary"
	ProtoGRPC      = "grpc_protobuf"
	ProtoWebDAV    = "webdav"

	// DNS & Tunneling
	ProtoDNSA   = "dns_a"
	ProtoDNSTXT = "dns_txt"
	ProtoDoH    = "dns_over_https"
	ProtoDoT    = "dns_over_tls"

	// File & Mail
	ProtoFTP  = "ftp"
	ProtoFTPS = "ftps"
	ProtoSFTP = "sftp"
	ProtoSMTP = "smtp"

	// Windows SMB
	ProtoSMBFile = "smb_file"
	ProtoSMBHash = "smb_hash_capture"
	ProtoSMBQUIC = "smb_quic"

	// Native Cloud Storage
	ProtoAWSS3     = "aws_s3"
	ProtoGCPGCS    = "gcp_gcs"
	ProtoAzureBlob = "azure_blob"

	// Covert & Infrastructure
	ProtoICMPEcho = "icmp_echo"
	ProtoNTPTime  = "ntp_timestamp"
	ProtoSyslog   = "syslog"
	ProtoMQTT     = "mqtt"

	// Compatibility aliases
	ProtoSMBTCP = ProtoSMBFile
	ProtoICMP   = ProtoICMPEcho
	ProtoNTP    = ProtoNTPTime
)

// Protocol Categories
const (
	CategoryAll    = "all"
	CategoryWeb    = "web"
	CategoryDNS    = "dns"
	CategoryFile   = "file"
	CategoryMail   = "mail"
	CategorySMB    = "smb"
	CategoryCloud  = "cloud"
	CategoryCovert = "covert"
)

// CategoryMap maps category names to protocol identifier lists
var CategoryMap = map[string][]string{
	CategoryWeb:    {ProtoHTTP1, ProtoHTTP2, ProtoHTTP3, ProtoWebSocket, ProtoGRPC, ProtoWebDAV},
	CategoryDNS:    {ProtoDNSA, ProtoDNSTXT, ProtoDoH, ProtoDoT},
	CategoryFile:   {ProtoFTP, ProtoFTPS, ProtoSFTP},
	CategoryMail:   {ProtoSMTP},
	CategorySMB:    {ProtoSMBFile, ProtoSMBHash, ProtoSMBQUIC},
	CategoryCloud:  {ProtoAWSS3, ProtoGCPGCS, ProtoAzureBlob},
	CategoryCovert: {ProtoICMPEcho, ProtoNTPTime, ProtoSyslog, ProtoMQTT},
}

// uTLS Fingerprint Presets
const (
	TLSFingerprintChrome  = "chrome"
	TLSFingerprintEdge    = "edge"
	TLSFingerprintSafari  = "safari"
	TLSFingerprintFirefox = "firefox"
	TLSFingerprintCurl    = "curl"
	TLSFingerprintDefault = "default"
)

var AllTLSFingerprints = []string{
	TLSFingerprintChrome,
	TLSFingerprintEdge,
	TLSFingerprintSafari,
	TLSFingerprintFirefox,
	TLSFingerprintCurl,
	TLSFingerprintDefault,
}

// ALPN Constants
const (
	ALPNHTTP1 = "http/1.1"
	ALPNHTTP2 = "h2"
	ALPNHTTP3 = "h3"
	ALPNFTP   = "ftp"
	ALPNDoT   = "dot"
	ALPNSMB   = "smb"
	ALPNMQTT  = "mqtt"
)

// Cadence Pacing Profiles
const (
	CadenceBurst       = "burst"
	CadenceSteady      = "steady"
	CadenceJittered    = "jittered"
	CadenceOfficeHours = "office-hours"
	CadenceLowAndSlow  = "low-and-slow"
)

var AllCadenceProfiles = []string{
	CadenceBurst,
	CadenceSteady,
	CadenceJittered,
	CadenceOfficeHours,
	CadenceLowAndSlow,
}

// Synthetic DLP Payload Types
const (
	DLPTypePCI     = "pci"
	DLPTypePII     = "pii"
	DLPTypeHIPAA   = "hipaa"
	DLPTypeSecrets = "secrets"
	DLPTypeAll     = "all"
)

var AllDLPTypes = []string{DLPTypePCI, DLPTypePII, DLPTypeHIPAA, DLPTypeSecrets}

// Procedural Carrier Contexts
const (
	CarrierCSV    = "csv"
	CarrierJSON   = "json"
	CarrierSQL    = "sql"
	CarrierEmail  = "email"
	CarrierSyslog = "syslog"
	CarrierNoise  = "noise"
)

var AllCarrierTypes = []string{CarrierCSV, CarrierJSON, CarrierSQL, CarrierEmail, CarrierSyslog, CarrierNoise}

// Evasion Transforms
const (
	TransformRaw    = "raw"
	TransformBase64 = "base64"
	TransformHex    = "hex"
	TransformGzip   = "gzip"
	TransformZlib   = "zlib"
	TransformZstd   = "zstd"
	TransformAESGCM = "aes_gcm"
)

// Steganography Smuggling Types
const (
	StegoNone = "none"
	StegoPNG  = "png"
	StegoJPEG = "jpeg"
	StegoPDF  = "pdf"
	StegoZIP  = "zip"
)

// Operational Defaults & Tuning
const (
	DefaultConcurrency = 100
	MaxConcurrency     = 1000
	DefaultRateLimit   = 500         // packets per second
	DefaultChunkSize   = 1024 * 1024 // 1MB
	DefaultThreads     = 4
	MaxThreads         = 64
	DefaultTCPTimeout  = 1500 * time.Millisecond
	DefaultWPADTimeout = 3 * time.Second
	DefaultReportPort  = 8088
	DefaultServerBind  = "0.0.0.0"
	FixedNTLMChallenge = "1122334455667788"
)

var FixedNTLMChallengeBytes = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
