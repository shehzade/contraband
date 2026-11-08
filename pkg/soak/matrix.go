package soak

import (
	"fmt"

	"github.com/shehzade/contraband/pkg/common"
)

// Standard Multi-Zone Identifiers
const (
	ZoneLANCorp      = "zone-lan-corp"
	ZoneDMZ          = "zone-dmz"
	ZonePCIDSS       = "zone-pci-dss"
	ZoneCloudEast    = "zone-cloud-east"
	ZoneBranchOffice = "zone-branch-office"
)

// AllZones returns the complete set of 5 concurrent enterprise client zones.
func AllZones() []string {
	return []string{
		ZoneLANCorp,
		ZoneDMZ,
		ZonePCIDSS,
		ZoneCloudEast,
		ZoneBranchOffice,
	}
}

// AllSoakProtocols returns all 20+ L7 smuggling protocols supported by Contraband.
func AllSoakProtocols() []string {
	return []string{
		common.ProtoHTTP1,     // HTTP/1.1 POST smuggling
		common.ProtoHTTP2,     // HTTP/2 over TLS
		common.ProtoHTTP3,     // HTTP/3 over QUIC
		common.ProtoWebSocket, // WebSocket binary framing
		common.ProtoGRPC,      // gRPC / HTTP/2 Protobuf streams
		common.ProtoDNSTXT,    // DNS TXT record tunneling
		common.ProtoDNSA,      // DNS A / CNAME / NULL tunneling
		common.ProtoICMPEcho,  // ICMP Echo covert carrier
		common.ProtoSMTP,      // ESMTP DATA MIME smuggling
		common.ProtoDoH,       // DNS over HTTPS
		common.ProtoDoT,       // DNS over TLS
		common.ProtoSFTP,      // SSH / SFTP subsystem channel
		common.ProtoFTP,       // FTP passive channel
		common.ProtoFTPS,      // Explicit FTPS
		common.ProtoSMBFile,   // SMB2/3 File Transfer
		common.ProtoSMBQUIC,   // SMB over QUIC
		common.ProtoWebDAV,    // HTTP WebDAV PUT / PROPFIND
		common.ProtoNTPTime,   // NTP timestamp fraction steganography
		common.ProtoSyslog,    // Syslog RFC 5424 structured exfiltration
		common.ProtoMQTT,      // MQTT 3.1.1 QoS0/1 binary payloads
		common.ProtoAWSS3,     // S3 API REST PUT object
		common.ProtoGCPGCS,    // GCP Cloud Storage REST API
		common.ProtoAzureBlob, // Azure Blob Storage REST API
	}
}

// Progressive Volume Spectrum (in bytes)
const (
	Volume50KB  int64 = 50 * 1024
	Volume500KB int64 = 500 * 1024
	Volume5MB   int64 = 5 * 1024 * 1024
	Volume50MB  int64 = 50 * 1024 * 1024
	Volume100MB int64 = 100 * 1024 * 1024
	Volume500MB int64 = 500 * 1024 * 1024
	Volume1GB   int64 = 1024 * 1024 * 1024
	Volume5GB   int64 = 5 * 1024 * 1024 * 1024
)

// AllVolumeTiers returns the progressive large transfer volume spectrum for soak testing.
func AllVolumeTiers() []int64 {
	return []int64{
		Volume50MB,
		Volume100MB,
		Volume500MB,
		Volume1GB,
		Volume5GB,
	}
}

// ValidationVolumeTiers returns micro, medium, and bulk tiers for pre-soak sanity validation.
func ValidationVolumeTiers() []int64 {
	return []int64{
		Volume50KB,
		Volume500KB,
		Volume5MB,
		Volume50MB,
		Volume100MB,
	}
}

// Proxy Modes
const (
	ProxyDirect    = "direct"
	ProxyWPAD      = "wpad"
	ProxyPAC       = "pac"
	ProxyAuthNTLM  = "auth_ntlm"
	ProxyAuthBasic = "auth_basic"
)

// AllProxyModes returns all corporate proxy traversal profiles.
func AllProxyModes() []string {
	return []string{
		ProxyDirect,
		ProxyWPAD,
		ProxyPAC,
		ProxyAuthNTLM,
		ProxyAuthBasic,
	}
}

// Negative Test Injection Types
const (
	NegativeNone = ""
	NegativeL4   = "L4"  // Network drop, closed port, timeout -> BLOCKED_L4
	NegativeL7   = "L7"  // TLS reset, proxy 403, invalid verb -> BLOCKED_L7
	NegativeDLP  = "DLP" // Corrupted SHA-256 rolling hash, tampering -> BLOCKED_DLP
)

// Scenario encapsulates an execution permutation in the soak testing matrix.
type Scenario struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Zone            string         `json:"zone"`
	Protocol        string         `json:"protocol"`
	VolumeBytes     int64          `json:"volume_bytes"`
	VolumeStr       string         `json:"volume_str"`
	DLPType         string         `json:"dlp_type"`
	CarrierType     string         `json:"carrier_type"`
	Stego           string         `json:"stego"`
	Transforms      string         `json:"transforms"`
	Cadence         string         `json:"cadence"`
	TLSFingerprint  string         `json:"tls_fingerprint"`
	ProxyMode       string         `json:"proxy_mode"`
	IsNegative      bool           `json:"is_negative"`
	NegativeType    string         `json:"negative_type,omitempty"`
	ExpectedVerdict common.Verdict `json:"expected_verdict"`
}

// IsCovertProtocol returns true if the protocol is a low-bandwidth datagram or covert query tunnel (DNS, DoH, DoT, ICMP, NTP, Syslog, MQTT).
func IsCovertProtocol(proto string) bool {
	switch proto {
	case common.ProtoDNSTXT, common.ProtoDNSA, common.ProtoDoH, common.ProtoDoT,
		common.ProtoICMPEcho, common.ProtoNTPTime, common.ProtoSyslog, common.ProtoMQTT:
		return true
	default:
		return false
	}
}

// GenerateScenarioMatrix synthesizes the full multi-scenario matrix for the soak engine.
func GenerateScenarioMatrix(volumes []int64) []Scenario {
	if len(volumes) == 0 {
		volumes = AllVolumeTiers()
	}

	zones := AllZones()
	protocols := AllSoakProtocols()
	dlpTypes := common.AllDLPTypes
	carrierTypes := common.AllCarrierTypes
	stegoCarriers := []string{common.StegoNone, common.StegoPNG, common.StegoJPEG, common.StegoPDF, common.StegoZIP}
	transforms := []string{
		common.TransformRaw,
		common.TransformBase64,
		common.TransformHex,
		common.TransformGzip,
		common.TransformZlib,
		common.TransformZstd,
		common.TransformAESGCM,
	}
	cadences := common.AllCadenceProfiles
	fingerprints := common.AllTLSFingerprints
	proxies := AllProxyModes()

	var matrix []Scenario
	seq := 1

	for pIdx, proto := range protocols {
		for vIdx, vol := range volumes {
			effectiveVol := vol
			if IsCovertProtocol(proto) && effectiveVol > Volume50KB {
				effectiveVol = Volume50KB
			}
			zone := zones[(pIdx+vIdx)%len(zones)]
			dlpType := dlpTypes[(pIdx+vIdx)%len(dlpTypes)]
			carrier := carrierTypes[(pIdx+vIdx)%len(carrierTypes)]
			stego := stegoCarriers[(pIdx+vIdx)%len(stegoCarriers)]
			xform := transforms[(pIdx+vIdx)%len(transforms)]
			cadence := cadences[(pIdx+vIdx)%len(cadences)]
			fp := fingerprints[(pIdx+vIdx)%len(fingerprints)]
			proxy := proxies[(pIdx+vIdx)%len(proxies)]

			volStr := common.FormatBytes(effectiveVol)
			sc := Scenario{
				ID:              fmt.Sprintf("SC-%04d", seq),
				Name:            fmt.Sprintf("%s_%s_%s_%s", zone, proto, volStr, dlpType),
				Zone:            zone,
				Protocol:        proto,
				VolumeBytes:     effectiveVol,
				VolumeStr:       volStr,
				DLPType:         dlpType,
				CarrierType:     carrier,
				Stego:           stego,
				Transforms:      xform,
				Cadence:         cadence,
				TLSFingerprint:  fp,
				ProxyMode:       proxy,
				IsNegative:      false,
				ExpectedVerdict: common.VerdictSuccess,
			}
			matrix = append(matrix, sc)
			seq++
		}
	}

	// Add Negative Testing Scenarios
	negativeTypes := []struct {
		negType string
		verdict common.Verdict
		name    string
	}{
		{NegativeL4, common.VerdictBlockedL4, "Simulated_L4_Network_Drop_RST"},
		{NegativeL7, common.VerdictBlockedL7, "Simulated_L7_Proxy403_TLS_Rejection"},
		{NegativeDLP, common.VerdictBlockedDLP, "Simulated_DLP_Hash_Tampering_Interception"},
	}

	for _, neg := range negativeTypes {
		for _, zone := range zones {
			sc := Scenario{
				ID:              fmt.Sprintf("SC-NEG-%04d", seq),
				Name:            fmt.Sprintf("%s_%s", zone, neg.name),
				Zone:            zone,
				Protocol:        common.ProtoHTTP2,
				VolumeBytes:     Volume50KB,
				VolumeStr:       "50KB",
				DLPType:         common.DLPTypePCI,
				CarrierType:     common.CarrierCSV,
				Stego:           common.StegoNone,
				Transforms:      common.TransformRaw,
				Cadence:         common.CadenceSteady,
				TLSFingerprint:  common.TLSFingerprintChrome,
				ProxyMode:       ProxyDirect,
				IsNegative:      true,
				NegativeType:    neg.negType,
				ExpectedVerdict: neg.verdict,
			}
			matrix = append(matrix, sc)
			seq++
		}
	}

	return matrix
}
