package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// RemediationRuleSet contains vendor-synthesized firewall blocking rules.
type RemediationRuleSet struct {
	GeneratedAt    time.Time `json:"generated_at"`
	OpenTCPPorts   []int     `json:"open_tcp_ports"`
	OpenUDPPorts   []int     `json:"open_udp_ports"`
	OpenProtocols  []string  `json:"open_protocols"`
	TargetHost     string    `json:"target_host,omitempty"`
	IPTablesRules  string    `json:"iptables"`
	NFTablesRules  string    `json:"nftables"`
	PANOSRules     string    `json:"panos"`
	FortiGateRules string    `json:"fortigate"`
	CiscoASARules  string    `json:"cisco_asa"`
}

// Ergonomic accessors for templates and scripts
func (r RemediationRuleSet) IPTables() string  { return r.IPTablesRules }
func (r RemediationRuleSet) NFTables() string  { return r.NFTablesRules }
func (r RemediationRuleSet) PANOS() string     { return r.PANOSRules }
func (r RemediationRuleSet) FortiGate() string { return r.FortiGateRules }
func (r RemediationRuleSet) CiscoASA() string  { return r.CiscoASARules }

// FormatAll produces a consolidated multi-vendor remediation configuration document.
func (r *RemediationRuleSet) FormatAll() string {
	var b strings.Builder
	b.WriteString("### Linux iptables Rules\n\n")
	b.WriteString(r.IPTablesRules)
	b.WriteString("\n\n### Linux nftables Rules\n\n")
	b.WriteString(r.NFTablesRules)
	b.WriteString("\n\n### Palo Alto Networks PAN-OS Rules\n\n")
	b.WriteString(r.PANOSRules)
	b.WriteString("\n\n### Fortinet FortiGate CLI Rules\n\n")
	b.WriteString(r.FortiGateRules)
	b.WriteString("\n\n### Cisco ASA Rules\n\n")
	b.WriteString(r.CiscoASARules)
	return b.String()
}

// GenerateRemediation produces vendor-accurate firewall configurations for all successful probes.
// Only successful channels (VerdictSuccess) generate blocking rules.
func GenerateRemediation(probes []common.ProbeResult, targetHost string) *RemediationRuleSet {
	ruleSet := &RemediationRuleSet{
		GeneratedAt: time.Now().UTC(),
		TargetHost:  targetHost,
	}

	tcpPortMap := make(map[int]bool)
	udpPortMap := make(map[int]bool)
	protoMap := make(map[string]bool)

	// Filter strictly for Verdict == VerdictSuccess
	for _, p := range probes {
		if p.Verdict != common.VerdictSuccess {
			continue
		}

		if p.TargetPort > 0 {
			switch strings.ToLower(p.Protocol) {
			case "udp", "ntp_timestamp", "syslog_udp", "icmp_echo":
				udpPortMap[p.TargetPort] = true
			default:
				tcpPortMap[p.TargetPort] = true
			}
		}

		if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
			protoMap[p.Protocol] = true
		}
	}

	// Sort ports for deterministic output
	for port := range tcpPortMap {
		ruleSet.OpenTCPPorts = append(ruleSet.OpenTCPPorts, port)
	}
	sort.Ints(ruleSet.OpenTCPPorts)

	for port := range udpPortMap {
		ruleSet.OpenUDPPorts = append(ruleSet.OpenUDPPorts, port)
	}
	sort.Ints(ruleSet.OpenUDPPorts)

	for proto := range protoMap {
		ruleSet.OpenProtocols = append(ruleSet.OpenProtocols, proto)
	}
	sort.Strings(ruleSet.OpenProtocols)

	// Generate rule sets
	ruleSet.IPTablesRules = generateIPTables(ruleSet.OpenTCPPorts, ruleSet.OpenUDPPorts, targetHost)
	ruleSet.NFTablesRules = generateNFTables(ruleSet.OpenTCPPorts, ruleSet.OpenUDPPorts, targetHost)
	ruleSet.PANOSRules = generatePANOS(ruleSet.OpenTCPPorts, ruleSet.OpenUDPPorts, ruleSet.OpenProtocols, targetHost)
	ruleSet.FortiGateRules = generateFortiGate(ruleSet.OpenTCPPorts, ruleSet.OpenUDPPorts, targetHost)
	ruleSet.CiscoASARules = generateCiscoASA(ruleSet.OpenTCPPorts, ruleSet.OpenUDPPorts, targetHost)

	return ruleSet
}

func generateIPTables(tcpPorts, udpPorts []int, targetHost string) string {
	if len(tcpPorts) == 0 && len(udpPorts) == 0 {
		return "# Contraband Remediation: No open egress ports detected (perimeter is hardened).\n"
	}

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# =============================================================================\n")
	b.WriteString("# Contraband Automated Remediation: Linux iptables\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("# =============================================================================\n\n")

	b.WriteString("# 1. Allow stateful established and related outbound connections\n")
	b.WriteString("iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\n")

	b.WriteString("# 2. Allow local loopback traffic\n")
	b.WriteString("iptables -A OUTPUT -o lo -j ACCEPT\n\n")

	b.WriteString("# 3. Block discovered unauthorized egress ports\n")
	for _, port := range tcpPorts {
		if targetHost != "" {
			b.WriteString(fmt.Sprintf("iptables -A OUTPUT -d %s -p tcp --dport %d -j REJECT --reject-with tcp-reset -m comment --comment \"CTRB: Block %s:%d/tcp\"\n", targetHost, port, targetHost, port))
		}
		b.WriteString(fmt.Sprintf("iptables -A OUTPUT -p tcp --dport %d -j REJECT --reject-with tcp-reset -m comment --comment \"CTRB: Block egress port %d/tcp\"\n", port, port))
	}
	for _, port := range udpPorts {
		if targetHost != "" {
			b.WriteString(fmt.Sprintf("iptables -A OUTPUT -d %s -p udp --dport %d -j DROP -m comment --comment \"CTRB: Block %s:%d/udp\"\n", targetHost, port, targetHost, port))
		}
		b.WriteString(fmt.Sprintf("iptables -A OUTPUT -p udp --dport %d -j DROP -m comment --comment \"CTRB: Block egress port %d/udp\"\n", port, port))
	}

	b.WriteString("\n# 4. Whitelist legitimate outbound services (DNS and HTTPS only)\n")
	b.WriteString("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT -m comment --comment \"Allow outbound DNS\"\n")
	b.WriteString("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT -m comment --comment \"Allow outbound DNS TCP\"\n")
	b.WriteString("iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT -m comment --comment \"Allow outbound HTTPS\"\n\n")

	b.WriteString("# 5. Default Deny Policy on OUTPUT chain\n")
	b.WriteString("iptables -P OUTPUT DROP\n")

	return b.String()
}

func generateNFTables(tcpPorts, udpPorts []int, targetHost string) string {
	if len(tcpPorts) == 0 && len(udpPorts) == 0 {
		return "# Contraband Remediation: No open egress ports detected (perimeter is hardened).\n"
	}

	var b strings.Builder
	b.WriteString("# =============================================================================\n")
	b.WriteString("# Contraband Automated Remediation: Linux nftables\n")
	b.WriteString("# =============================================================================\n\n")

	b.WriteString("table inet filter {\n")
	b.WriteString("    chain output {\n")
	b.WriteString("        type filter hook output priority 0; policy drop;\n\n")

	b.WriteString("        # Accept established and related connections\n")
	b.WriteString("        ct state established,related accept\n\n")

	b.WriteString("        # Accept loopback\n")
	b.WriteString("        oifname \"lo\" accept\n\n")

	if len(tcpPorts) > 0 {
		var portStrs []string
		for _, p := range tcpPorts {
			portStrs = append(portStrs, fmt.Sprintf("%d", p))
		}
		b.WriteString(fmt.Sprintf("        # Block open egress TCP ports\n        tcp dport { %s } reject with tcp reset comment \"CTRB: Block open egress TCP ports\"\n\n", strings.Join(portStrs, ", ")))
	}

	if len(udpPorts) > 0 {
		var portStrs []string
		for _, p := range udpPorts {
			portStrs = append(portStrs, fmt.Sprintf("%d", p))
		}
		b.WriteString(fmt.Sprintf("        # Block open egress UDP ports\n        udp dport { %s } drop comment \"CTRB: Block open egress UDP ports\"\n\n", strings.Join(portStrs, ", ")))
	}

	b.WriteString("        # Allow authorized administrative outbound ports\n")
	b.WriteString("        udp dport 53 accept comment \"Allow outbound DNS\"\n")
	b.WriteString("        tcp dport 443 accept comment \"Allow outbound HTTPS\"\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	return b.String()
}

func mapPANOSAppID(proto string) string {
	switch proto {
	case "dns_a", "dns_txt":
		return "dns-tunneling"
	case "dns_over_https":
		return "dns-over-https"
	case "dns_over_tls":
		return "dns-over-tls"
	case "smb_file", "smb_hash_capture":
		return "ms-smb"
	case "smb_quic":
		return "ms-smb-over-quic"
	case "sftp":
		return "sftp"
	case "ftp", "ftps":
		return "ftp"
	case "smtp":
		return "smtp"
	case "icmp_echo":
		return "icmp"
	case "ntp_timestamp":
		return "ntp"
	case "syslog":
		return "syslog"
	case "mqtt":
		return "mqtt"
	case "websocket_binary":
		return "websocket"
	case "grpc_protobuf":
		return "grpc"
	case "webdav":
		return "webdav"
	case "aws_s3":
		return "amazon-s3-upload"
	case "gcp_gcs":
		return "google-cloud-storage"
	case "azure_blob":
		return "azure-blob-storage"
	default:
		return proto
	}
}

func generatePANOS(tcpPorts, udpPorts []int, protocols []string, targetHost string) string {
	if len(tcpPorts) == 0 && len(udpPorts) == 0 && len(protocols) == 0 {
		return "# Contraband Remediation: No open egress vectors detected.\n"
	}

	var b strings.Builder
	b.WriteString("# =============================================================================\n")
	b.WriteString("# Contraband Automated Remediation: Palo Alto Networks PAN-OS CLI\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("# Paste into PAN-OS configuration mode: 'configure'\n")
	b.WriteString("# =============================================================================\n\n")

	// Service objects
	for _, port := range tcpPorts {
		b.WriteString(fmt.Sprintf("set service service-ctrb-tcp-%d protocol tcp port %d\n", port, port))
	}
	for _, port := range udpPorts {
		b.WriteString(fmt.Sprintf("set service service-ctrb-udp-%d protocol udp port %d\n", port, port))
	}
	b.WriteString("\n")

	// Security rules for ports
	for _, port := range tcpPorts {
		ruleName := fmt.Sprintf("CTRB-BLOCK-TCP-%d", port)
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" to untrust\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" from trust\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" source any\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" destination any\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" service service-ctrb-tcp-%d\n", ruleName, port))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" application any\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" action deny\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" log-end yes\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" description \"CTRB: Block egress port %d/tcp\"\n", ruleName, port))
		b.WriteString(fmt.Sprintf("move rulebase security rules \"%s\" top\n\n", ruleName))
	}

	// App-ID strict rules
	for _, proto := range protocols {
		appID := mapPANOSAppID(proto)
		ruleName := fmt.Sprintf("CTRB-DENY-APP-%s", proto)
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" to untrust\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" from trust\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" source any\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" destination any\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" application %s\n", ruleName, appID))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" action deny\n", ruleName))
		b.WriteString(fmt.Sprintf("set rulebase security rules \"%s\" log-end yes\n", ruleName))
		b.WriteString(fmt.Sprintf("move rulebase security rules \"%s\" top\n\n", ruleName))
	}

	b.WriteString("commit description \"Contraband egress remediation rules applied\"\n")
	return b.String()
}

func generateFortiGate(tcpPorts, udpPorts []int, targetHost string) string {
	if len(tcpPorts) == 0 && len(udpPorts) == 0 {
		return "# Contraband Remediation: No open egress ports detected.\n"
	}

	var b strings.Builder
	b.WriteString("# =============================================================================\n")
	b.WriteString("# Contraband Automated Remediation: Fortinet FortiGate CLI\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("# =============================================================================\n\n")

	b.WriteString("config firewall service custom\n")
	for _, port := range tcpPorts {
		b.WriteString(fmt.Sprintf("    edit \"CTRB_SVC_TCP_%d\"\n        set tcp-portrange %d\n        set comment \"Contraband egress port %d/tcp\"\n    next\n", port, port, port))
	}
	for _, port := range udpPorts {
		b.WriteString(fmt.Sprintf("    edit \"CTRB_SVC_UDP_%d\"\n        set udp-portrange %d\n        set comment \"Contraband egress port %d/udp\"\n    next\n", port, port, port))
	}
	b.WriteString("end\n\n")

	b.WriteString("config firewall policy\n")
	for _, port := range tcpPorts {
		b.WriteString(fmt.Sprintf("    edit 0\n        set name \"CTRB_BLOCK_TCP_%d\"\n        set srcintf \"lan\"\n        set dstintf \"wan\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set action deny\n        set schedule \"always\"\n        set service \"CTRB_SVC_TCP_%d\"\n        set logtraffic all\n        set comments \"CTRB: Block unauthorized port %d/tcp\"\n    next\n", port, port, port))
	}
	for _, port := range udpPorts {
		b.WriteString(fmt.Sprintf("    edit 0\n        set name \"CTRB_BLOCK_UDP_%d\"\n        set srcintf \"lan\"\n        set dstintf \"wan\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set action deny\n        set schedule \"always\"\n        set service \"CTRB_SVC_UDP_%d\"\n        set logtraffic all\n        set comments \"CTRB: Block unauthorized port %d/udp\"\n    next\n", port, port, port))
	}

	// Enable Strict Outbound Deep Packet & DLP Inspection
	b.WriteString("    edit 0\n        set name \"CTRB_DEEP_INSPECT\"\n        set srcintf \"lan\"\n        set dstintf \"wan\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set action accept\n        set schedule \"always\"\n        set service \"HTTPS\" \"HTTP\" \"DNS\"\n        set utm-status enable\n        set ssl-ssh-profile \"deep-inspection\"\n        set dlp-profile \"default\"\n        set av-profile \"default\"\n        set logtraffic all\n        set comments \"CTRB: Enforce deep SSL and DLP inspection\"\n    next\n")
	b.WriteString("end\n")

	return b.String()
}

func generateCiscoASA(tcpPorts, udpPorts []int, targetHost string) string {
	if len(tcpPorts) == 0 && len(udpPorts) == 0 {
		return "! Contraband Remediation: No open egress ports detected.\n"
	}

	var b strings.Builder
	b.WriteString("! =============================================================================\n")
	b.WriteString("! Contraband Automated Remediation: Cisco ASA / Firepower CLI\n")
	b.WriteString(fmt.Sprintf("! Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("! =============================================================================\n\n")

	for _, port := range tcpPorts {
		if targetHost != "" {
			b.WriteString(fmt.Sprintf("access-list OUTBOUND_FILTER extended deny tcp any host %s eq %d\n", targetHost, port))
		}
		b.WriteString(fmt.Sprintf("access-list OUTBOUND_FILTER extended deny tcp any any eq %d\n", port))
	}
	for _, port := range udpPorts {
		if targetHost != "" {
			b.WriteString(fmt.Sprintf("access-list OUTBOUND_FILTER extended deny udp any host %s eq %d\n", targetHost, port))
		}
		b.WriteString(fmt.Sprintf("access-list OUTBOUND_FILTER extended deny udp any any eq %d\n", port))
	}

	b.WriteString("\n! Whitelist authorized inspection outbound traffic\n")
	b.WriteString("access-list OUTBOUND_FILTER extended permit udp any any eq 53\n")
	b.WriteString("access-list OUTBOUND_FILTER extended permit tcp any any eq 53\n")
	b.WriteString("access-list OUTBOUND_FILTER extended permit tcp any any eq 443\n")
	b.WriteString("access-list OUTBOUND_FILTER extended deny ip any any\n\n")

	b.WriteString("! Apply access-group to inside interface\n")
	b.WriteString("access-group OUTBOUND_FILTER in interface inside\n\n")

	b.WriteString("! Modular Policy Framework (MPF) Protocol Inspection\n")
	b.WriteString("class-map CTRB_INSPECT_TRAFFIC\n  match default-inspection-traffic\n")
	b.WriteString("policy-map global_policy\n  class CTRB_INSPECT_TRAFFIC\n    inspect dns\n    inspect ftp\n    inspect http\n")

	return b.String()
}
