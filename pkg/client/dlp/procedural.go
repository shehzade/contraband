package dlp

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// GenerateCarrierRecord produces a serialized record embedding synthetic DLP data in the specified carrier format.
func GenerateCarrierRecord(carrier string, dlpType string, r *rand.Rand, domain string) []byte {
	if domain == "" {
		domain = "acme-corp.internal"
	}

	switch strings.ToLower(carrier) {
	case "csv":
		return generateCSVRecord(dlpType, r, domain)
	case "json":
		return generateJSONRecord(dlpType, r, domain)
	case "sql":
		return generateSQLRecord(dlpType, r, domain)
	case "email":
		return generateEmailRecord(dlpType, r, domain)
	case "syslog":
		return generateSyslogRecord(dlpType, r, domain)
	case "noise":
		return generateNoiseRecord(dlpType, r, domain)
	default:
		return generateRawRecord(dlpType, r, domain)
	}
}

func generateCSVRecord(dlpType string, r *rand.Rand, domain string) []byte {
	emp := GenerateEmployeeProfile(r, domain)
	cc, _ := GenerateCreditCard(BrandVisa, r, FormatHyphenated)
	// Return a single CSV row
	line := fmt.Sprintf("%s,\"%s %s\",%s,%s,%02d/%02d,%s,%s,%d\n",
		emp.ID, emp.FirstName, emp.LastName, emp.SSN, cc.Formatted, cc.ExpMonth, cc.ExpYear, emp.Department, emp.Email, emp.Salary)
	return []byte(line)
}

func generateJSONRecord(dlpType string, r *rand.Rand, domain string) []byte {
	emp := GenerateEmployeeProfile(r, domain)
	cc, _ := GenerateCreditCard(BrandMasterCard, r, FormatHyphenated)
	t := time.Unix(1772841600+r.Int63n(86400*30), int64(r.Intn(1000000000))).UTC()
	data := map[string]any{
		"event_id":    fmt.Sprintf("evt_%08x", r.Uint32()),
		"timestamp":   t.Format(time.RFC3339Nano),
		"employee":    emp,
		"billing_pan": cc.Formatted,
		"card_exp":    fmt.Sprintf("%02d/%02d", cc.ExpMonth, cc.ExpYear),
		"cvv":         cc.CVV,
	}
	b, _ := json.Marshal(data)
	return append(b, '\n')
}

func generateSQLRecord(dlpType string, r *rand.Rand, domain string) []byte {
	emp := GenerateEmployeeProfile(r, domain)
	cc, _ := GenerateCreditCard(BrandAmex, r, FormatRaw)
	line := fmt.Sprintf("INSERT INTO corporate_records (emp_id, first_name, last_name, email, ssn, pan, salary) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', %d);\n",
		emp.ID, emp.FirstName, emp.LastName, emp.Email, emp.SSN, cc.Number, emp.Salary)
	return []byte(line)
}

func generateEmailRecord(dlpType string, r *rand.Rand, domain string) []byte {
	emp := GenerateEmployeeProfile(r, domain)
	cc, _ := GenerateCreditCard(BrandVisa, r, FormatSpaceDelimited)
	ak, sk := GenerateAWSCredentials(r)
	t := time.Unix(1772841600+r.Int63n(86400*30), 0).UTC()

	email := fmt.Sprintf("From: %s\r\nTo: compliance-audit@%s\r\nSubject: Quarterly Verification - %s\r\nDate: %s\r\nMessage-ID: <%08x@%s>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHi Team,\r\n\r\nPlease review the attached employee billing record for %s %s (SSN: %s).\r\nCorporate Card on file: %s (Exp: %02d/%02d).\r\nStaging AWS Access: %s (Secret: %s)\r\n\r\nRegards,\r\n%s %s\r\n%s Department\r\n---\r\n\r\n",
		emp.Email, domain, emp.ID, t.Format(time.RFC1123Z), r.Uint32(), domain,
		emp.FirstName, emp.LastName, emp.SSN, cc.Formatted, cc.ExpMonth, cc.ExpYear,
		ak, sk, emp.FirstName, emp.LastName, emp.Department)
	return []byte(email)
}

func generateSyslogRecord(dlpType string, r *rand.Rand, domain string) []byte {
	emp := GenerateEmployeeProfile(r, domain)
	t := time.Unix(1772841600+r.Int63n(86400*30), int64(r.Intn(1000000000))).UTC()
	timestamp := t.Format(time.RFC3339Nano)
	line := fmt.Sprintf("<134>1 %s auth-server.internal app - [authEvent@41113 ssn=\"%s\" user=\"%s\" dept=\"%s\"] Authentication granted for %s\n",
		timestamp, emp.SSN, emp.Email, emp.Department, emp.ID)
	return []byte(line)
}

func generateNoiseRecord(dlpType string, r *rand.Rand, domain string) []byte {
	rawDLP := strings.TrimRight(string(generateRawRecord(dlpType, r, domain)), "\r\n")

	preLen := 16 + r.Intn(32)
	postLen := 16 + r.Intn(32)

	preBytes := make([]byte, preLen)
	r.Read(preBytes)
	postBytes := make([]byte, postLen)
	r.Read(postBytes)

	var prefix, suffix string
	if r.Intn(2) == 0 {
		prefix = hex.EncodeToString(preBytes)
	} else {
		prefix = base64.StdEncoding.EncodeToString(preBytes)
	}

	if r.Intn(2) == 0 {
		suffix = hex.EncodeToString(postBytes)
	} else {
		suffix = base64.StdEncoding.EncodeToString(postBytes)
	}

	return []byte(fmt.Sprintf("%s %s %s\n", prefix, rawDLP, suffix))
}

func generateRawRecord(dlpType string, r *rand.Rand, domain string) []byte {
	switch dlpType {
	case "pci":
		cc, _ := GenerateCreditCard(BrandVisa, r, FormatHyphenated)
		return []byte(fmt.Sprintf("%s %02d/%02d %s %s\n", cc.Formatted, cc.ExpMonth, cc.ExpYear, cc.CVV, cc.CardholderName))
	case "ssn":
		return []byte(GenerateSSN(r, true) + "\n")
	case "keys":
		ak, sk := GenerateAWSCredentials(r)
		ghp := GenerateGitHubPAT(r, false)
		aiza := GenerateGoogleAIzaKey(r)
		azure := GenerateAzureKey(r)
		slack := GenerateSlackToken(r, true)
		return []byte(fmt.Sprintf("AWS_KEY=%s AWS_SECRET=%s GHP=%s AIZA=%s AZURE=%s SLACK=%s\n", ak, sk, ghp, aiza, azure, slack))
	case "hipaa":
		med := GenerateMedicalRecord(r)
		return []byte(FormatHL7v2(med))
	default:
		emp := GenerateEmployeeProfile(r, domain)
		return []byte(fmt.Sprintf("%s|%s %s|%s|%s\n", emp.ID, emp.FirstName, emp.LastName, emp.Email, emp.SSN))
	}
}
