package dlp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"strings"
)

// GenerateAWSCredentials generates an Access Key ID and Secret Key.
func GenerateAWSCredentials(r *mrand.Rand) (string, string) {
	const idCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var id [16]byte
	for i := 0; i < 16; i++ {
		id[i] = idCharset[r.Intn(len(idCharset))]
	}
	accessKey := "AKIA" + string(id[:])

	const secretCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"
	var secret [40]byte
	for i := 0; i < 40; i++ {
		secret[i] = secretCharset[r.Intn(len(secretCharset))]
	}
	return accessKey, string(secret[:])
}

// GenerateGitHubPAT generates classic or fine-grained GitHub tokens.
func GenerateGitHubPAT(r *mrand.Rand, fineGrained bool) string {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	if !fineGrained {
		var b [36]byte
		for i := 0; i < 36; i++ {
			b[i] = charset[r.Intn(len(charset))]
		}
		return "ghp_" + string(b[:])
	}
	var b [82]byte
	for i := 0; i < 82; i++ {
		b[i] = charset[r.Intn(len(charset))]
	}
	return "github_pat_" + string(b[:])
}

// GenerateSlackToken generates xoxb bot token or xoxp user token.
func GenerateSlackToken(r *mrand.Rand, isBot bool) string {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	d1 := 100000000000 + r.Int63n(899999999999)
	d2 := 1000000000000 + r.Int63n(8999999999999)
	if isBot {
		var b [24]byte
		for i := 0; i < 24; i++ {
			b[i] = charset[r.Intn(len(charset))]
		}
		return fmt.Sprintf("xoxb-%d-%d-%s", d1, d2, string(b[:]))
	}
	d3 := 1000000000000 + r.Int63n(8999999999999)
	var b [30]byte
	for i := 0; i < 30; i++ {
		b[i] = charset[r.Intn(len(charset))]
	}
	return fmt.Sprintf("xoxp-%d-%d-%d-%s", d1, d2, d3, string(b[:]))
}

// GenerateRSAPrivateKeyBlock creates an authentic formatted PEM block.
func GenerateRSAPrivateKeyBlock(r *mrand.Rand) string {
	raw := make([]byte, 1192) // typical DER size for 2048-bit RSA key
	for i := range raw {
		raw[i] = byte(r.Intn(256))
	}
	// Set valid ASN.1 sequence headers
	raw[0] = 0x30
	raw[1] = 0x82
	b64 := base64.StdEncoding.EncodeToString(raw)

	var sb strings.Builder
	sb.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end] + "\n")
	}
	sb.WriteString("-----END RSA PRIVATE KEY-----\n")
	return sb.String()
}

// GenerateGoogleAIzaKey generates a valid 39-character Google API key.
func GenerateGoogleAIzaKey(r *mrand.Rand) string {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"
	var b [35]byte
	for i := 0; i < 35; i++ {
		b[i] = charset[r.Intn(len(charset))]
	}
	return "AIza" + string(b[:])
}

// GenerateAzureKey generates an authentic 88-character Azure Base64 Storage Key (64 random bytes).
func GenerateAzureKey(r *mrand.Rand) string {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(r.Intn(256))
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// GenerateAzureConnectionString generates an authentic Azure Storage Connection String.
func GenerateAzureConnectionString(r *mrand.Rand, accountName string) string {
	if accountName == "" {
		accountName = fmt.Sprintf("storage%06d", r.Intn(1000000))
	}
	key := GenerateAzureKey(r)
	return fmt.Sprintf("DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net", accountName, key)
}

// GenerateOpenAIToken generates an OpenAI project key.
func GenerateOpenAIToken(r *mrand.Rand) string {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"
	var b [48]byte
	for i := 0; i < 48; i++ {
		b[i] = charset[r.Intn(len(charset))]
	}
	return "sk-proj-" + string(b[:])
}

// GenerateAnthropicToken generates an Anthropic API key.
func GenerateAnthropicToken(r *mrand.Rand) string {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"
	var b [88]byte
	for i := 0; i < 88; i++ {
		b[i] = charset[r.Intn(len(charset))]
	}
	return "sk-ant-api03-" + string(b[:])
}

// GenerateGCPServiceAccountKey generates an authentic GCP Service Account JSON keyfile.
func GenerateGCPServiceAccountKey(r *mrand.Rand, projectID string) (string, error) {
	if projectID == "" {
		projectID = fmt.Sprintf("corp-prod-%05d", r.Intn(100000))
	}
	keyID := fmt.Sprintf("%040x", r.Uint64())
	pemKey := GenerateRSAPrivateKeyBlock(r)
	clientEmail := fmt.Sprintf("sa-contraband@%s.iam.gserviceaccount.com", projectID)
	clientID := fmt.Sprintf("1%020d", r.Int63n(899999999999999999))

	keyMap := map[string]string{
		"type":                        "service_account",
		"project_id":                  projectID,
		"private_key_id":              keyID,
		"private_key":                 pemKey,
		"client_email":                clientEmail,
		"client_id":                   clientID,
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        fmt.Sprintf("https://www.googleapis.com/robot/v1/metadata/x509/%s", clientEmail),
	}
	b, err := json.MarshalIndent(keyMap, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
