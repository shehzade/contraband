package listeners

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"nhooyr.io/websocket"
)

// WebSocketHandler processes incoming RFC 6455 masked binary frames and assembles chunks in ledger.
type WebSocketHandler struct {
	ledger server.Ledger
}

// NewWebSocketHandler constructs a WebSocket handler attached to the ledger.
func NewWebSocketHandler(ledger server.Ledger) *WebSocketHandler {
	return &WebSocketHandler{ledger: ledger}
}

func (h *WebSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(16 * 1024 * 1024)
	defer conn.Close(websocket.StatusInternalError, "closing")

	ctx := r.Context()
	headerHash := r.Header.Get(common.HeaderPayloadHash)

	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	}
	if ipHdr := r.Header.Get(common.HeaderClientIP); ipHdr != "" {
		clientIP = ipHdr
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		clientIP = strings.TrimSpace(parts[0])
	}

	port := 0
	if localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && localAddr != nil {
		if _, pStr, err := net.SplitHostPort(localAddr.String()); err == nil {
			port, _ = strconv.Atoi(pStr)
		}
	}
	if port == 0 && r.Host != "" {
		if _, pStr, err := net.SplitHostPort(r.Host); err == nil {
			port, _ = strconv.Atoi(pStr)
		}
	}
	if port == 0 {
		if r.TLS != nil {
			port = 443
		} else {
			port = 80
		}
	}

	clientHost := r.Header.Get(common.HeaderClientHost)
	if clientHost == "" {
		clientHost = clientIP
	}

	networkZone := r.Header.Get(common.HeaderNetworkZone)
	proto := r.Header.Get(common.HeaderProtocol)
	if proto == "" {
		proto = common.ProtoWebSocket
	} else {
		proto = common.SanitizeProtocolName(proto)
	}

	for {
		msgType, msg, err := conn.Read(ctx)
		if err != nil {
			break
		}
		var rawMsg []byte
		if msgType == websocket.MessageBinary {
			rawMsg = msg
		} else if msgType == websocket.MessageText {
			if decoded, decErr := base64.StdEncoding.DecodeString(string(msg)); decErr == nil && len(decoded) >= common.ChunkHeaderSize {
				rawMsg = decoded
			} else {
				rawMsg = msg
			}
		} else {
			continue
		}
		if len(rawMsg) < common.ChunkHeaderSize {
			continue
		}

		var hdr common.ChunkHeader
		if err := hdr.UnmarshalBinary(rawMsg[:common.ChunkHeaderSize]); err != nil {
			continue
		}

		payload := rawMsg[common.ChunkHeaderSize:]
		if uint32(len(payload)) > hdr.PayloadLen {
			payload = payload[:hdr.PayloadLen]
		}

		session, completed, err := h.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, headerHash, clientIP, proto, port, clientHost, networkZone)
		if err != nil {
			verdict := common.VerdictBlockedL7
			if errors.Is(err, server.ErrHashMismatch) || (session != nil && session.Verdict == common.VerdictBlockedDLP) {
				verdict = common.VerdictBlockedDLP
			}
			ack := common.VerificationACK{
				Status:       "ERROR",
				SessionID:    hdr.Token.String(),
				Verdict:      verdict,
				ErrorMessage: err.Error(),
			}
			data, _ := json.Marshal(ack)
			_ = conn.Write(ctx, websocket.MessageBinary, data)
			break
		}

		if completed {
			ack := common.VerificationACK{
				Status:         "OK",
				SessionID:      hdr.Token.String(),
				TotalBytes:     session.TotalBytes,
				ReceivedChunks: session.ReceivedChunks,
				TotalChunks:    session.TotalChunks,
				PayloadHash:    session.PayloadHash,
				Verdict:        session.Verdict,
			}
			data, _ := json.Marshal(ack)
			_ = conn.Write(ctx, websocket.MessageBinary, data)
			_ = conn.Close(websocket.StatusNormalClosure, "exfil complete")
			return
		}

		// Intermediate chunk ACK
		ack := common.VerificationACK{
			Status:         "OK",
			SessionID:      hdr.Token.String(),
			Sequence:       hdr.Sequence,
			ReceivedChunks: session.ReceivedChunks,
			TotalChunks:    session.TotalChunks,
			Verdict:        "IN_PROGRESS",
		}
		data, _ := json.Marshal(ack)
		_ = conn.Write(ctx, websocket.MessageBinary, data)
	}
}
