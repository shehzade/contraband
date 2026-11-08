package listeners

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// GRPCServerListener implements ProtocolListener for gRPC exfiltration over HTTP/2 and uTLS.
type GRPCServerListener struct {
	mu         sync.Mutex
	bindAddr   string
	ports      []int
	boundPorts []int
	tlsConfig  *tls.Config
	ledger     server.Ledger
	grpcServer *grpc.Server
	listeners  []net.Listener
	cancel     context.CancelFunc
	closed     bool
}

// NewGRPCServerListener constructs a gRPC exfiltration listener.
func NewGRPCServerListener(bindAddr string, ports []int, tlsConfig *tls.Config) *GRPCServerListener {
	if len(ports) == 0 {
		ports = []int{443, 50051}
	}
	return &GRPCServerListener{
		bindAddr:  bindAddr,
		ports:     ports,
		tlsConfig: tlsConfig,
	}
}

func (l *GRPCServerListener) Name() string {
	return "grpc_server"
}

func (l *GRPCServerListener) Protocol() string {
	return common.ProtoGRPC
}

func (l *GRPCServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.boundPorts) > 0 {
		return l.boundPorts
	}
	return l.ports
}

// Start binds listeners and starts the gRPC server.
func (l *GRPCServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("grpc listener already stopped")
	}

	l.ledger = ledger
	ctx, l.cancel = context.WithCancel(ctx)

	var opts []grpc.ServerOption
	if l.tlsConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(l.tlsConfig)))
	}

	l.grpcServer = grpc.NewServer(opts...)
	proto.RegisterExfilServiceServer(l.grpcServer, &exfilGRPCService{ledger: ledger})

	for _, port := range l.ports {
		addr := fmt.Sprintf("%s:%d", l.bindAddr, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind grpc port %d: %w", port, err)
		}
		l.listeners = append(l.listeners, ln)
		l.boundPorts = append(l.boundPorts, ln.Addr().(*net.TCPAddr).Port)

		go func(listener net.Listener) {
			_ = l.grpcServer.Serve(listener)
		}(ln)
	}

	return nil
}

func (l *GRPCServerListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopInternal()
}

func (l *GRPCServerListener) stopInternal() error {
	if l.closed {
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}
	if l.grpcServer != nil {
		l.grpcServer.GracefulStop()
	}
	for _, ln := range l.listeners {
		_ = ln.Close()
	}
	l.listeners = nil
	return nil
}

type exfilGRPCService struct {
	proto.UnimplementedExfilServiceServer
	ledger server.Ledger
}

func extractGRPCMeta(ctx context.Context) (clientIP, clientHost, networkZone, protoName string, port int) {
	clientIP = ""
	port = 50051
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			clientIP = host
		} else {
			clientIP = p.Addr.String()
		}
	}
	clientHost = clientIP
	protoName = common.ProtoGRPC
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(strings.ToLower(common.HeaderClientHost)); len(vals) > 0 && vals[0] != "" {
			clientHost = vals[0]
		}
		if vals := md.Get(strings.ToLower(common.HeaderNetworkZone)); len(vals) > 0 && vals[0] != "" {
			networkZone = vals[0]
		}
		if vals := md.Get(strings.ToLower(common.HeaderProtocol)); len(vals) > 0 && vals[0] != "" {
			protoName = common.SanitizeProtocolName(vals[0])
		}
	}
	return
}

func (s *exfilGRPCService) UploadChunk(ctx context.Context, req *proto.ChunkRequest) (*proto.ChunkResponse, error) {
	if len(req.Token) != 16 {
		return &proto.ChunkResponse{
			Success:      false,
			ErrorMessage: "invalid session token: must be 16 bytes",
		}, nil
	}

	var token common.SessionToken
	copy(token[:], req.Token)

	clientIP, clientHost, networkZone, protoName, port := extractGRPCMeta(ctx)
	session, completed, err := s.ledger.AssembleChunkWithMeta(token, req.Sequence, req.TotalChunks, req.Payload, req.ExpectedHash, clientIP, protoName, port, clientHost, networkZone)
	if err != nil {
		verdict := "BLOCKED_L7"
		if errors.Is(err, server.ErrHashMismatch) || (session != nil && session.Verdict == common.VerdictBlockedDLP) {
			verdict = string(common.VerdictBlockedDLP)
		}
		return &proto.ChunkResponse{
			Success:      false,
			SessionId:    token.String(),
			Verdict:      verdict,
			ErrorMessage: err.Error(),
		}, nil
	}

	verdict := "IN_PROGRESS"
	if completed {
		verdict = string(session.Verdict)
	}

	return &proto.ChunkResponse{
		Success:     true,
		SessionId:   token.String(),
		TotalBytes:  session.TotalBytes,
		PayloadHash: session.PayloadHash,
		Verdict:     verdict,
	}, nil
}

func (s *exfilGRPCService) UploadStream(stream proto.ExfilService_UploadStreamServer) error {
	var lastToken common.SessionToken
	var lastSession *common.Session
	var isCompleted bool
	var lastErr error

	clientIP, clientHost, networkZone, protoName, port := extractGRPCMeta(stream.Context())

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(req.Token) == 16 {
			copy(lastToken[:], req.Token)
		}

		session, completed, err := s.ledger.AssembleChunkWithMeta(lastToken, req.Sequence, req.TotalChunks, req.Payload, req.ExpectedHash, clientIP, protoName, port, clientHost, networkZone)
		if err != nil {
			lastErr = err
			break
		}
		lastSession = session
		isCompleted = completed
	}

	if lastErr != nil {
		verdict := "BLOCKED_L7"
		if errors.Is(lastErr, server.ErrHashMismatch) || (lastSession != nil && lastSession.Verdict == common.VerdictBlockedDLP) {
			verdict = string(common.VerdictBlockedDLP)
		}
		return stream.SendAndClose(&proto.ChunkResponse{
			Success:      false,
			SessionId:    lastToken.String(),
			Verdict:      verdict,
			ErrorMessage: lastErr.Error(),
		})
	}

	verdict := "IN_PROGRESS"
	var totalBytes int64
	var payloadHash string
	if lastSession != nil {
		totalBytes = lastSession.TotalBytes
		payloadHash = lastSession.PayloadHash
		if isCompleted {
			verdict = string(lastSession.Verdict)
		}
	}

	return stream.SendAndClose(&proto.ChunkResponse{
		Success:     true,
		SessionId:   lastToken.String(),
		TotalBytes:  totalBytes,
		PayloadHash: payloadHash,
		Verdict:     verdict,
	})
}
