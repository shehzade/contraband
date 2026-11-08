package listeners

import (
	"context"

	"github.com/shehzade/contraband/pkg/server"
)

// ProtocolListener represents a dedicated L7 protocol service implementation.
type ProtocolListener interface {
	Name() string
	Protocol() string
	Ports() []int
	Start(ctx context.Context, ledger server.Ledger) error
	Stop() error
}
