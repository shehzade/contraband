package dlp

import (
	"bytes"
	"io"
	"math/rand"
	"time"
)

// Generator provides batch and streaming synthetic DLP generation.
type Generator struct {
	cfg GeneratorConfig
	rng *rand.Rand
}

// NewGenerator returns a new Generator instance with the given configuration.
func NewGenerator(cfg GeneratorConfig) *Generator {
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &Generator{
		cfg: cfg,
		rng: rand.New(rand.NewSource(seed)),
	}
}

// GeneratePayload generates a fixed-size payload into a byte slice.
func (g *Generator) GeneratePayload(size int64) ([]byte, error) {
	streamer := NewDLPStreamer(size, g.cfg)
	defer streamer.Close()

	var buf bytes.Buffer
	_, err := io.Copy(&buf, streamer)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf.Bytes(), nil
}

// StreamPayload returns an io.Reader that streams the configured volume of DLP data.
func (g *Generator) StreamPayload(size int64) *DLPStreamer {
	return NewDLPStreamer(size, g.cfg)
}
