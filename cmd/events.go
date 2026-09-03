package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/events"
)

// flagEvents is bound to --events by root.go's init.
var flagEvents string

// openEventsWriter resolves the --events destination spec into a writer:
//
//	""        disabled (no event stream)
//	"stdout"  JSONL to stdout (machine output; do not mix with human reports)
//	"stderr"  JSONL to stderr (the default choice for interactive use)
//	anything else is a file path, created/truncated with 0600
//
// The returned close function must be called when the stream is done; it is
// nil when the stream is disabled or a fixed console.
func openEventsWriter(spec string) (io.Writer, func() error, error) {
	switch spec {
	case "":
		return nil, nil, nil
	case "stdout":
		return os.Stdout, nil, nil
	case "stderr":
		return os.Stderr, nil, nil
	}
	f, err := os.OpenFile(spec, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("events file: %w", err)
	}
	return f, f.Close, nil
}

// executionID returns a per-run identifier so a stream can be grouped by
// execution, mirroring the shared QYVORA contract.
func executionID() string {
	return fmt.Sprintf("anansi-%d", time.Now().UnixNano())
}

// newEventsEmitter builds an emitter bound to the --events destination. It
// returns (nil, nil, nil) when the stream is disabled.
func newEventsEmitter() (*events.Emitter, func(), error) {
	w, closeFn, err := openEventsWriter(flagEvents)
	if err != nil {
		return nil, nil, err
	}
	if w == nil {
		return nil, nil, nil
	}
	return events.New(w, executionID()), func() {
		if closeFn != nil {
			_ = closeFn()
		}
	}, nil
}
