// Package events implements the canonical QYVORA JSONL event stream. Every
// framework that participates in the shared contract emits the same event
// shape (schema_version, timestamp, execution_id, framework, level, event,
// data), one JSON object per line, so agents, CI pipelines and the future
// orchestrator can consume any framework's stream uniformly.
package events

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// SchemaVersion is the event schema version every emitted event carries.
const SchemaVersion = "1.0"

// Event names. The dotted namespace is stable across frameworks so an agent
// can key on scan.started / finding.discovered regardless of which framework
// produced the stream.
const (
	ScanStarted       = "scan.started"
	ScanCompleted     = "scan.completed"
	PhaseStarted      = "phase.started"
	PhaseCompleted    = "phase.completed"
	FindingDiscovered = "finding.discovered"
	Warning           = "warning"
	Error             = "error"
	ReportGenerated   = "report.generated"
	ScanInterrupted   = "scan.interrupted"

	// Exploitation lifecycle events, emitted by the PoC/exploitation engine.
	// The dotted names are part of the shared contract across all QYVORA
	// frameworks so a stream consumer can key on exploit.* uniformly.
	ExploitSelected  = "exploit.selected"
	ExploitValidated = "exploit.validated"
	ExploitStarted   = "exploit.started"
	ExploitCompleted = "exploit.completed"
	ExploitFailed    = "exploit.failed"
	EvidenceCaptured = "evidence.captured"
)

// Levels classify how an event should be treated by a consumer.
const (
	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Event is one line of the JSONL stream.
type Event struct {
	SchemaVersion string         `json:"schema_version"`
	Timestamp     time.Time      `json:"timestamp"`
	ExecutionID   string         `json:"execution_id"`
	Framework     string         `json:"framework"`
	Level         string         `json:"level"`
	Event         string         `json:"event"`
	Data          map[string]any `json:"data,omitempty"`
}

// Emitter writes Events as JSON Lines to an io.Writer. It is safe for
// concurrent use because phase workers emit from multiple goroutines.
type Emitter struct {
	mu     sync.Mutex
	w      io.Writer
	execID string
}

// New returns an Emitter writing JSONL to w. Every event carries execID as
// its execution_id so a stream can be grouped by run.
func New(w io.Writer, execID string) *Emitter {
	return &Emitter{w: w, execID: execID}
}

// Emit writes a single event, tagged with the framework name.
func (e *Emitter) Emit(framework, level, name string, data map[string]any) {
	if e == nil || e.w == nil {
		return
	}
	line, err := json.Marshal(Event{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC(),
		ExecutionID:   e.execID,
		Framework:     framework,
		Level:         level,
		Event:         name,
		Data:          data,
	})
	if err != nil {
		return
	}
	line = append(line, '\n')
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.w.Write(line)
}

// Info emits an informational event.
func (e *Emitter) Info(framework, name string, data map[string]any) {
	e.Emit(framework, LevelInfo, name, data)
}

// Warn emits a warning event.
func (e *Emitter) Warn(framework, name string, data map[string]any) {
	e.Emit(framework, LevelWarning, name, data)
}

// Fail emits an error event.
func (e *Emitter) Fail(framework, name string, data map[string]any) {
	e.Emit(framework, LevelError, name, data)
}

// Close flushes and closes the underlying writer when it is a closable file
// (not stdout/stderr). It is safe to call multiple times.
func (e *Emitter) Close() {
	if e == nil || e.w == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.w.(io.Closer); ok {
		_ = c.Close()
	}
	e.w = nil
}
