package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEmitterWritesSchemaCompliantJSONL(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "anansi-test")
	e.Info("anansi", ScanStarted, map[string]any{"target": "example.com"})
	e.Warn("anansi", Warning, map[string]any{"message": "slow phase"})
	e.Fail("anansi", Error, map[string]any{"message": "boom"})

	sc := bufio.NewScanner(&buf)
	var got []Event
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal %q: %v", sc.Text(), err)
		}
		got = append(got, ev)
	}
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}

	if got[0].SchemaVersion != SchemaVersion || got[0].ExecutionID != "anansi-test" || got[0].Framework != "anansi" {
		t.Errorf("first event envelope wrong: %+v", got[0])
	}
	if got[0].Level != LevelInfo || got[0].Event != ScanStarted {
		t.Errorf("first event = %s/%s", got[0].Level, got[0].Event)
	}
	if got[1].Level != LevelWarning || got[2].Level != LevelError {
		t.Errorf("levels = %s,%s,%s", got[0].Level, got[1].Level, got[2].Level)
	}
	if got[0].Data["target"] != "example.com" {
		t.Errorf("data = %v", got[0].Data)
	}
}

func TestEmitterNilSafe(t *testing.T) {
	var e *Emitter
	e.Info("anansi", ScanStarted, nil) // must not panic
	var buf bytes.Buffer
	ne := New(&buf, "x")
	ne.Emit("anansi", LevelInfo, ScanStarted, nil)
	if !strings.Contains(buf.String(), ScanStarted) {
		t.Error("expected scan.started in stream")
	}
}

func TestEmitterConcurrentSafe(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "anansi-race")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				e.Info("anansi", FindingDiscovered, map[string]any{"n": j})
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if n := strings.Count(buf.String(), "\n"); n != 400 {
		t.Errorf("wrote %d lines, want 400", n)
	}
}

func TestCloseIdempotent(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "x")
	e.Close()
	e.Close() // must not panic or double-close the writer
	e.Info("anansi", ScanStarted, nil)
	if buf.Len() != 0 {
		t.Error("emitter should no-op after Close")
	}
}
