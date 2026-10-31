package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilitiesJSON(t *testing.T) {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"capabilities", "-o", "json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	var doc struct {
		Framework     string   `json:"framework"`
		OutputFormats []string `json:"output_formats"`
		Capabilities  []any    `json:"capabilities"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v: %s", err, buf.String())
	}
	if doc.Framework != "anansi" {
		t.Errorf("framework = %q, want anansi", doc.Framework)
	}
	if len(doc.Capabilities) == 0 {
		t.Error("capabilities document is empty")
	}
	if strings.Join(doc.OutputFormats, ",") != "terminal,json,yaml,markdown,html" {
		t.Errorf("output_formats = %v", doc.OutputFormats)
	}
}

func TestCapabilitiesYAML(t *testing.T) {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"capabilities", "-o", "yaml"})
	if err := root.Execute(); err != nil {
		t.Fatalf("capabilities yaml: %v", err)
	}
	if !strings.Contains(buf.String(), "framework: anansi") {
		t.Errorf("capabilities yaml = %q", buf.String())
	}
}
