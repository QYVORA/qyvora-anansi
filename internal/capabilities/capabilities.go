// Package capabilities advertises ANANSI's machine-readable tool contract.
package capabilities

import (
	"sort"

	"github.com/QYVORA/qyvora-anansi/internal/events"
	"github.com/QYVORA/qyvora-anansi/internal/exploit"
	"github.com/QYVORA/qyvora-anansi/internal/version"
)

// ContractVersion is the capability document schema version.
const ContractVersion = "1.0"

// Tool is one capability an orchestrator can call.
type Tool struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Framework      string   `json:"framework"`
	Category       string   `json:"category"`
	Output         []string `json:"output,omitempty"`
	Risk           string   `json:"risk"`
	NoiseLevel     string   `json:"noise_level,omitempty"`
	AuthRequired   bool     `json:"authorization_required"`
	Confirm        bool     `json:"confirmation_required"`
	Reversible     bool     `json:"reversible"`
	ChangesState   bool     `json:"changes_state"`
	Targets        []string `json:"target_types,omitempty"`
	Duration       string   `json:"duration,omitempty"`
	CapabilityType string   `json:"capability,omitempty"`
}

// Document is the capability manifest.
type Document struct {
	Framework          string   `json:"framework"`
	Version            string   `json:"version"`
	ContractVersion    string   `json:"contract_version"`
	OutputFormats      []string `json:"output_formats"`
	ExitCodes          []string `json:"exit_codes"`
	EventVerbs         []string `json:"event_verbs"`
	AuthorizationModel string   `json:"authorization_model"`
	Capabilities       []Tool   `json:"capabilities"`
	Commands           []Tool   `json:"commands"`
}

// Build returns the current capability document.
func Build(scanModules []string) Document {
	mods := append([]string(nil), scanModules...)
	sort.Strings(mods)

	tools := []Tool{{
		ID:             "anansi.scan",
		Name:           "Web application assessment",
		Description:    "Run the configured web assessment modules against an authorized target.",
		Framework:      "anansi",
		Category:       "assessment",
		Output:         []string{"report", "findings", "events"},
		Risk:           "S2",
		NoiseLevel:     "moderate",
		AuthRequired:   true,
		Confirm:        false,
		Reversible:     true,
		ChangesState:   false,
		Targets:        []string{"url", "domain"},
		Duration:       "minutes",
		CapabilityType: "scan",
	}}

	for _, m := range exploit.DefaultRegistry.All() {
		meta := m.Meta()
		tools = append(tools, Tool{
			ID:             "anansi.exploit." + meta.ID,
			Name:           meta.Name,
			Description:    meta.Description,
			Framework:      "anansi",
			Category:       meta.Category,
			Output:         []string{"exploit_result", "evidence"},
			Risk:           meta.Risk,
			NoiseLevel:     meta.NoiseLevel,
			AuthRequired:   meta.NeedsAuth,
			Confirm:        meta.NeedsAuth,
			Reversible:     true,
			ChangesState:   false,
			Targets:        []string{"url", "domain"},
			Duration:       "seconds",
			CapabilityType: "exploit",
		})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })

	return Document{
		Framework:          version.Framework,
		Version:            version.GetInfo().Version,
		ContractVersion:    ContractVersion,
		OutputFormats:      []string{"terminal", "json", "yaml", "markdown", "html"},
		ExitCodes:          []string{"0 success", "1 runtime", "2 usage", "3 unsupported", "130 interrupted"},
		EventVerbs:         []string{events.ScanStarted, events.ScanCompleted, events.PhaseStarted, events.PhaseCompleted, events.FindingDiscovered, events.ExploitStarted, events.ExploitCompleted, events.EvidenceCaptured},
		AuthorizationModel: "Explicit --authorized is required for exploit modules; scans must target systems the operator is authorized to test.",
		Capabilities:       tools,
		Commands:           tools,
	}
}
