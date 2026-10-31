package output

import (
	"encoding/json"
	"io"

	"go.yaml.in/yaml/v3"
)

// WriteYAML encodes v as YAML using a JSON round-trip so the json tags on the
// report types define the YAML keys, matching the JSON contract.
func WriteYAML(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	return yaml.NewEncoder(w).Encode(raw)
}
