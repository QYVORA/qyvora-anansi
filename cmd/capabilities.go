package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-anansi/internal/capabilities"
	"github.com/QYVORA/qyvora-anansi/internal/output"
)

func newCapabilitiesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "capabilities",
		Aliases: []string{"caps"},
		Short:   "List ANANSI's machine-readable tool contract",
		Args:    usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc := capabilities.Build(defaultModules)
			w := cmd.OutOrStdout()
			switch strings.ToLower(flagOut) {
			case "json":
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(doc)
			case "yaml":
				return output.WriteYAML(w, doc)
			case "", "terminal", "table", "text":
				fmt.Fprintf(w, "%-38s %-24s %-10s %s\n", "ID", "NAME", "RISK", "AUTH")
				for _, t := range doc.Capabilities {
					auth := "no"
					if t.AuthRequired {
						auth = "yes"
					}
					fmt.Fprintf(w, "%-38s %-24s %-10s %s\n", t.ID, t.Name, t.Risk, auth)
				}
				return nil
			default:
				return &usageError{fmt.Errorf("invalid output format %q for capabilities (terminal, json, yaml)", flagOut)}
			}
		},
	}
}
