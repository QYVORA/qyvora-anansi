// Package cmd — update.go implements `anansi updates`: check the running
// version against ANANSI's official QYVORA GitHub releases and install a
// newer release after cryptographic verification. See internal/selfupdate
// for the shared flow.
package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-anansi-cli/internal/selfupdate"
)

// releaseConfig pins the updater to ANANSI's official release source: the
// QYVORA/qyvora-anansi-cli GitHub repository and nothing else.
func releaseConfig() selfupdate.Config {
	return selfupdate.Config{
		Owner:          "QYVORA",
		Repo:           "qyvora-anansi-cli",
		ToolName:       "Anansi",
		CurrentVersion: func() string { return Version },
		ArtifactName: func(goos, goarch string) string {
			// The release pipeline names darwin assets with "macos".
			os := goos
			if os == "darwin" {
				os = "macos"
			}
			name := fmt.Sprintf("anansi-%s-%s", os, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			return name
		},
		ChecksumAsset: func(string) string { return "checksums.txt" },
	}
}

var updatesCmd = &cobra.Command{
	Use:     "updates",
	Aliases: []string{"update"},
	Short:   "Update the ANANSI CLI from official QYVORA releases",
	Long: `Check for a newer ANANSI release and install it.

The installed version is compared against the latest official QYVORA
GitHub release for this platform. If an update exists, it is downloaded,
verified against the release checksums.txt SHA-256 manifest, and swapped in
atomically; the previous binary is never touched unless every step succeeds.

No Go toolchain, Git, or source checkout is required.`,
	Args: cobra.NoArgs,
	// Update failures are runtime conditions, not usage mistakes: report the
	// reason without burying it under the full usage block.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		opts := selfupdate.Options{Out: cmd.OutOrStdout()}
		jsonMode := strings.EqualFold(flagOut, "json")
		if jsonMode {
			opts.Quiet = true
		}

		res, err := selfupdate.Run(cmd.Context(), releaseConfig(), opts)
		if jsonMode {
			payload := map[string]string{
				"framework": "anansi",
				"command":   "updates",
				"installed": res.Current,
				"latest":    res.Latest,
			}
			switch res.Status {
			case selfupdate.StatusUpdated:
				payload["status"] = "updated"
				payload["path"] = res.Path
			case selfupdate.StatusCurrent:
				payload["status"] = "current"
			case selfupdate.StatusNewerInstalled:
				payload["status"] = "newer_installed"
			}
			if err != nil {
				payload["status"] = "failed"
				payload["error"] = err.Error()
				var ue *selfupdate.UpdateError
				if errors.As(err, &ue) {
					payload["kind"] = string(ue.Kind)
				}
			}
			data, jerr := json.Marshal(payload)
			if jerr != nil {
				return jerr
			}
			cmd.Println(string(data))
		}

		return enrichUpdateError(err)
	},
}

// enrichUpdateError keeps failures clean for ordinary users while expanding
// permission denials into actionable multi-line guidance.
func enrichUpdateError(err error) error {
	if err == nil {
		return nil
	}
	var ue *selfupdate.UpdateError
	if !errors.As(err, &ue) {
		return err
	}
	if ue.Kind == selfupdate.KindPermission && ue.Path() != "" {
		return fmt.Errorf("%s\n\n%s", ue.Error(), selfupdate.PermissionHint("anansi", ue.Path()))
	}
	return ue
}
