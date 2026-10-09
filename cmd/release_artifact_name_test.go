package cmd

import (
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-anansi/internal/selfupdate"
)

// TestReleaseArtifactName pins the release asset naming contract for anansi.
//
// The same names are produced in three places that can drift apart: the
// release workflow (.github/workflows/release.yml), install.sh, and this
// updater. When they disagree the updater requests an asset that no release
// has ever published and the user is told to reinstall by hand.
//
// Canonical: anansi_<version>_<linux|macos|windows|android>_<arch>.tar.gz
// (zip on windows), where <version> is the tag with its leading "v" stripped.
// The cases that have actually been wrong in this ecosystem:
//
//   - macOS assets are published as "macos", but Go reports GOOS "darwin".
//   - Android/Termux is its own target: GOOS is "android" for a GOOS=android
//     build and the asset is "anansi_<version>_android_arm64.tar.gz". A
//     linux/arm64 asset must never be substituted, because Android's bionic
//     linker rejects an ET_EXEC binary with "unexpected e_type: 2".
//   - The version is part of the asset name. GoReleaser strips the "v", so a
//     tag of "v1.1.0" yields "anansi_1.1.0_...".
func TestReleaseArtifactName(t *testing.T) {
	cfg := releaseConfig()
	if cfg.ArtifactName == nil {
		t.Fatal("ArtifactName is nil; the updater cannot resolve a release asset")
	}

	tests := []struct {
		version, goos, goarch, want string
	}{
		{"v1.1.0", "linux", "amd64", "anansi_1.1.0_linux_amd64.tar.gz"},
		{"v1.1.0", "linux", "arm64", "anansi_1.1.0_linux_arm64.tar.gz"},
		{"v1.1.0", "darwin", "amd64", "anansi_1.1.0_macos_amd64.tar.gz"},
		{"v1.1.0", "darwin", "arm64", "anansi_1.1.0_macos_arm64.tar.gz"},
		{"v1.1.0", "windows", "amd64", "anansi_1.1.0_windows_amd64.zip"},
		{"v1.1.0", "windows", "arm64", "anansi_1.1.0_windows_arm64.zip"},
		{"v1.1.0", "android", "arm64", "anansi_1.1.0_android_arm64.tar.gz"},
		// A bare (already-stripped) version must produce the same name.
		{"1.1.0", "linux", "amd64", "anansi_1.1.0_linux_amd64.tar.gz"},
	}

	for _, tt := range tests {
		if got := cfg.ArtifactName(tt.version, tt.goos, tt.goarch); got != tt.want {
			t.Errorf("ArtifactName(%q, %q, %q) = %q, want %q",
				tt.version, tt.goos, tt.goarch, got, tt.want)
		}
	}
}

// TestReleaseArchiveEntryMatchesAsset guards the failure mode of an update
// that downloads and verifies the archive correctly but installs the wrong
// bytes: the archive's single executable entry must be the tool itself, and
// windows assets are zip while everything else is tar.gz.
func TestReleaseArchiveEntryMatchesAsset(t *testing.T) {
	cfg := releaseConfig()
	if cfg.ArchiveFor == nil {
		t.Fatal("ArchiveFor is nil; the updater would install the archive bytes as the binary")
	}

	kind, entry := cfg.ArchiveFor("linux", "amd64")
	if kind != selfupdate.ArchiveTarGz || entry != "anansi" {
		t.Errorf("ArchiveFor(linux, amd64) = (%v, %q), want (ArchiveTarGz, anansi)", kind, entry)
	}

	kind, entry = cfg.ArchiveFor("windows", "amd64")
	if kind != selfupdate.ArchiveZip || entry != "anansi.exe" {
		t.Errorf("ArchiveFor(windows, amd64) = (%v, %q), want (ArchiveZip, anansi.exe)", kind, entry)
	}
}

// TestChecksumAssetIsTheReleaseManifest pins the checksum source. A per-artifact
// ".sha256" sidecar holds a bare digest, which does not match a manifest line of
// the form "<sha256>  <name>", so verification silently fails against it.
func TestChecksumAssetIsTheReleaseManifest(t *testing.T) {
	cfg := releaseConfig()
	if cfg.ChecksumAsset == nil {
		t.Fatal("ChecksumAsset is nil; the update would be unverified")
	}
	for _, artifact := range []string{
		"anansi_1.1.0_linux_amd64.tar.gz", "anansi_1.1.0_macos_arm64.tar.gz",
		"anansi_1.1.0_android_arm64.tar.gz", "anansi_1.1.0_windows_amd64.zip",
	} {
		if got := cfg.ChecksumAsset(artifact); got != "checksums.txt" {
			t.Errorf("ChecksumAsset(%q) = %q, want \"checksums.txt\"", artifact, got)
		}
	}
}

// TestReleaseArtifactNameStripsVersionPrefix is the specific bug this contract
// exists for: GoReleaser embeds the tag with the "v" stripped, so leaving the
// prefix on produces a name no release ever published.
func TestReleaseArtifactNameStripsVersionPrefix(t *testing.T) {
	cfg := releaseConfig()
	for _, tag := range []string{"v1.1.0", "V1.1.0", "1.1.0"} {
		got := cfg.ArtifactName(tag, "linux", "amd64")
		if strings.Contains(got, "_v1.1.0_") || strings.Contains(got, "_V1.1.0_") {
			t.Errorf("ArtifactName(%q, linux, amd64) = %q, kept the version prefix", tag, got)
		}
	}
}
