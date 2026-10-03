// Package version holds build identity and public QYVORA contact details for
// the anansi binary.
//
// The values are compile-time defaults; release builds stamp them via:
//
//	go build -ldflags "-X github.com/QYVORA/qyvora-anansi/internal/version.Version=<tag> ..."
//
// The default Version is a semver baseline, never the bare string "dev", so
// machine consumers always receive actionable identity. A development (not yet
// released) build remains distinguishable from a release artifact by its
// Commit/Date/BuildUser metadata ("none"/"unknown"), which release pipelines
// overwrite.
package version

import "runtime"

// Framework is the canonical framework name carried in events and reports.
const Framework = "anansi"

// Public QYVORA organisation details. Kept in one place so every command that
// surfaces company data (version, report footers, banners) stays correct.
const (
	CompanyName  = "QYVORA OffSec"
	CompanyURL   = "https://qyvora.org"
	CompanyEmail = "qyvorasec@gmail.com"
	CompanyCity  = "Tamale, Ghana"
)

var (
	Version   = "0.1.0"
	Commit    = "none"
	Date      = "unknown"
	BuildUser = "unknown"
)

// Info is the machine-readable build and company identity.
type Info struct {
	Framework string `json:"framework"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	BuildUser string `json:"build_user"`
	GoVersion string `json:"go_version"`
	Arch      string `json:"arch"`
	OS        string `json:"os"`
	Website   string `json:"website"`
	Support   string `json:"support"`
	BuiltIn   string `json:"built_in"`
}

// GetInfo returns the full build identity.
func GetInfo() Info {
	return Info{
		Framework: Framework,
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		BuildUser: BuildUser,
		GoVersion: runtime.Version(),
		Arch:      runtime.GOARCH,
		OS:        runtime.GOOS,
		Website:   CompanyURL,
		Support:   CompanyEmail,
		BuiltIn:   CompanyCity,
	}
}

// String returns the short version string used by the CLI and console.
func String() string { return Version }
