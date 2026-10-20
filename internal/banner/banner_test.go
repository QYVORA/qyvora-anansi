package banner

import (
	"regexp"
	"strings"
	"testing"
)

// ansi matches the SGR escape sequences Render may add.
var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestArtNonEmpty guards against the banner being accidentally emptied.
func TestArtNonEmpty(t *testing.T) {
	if strings.TrimSpace(Art) == "" {
		t.Fatal("Art is empty")
	}
}

// TestArtIsPlain guards the contract that Art carries no escape codes. Art is
// written to files and machine-readable streams, so colour has to live in
// Render instead of leaking into the constant.
func TestArtIsPlain(t *testing.T) {
	if ansi.MatchString(Art) {
		t.Fatal("Art contains ANSI escape sequences; keep colour in Render")
	}
}

// TestRenderPreservesArt checks that colouring is purely additive: stripping
// the escapes from Render must give back Art exactly, whatever the terminal
// profile happens to be. This is what keeps a redirected run byte-identical to
// the plain banner.
func TestRenderPreservesArt(t *testing.T) {
	if got := ansi.ReplaceAllString(Render(), ""); got != Art {
		t.Error("Render did not reduce to Art once escapes were removed")
	}
}

// TestWidthMatchesArt pins Width to the art it describes. A stale width is
// worse than none: it is the number a caller uses to decide the banner fits.
func TestWidthMatchesArt(t *testing.T) {
	want := 0
	for _, line := range strings.Split(strings.TrimRight(Art, "\n"), "\n") {
		if n := len(line); n > want {
			want = n
		}
	}
	if Width != want {
		t.Errorf("Width = %d, want %d (widest row of Art)", Width, want)
	}
}

// TestGreenIsBrandAccent pins the brand colour so a well-meaning edit cannot
// quietly repaint every tool.
func TestGreenIsBrandAccent(t *testing.T) {
	if Green != "#06B66F" {
		t.Errorf("Green = %q, want %q", Green, "#06B66F")
	}
}

// TestTaglineStatesFrameworkIdentity guards against the product identity
// drifting back to a single capability. Anansi is a web application
// penetration testing framework; "attack surface" discovery is one capability
// area inside it, so the banner tagline must name the framework, not the
// technique. Keep this a substring check on the identity phrase, not an exact
// string match, so the surrounding wording can evolve without false failures.
func TestTaglineStatesFrameworkIdentity(t *testing.T) {
	const identity = "Web Application Penetration Testing Framework"
	if !strings.Contains(Tagline, identity) {
		t.Errorf("Tagline = %q; must state the framework identity %q", Tagline, identity)
	}
	if strings.Contains(strings.ToLower(Tagline), "attack surface intelligence") {
		t.Errorf("Tagline = %q; must not describe the whole product as an attack-surface tool", Tagline)
	}
}
