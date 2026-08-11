package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

// sectionWidth is the fixed visible width of every console section rule.
const sectionWidth = 60

// console palette — green accent matches the ANANSI scan terminal output;
// red is reserved for hard errors, amber for warnings.
var (
	cpAccent    = color.New(color.FgHiGreen, color.Bold)
	cpAccentDim = color.New(color.FgHiGreen)
	cpWhite     = color.New(color.FgWhite, color.Bold)
	cpDim       = color.New(color.FgHiBlack)
	cpRed       = color.New(color.FgRed, color.Bold)
	cpRedDim    = color.New(color.FgRed)
)

// consoleUI renders the console chrome: colored banner, status strip,
// sectioned help tables, and status glyphs.  Color is applied only when the
// session runs on a real terminal so piped/scripted output stays clean.
type consoleUI struct {
	w     io.Writer
	color bool
	// width is the live terminal column count used by the HUD; the console
	// refreshes it before every render.
	width int
}

func newConsoleUI(w io.Writer, colorEnabled bool) *consoleUI {
	return &consoleUI{w: w, color: colorEnabled, width: sectionWidth}
}

// paint colors s when colors are active.
func (u *consoleUI) paint(c *color.Color, s string) string {
	if !u.color || s == "" {
		return s
	}
	return c.Sprint(s)
}

// paintf colors a formatted string when colors are active.
func (u *consoleUI) paintf(c *color.Color, format string, args ...any) string {
	if !u.color {
		return fmt.Sprintf(format, args...)
	}
	return c.Sprintf(format, args...)
}

// Section prints a fixed-width horizontal rule carrying the title, e.g.
// "──────────────────────── Core Commands ─────────────────────────".
func (u *consoleUI) Section(title string) {
	label := strings.TrimSpace(title)
	if label == "" {
		u.Rule()
		return
	}
	inner := sectionWidth - runeWidth(label) - 2
	if inner < 2 {
		inner = 2
	}
	left := inner / 2
	right := inner - left
	fmt.Fprintf(u.w, "\n%s\n", u.paint(cpDim, strings.Repeat("─", left)+" "+label+" "+strings.Repeat("─", right)))
}

// Rule prints a full-width dim rule.
func (u *consoleUI) Rule() {
	fmt.Fprintln(u.w, u.paint(cpDim, strings.Repeat("─", sectionWidth)))
}

// KV prints a "  key: value" pair with the key emphasized.
func (u *consoleUI) KV(key, value string) {
	fmt.Fprintf(u.w, "  %s %s\n", u.paint(cpWhite, key+":"), u.paint(cpWhite, value))
}

// Glyph returns a colored "[x]" token for a status glyph character, matching
// the scan output conventions: [+] success, [*] info, [!] warning, [x] error,
// [>] system, [v] verbose, [-] neutral.
func (u *consoleUI) Glyph(glyph string) string {
	switch glyph {
	case "+":
		return u.paint(cpAccent, "[+]")
	case "*":
		return u.paint(cpAccentDim, "[*]")
	case "!":
		return u.paint(cpRedDim, "[!]")
	case "x", "X":
		return u.paint(cpRed, "[x]")
	case ">":
		return u.paint(cpWhite, "[>]")
	case "v":
		return u.paint(cpDim, "[v]")
	case "-":
		return u.paint(cpDim, "[-]")
	default:
		return u.paint(cpWhite, "["+glyph+"]")
	}
}

// Status prints a status line with a colored glyph.
func (u *consoleUI) Status(glyph, format string, args ...any) {
	fmt.Fprintf(u.w, "  %s %s\n", u.Glyph(glyph), u.paint(cpWhite, fmt.Sprintf(format, args...)))
}

// Err prints a hard-error line with a red [x] glyph.
func (u *consoleUI) Err(format string, args ...any) {
	fmt.Fprintf(u.w, "  %s %s\n", u.Glyph("x"), u.paint(cpRed, fmt.Sprintf(format, args...)))
}

// Prompt builds the interactive prompt: the framework name in bold green (the
// ANANSI accent color) and a bold white chevron.
func (u *consoleUI) Prompt(name string) string {
	return u.paint(cpAccent, name) + u.paint(cpWhite, " > ")
}

// Banner prints the ANANSI spider art, tagline, and build footer.
func (u *consoleUI) Banner() {
	fmt.Fprintln(u.w)
	for _, line := range strings.Split(output.AnansiASCIIArt, "\n") {
		fmt.Fprintln(u.w, u.paint(cpAccent, line))
	}
	fmt.Fprintln(u.w)
	fmt.Fprintln(u.w, u.paint(cpWhite, "  Attack Surface Intelligence Engine"))
	fmt.Fprintln(u.w, u.paintf(cpAccent, "  %s — %s", output.CompanyName, output.CompanyURL))
	fmt.Fprintln(u.w, u.paintf(cpDim, "  Built in %s", output.BuiltIn))
	fmt.Fprintln(u.w)
}

// BannerFoot prints the version footer and a help hint under the banner.
func (u *consoleUI) BannerFoot() {
	u.Status(">", "v %s", Version)
	fmt.Fprintln(u.w, u.paint(cpDim, "type 'help' for the command list, 'options' to view scan options."))
	fmt.Fprintln(u.w)
}

// HUD prints a one-line status bar with a green edge block and the live
// session state (RHOSTS, selected module) padded to the terminal width with
// the version pinned to the right edge.
func (u *consoleUI) HUD(s *consoleSession) {
	if !u.color {
		return
	}
	rhosts := strings.TrimSpace(s.values["RHOSTS"])
	if rhosts == "" {
		rhosts = "none"
	}
	module := s.module
	if module == "" {
		module = "none"
	}
	kv := func(k, v string) string {
		return u.paintf(cpDim, "%s ", k) + u.paint(cpWhite, v)
	}
	left := kv("rhosts", rhosts) + u.paintf(cpDim, "  ·  ") + kv("module", module)
	right := u.paintf(cpAccent, "v %s", Version)

	cols := u.width
	if cols < 20 {
		cols = 80
	}
	pad := cols - runeWidth(left) - runeWidth(right) - 1
	if pad < 1 {
		pad = 1
	}
	fmt.Fprintf(u.w, "%s %s%s\n", u.paint(cpAccent, "▮"), left, strings.Repeat(" ", pad)+right)
}

// Table prints a header and aligned rows, padded to the widest visible cell.
func (u *consoleUI) Table(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = runeWidth(h)
	}
	for _, r := range rows {
		for i := 0; i < len(headers) && i < len(r); i++ {
			if l := runeWidth(r[i]); l > widths[i] {
				widths[i] = l
			}
		}
	}

	var b strings.Builder
	for i, h := range headers {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(padTo(u.paint(cpWhite, h), widths[i]))
	}
	fmt.Fprintln(u.w, b.String())

	for _, r := range rows {
		var rb strings.Builder
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				rb.WriteString("  ")
			}
			var cell string
			if i < len(r) {
				cell = r[i]
			}
			rb.WriteString(padTo(u.paint(cpWhite, cell), widths[i]))
		}
		fmt.Fprintln(u.w, rb.String())
	}
}

// runeWidth counts the display width of s, stripping ANSI codes first and
// counting wide (CJK/emoji) characters as two columns.
func runeWidth(s string) int {
	if strings.Contains(s, "\x1b") {
		s = stripANSI(s)
	}
	n := 0
	for _, r := range s {
		if isWideRune(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// isWideRune reports whether r occupies two terminal columns. The ranges
// mirror the Unicode EastAsianWidth property used by wcwidth.
func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2329 && r <= 0x232A,
		r >= 0x2E80 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE10 && r <= 0xFE19,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F,
		r >= 0x1F900 && r <= 0x1F9FF:
		return true
	}
	return false
}

// stripANSI removes ANSI escape sequences from s.
func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
			j := i + 1
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// padTo pads s (which may contain ANSI codes) with trailing spaces to a
// visible width of n columns.
func padTo(s string, n int) string {
	pad := n - runeWidth(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// writerIsTerminal reports whether w is an interactive character device.
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
