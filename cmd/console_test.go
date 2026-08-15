package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

func newTestSession() (*consoleSession, *bytes.Buffer) {
	var buf bytes.Buffer
	s := newConsoleSession(&buf, false)
	return s, &buf
}

func TestParseBool(t *testing.T) {
	valid := map[string]bool{
		"true": true, "1": true, "yes": true, "on": true, "enabled": true,
		"false": false, "0": false, "no": false, "off": false, "disabled": false,
		"TRUE": true, "On": true, "OFF": false,
	}
	for in, want := range valid {
		got, err := parseBool(in)
		if err != nil {
			t.Errorf("parseBool(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseBool(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := parseBool("maybe"); err == nil {
		t.Error("parseBool(\"maybe\") expected error, got nil")
	}
}

func TestParseList(t *testing.T) {
	got := parseList(" discovery, probe ,tls, ,chain")
	want := []string{"discovery", "probe", "tls", "chain"}
	if len(got) != len(want) {
		t.Fatalf("parseList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseList = %v, want %v", got, want)
		}
	}
}

func TestConsoleSetAndUnset(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("set THREADS 200"); err != nil {
		t.Fatalf("set THREADS: %v", err)
	}
	if flagThreads != 200 {
		t.Errorf("flagThreads = %d, want 200", flagThreads)
	}
	if s.values["THREADS"] != "200" {
		t.Errorf("values[THREADS] = %q, want 200", s.values["THREADS"])
	}
	if !strings.Contains(buf.String(), "THREADS => 200") {
		t.Errorf("output missing THREADS confirmation: %q", buf.String())
	}
	buf.Reset()
	if _, err := s.handleLine("unset THREADS"); err != nil {
		t.Fatalf("unset THREADS: %v", err)
	}
	if flagThreads != 100 {
		t.Errorf("flagThreads = %d after unset, want default 100", flagThreads)
	}
}

func TestConsoleSetBoolValues(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("set DEEP true"); err != nil {
		t.Fatalf("set DEEP true: %v", err)
	}
	if !flagDeep {
		t.Error("flagDeep = false, want true")
	}
	if _, err := s.handleLine("set STEALTH off"); err != nil {
		t.Fatalf("set STEALTH off: %v", err)
	}
	if flagStealth {
		t.Error("flagStealth = true, want false")
	}
}

func TestConsoleSetInvalidValues(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("set THREADS abc"); err == nil {
		t.Error("set THREADS abc expected error")
	}
	if flagThreads != 100 {
		t.Errorf("flagThreads changed to %d after invalid set", flagThreads)
	}
	if _, err := s.handleLine("set DEEP maybe"); err == nil {
		t.Error("set DEEP maybe expected error")
	}
}

func TestConsoleSetUnknownOption(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("set BOGUS value"); err == nil {
		t.Error("set BOGUS expected error")
	}
	if _, err := s.handleLine("unset BOGUS"); err == nil {
		t.Error("unset BOGUS expected error")
	}
}

func TestConsoleSetRHOSTS(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("set RHOSTS example.com"); err != nil {
		t.Fatalf("set RHOSTS: %v", err)
	}
	if s.values["RHOSTS"] != "example.com" {
		t.Errorf("RHOSTS = %q, want example.com", s.values["RHOSTS"])
	}
}

func TestConsoleSetMODULES(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("set MODULES discovery,probe"); err != nil {
		t.Fatalf("set MODULES: %v", err)
	}
	want := []string{"discovery", "probe"}
	if len(flagModules) != len(want) {
		t.Fatalf("flagModules = %v, want %v", flagModules, want)
	}
	for i := range want {
		if flagModules[i] != want[i] {
			t.Fatalf("flagModules = %v, want %v", flagModules, want)
		}
	}
}

func TestConsoleOptionsOutput(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("set THREADS 250"); err != nil {
		t.Fatalf("set THREADS: %v", err)
	}
	buf.Reset()
	s.printOptions()
	out := buf.String()
	for _, name := range []string{"RHOSTS", "THREADS", "DEEP", "MODULES", "PORTS"} {
		if !strings.Contains(out, name) {
			t.Errorf("options output missing %s: %q", name, out)
		}
	}
	if !strings.Contains(out, "= 250") {
		t.Errorf("options output missing current THREADS value: %q", out)
	}
}

func TestConsoleHelpOutput(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("help"); err != nil {
		t.Fatalf("help: %v", err)
	}
	out := buf.String()
	for _, c := range []string{"scan", "run", "set", "unset", "options", "use", "back", "exit", "history"} {
		if !strings.Contains(out, c) {
			t.Errorf("help output missing %q", c)
		}
	}
}

func TestConsoleUseAndBack(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("use paths"); err != nil {
		t.Fatalf("use paths: %v", err)
	}
	if s.module != "paths" {
		t.Errorf("module = %q, want paths", s.module)
	}
	if !strings.Contains(buf.String(), "Using module paths") {
		t.Errorf("use output: %q", buf.String())
	}
	if _, err := s.handleLine("use bogus"); err == nil {
		t.Error("use bogus expected error")
	}
	if _, err := s.handleLine("back"); err != nil {
		t.Fatalf("back: %v", err)
	}
	if s.module != "" {
		t.Errorf("module after back = %q, want empty", s.module)
	}
}

func TestConsoleInfo(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("use takeover"); err != nil {
		t.Fatalf("use takeover: %v", err)
	}
	buf.Reset()
	if _, err := s.handleLine("info"); err != nil {
		t.Fatalf("info: %v", err)
	}
	if !strings.Contains(buf.String(), "takeover") {
		t.Errorf("module info missing module name: %q", buf.String())
	}
	buf.Reset()
	if _, err := s.handleLine("info THREADS"); err != nil {
		t.Fatalf("info THREADS: %v", err)
	}
	if !strings.Contains(buf.String(), "THREADS") {
		t.Errorf("option info missing option name: %q", buf.String())
	}
}

func TestConsoleSearch(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("search thread"); err != nil {
		t.Fatalf("search thread: %v", err)
	}
	if !strings.Contains(buf.String(), "THREADS") {
		t.Errorf("search thread missing THREADS: %q", buf.String())
	}
	buf.Reset()
	if _, err := s.handleLine("search takeover"); err != nil {
		t.Fatalf("search takeover: %v", err)
	}
	if !strings.Contains(buf.String(), "takeover") {
		t.Errorf("search takeover missing module: %q", buf.String())
	}
	buf.Reset()
	if _, err := s.handleLine("search zzzzzz"); err != nil {
		t.Fatalf("search zzzzzz: %v", err)
	}
	if !strings.Contains(buf.String(), "No matches") {
		t.Errorf("search zzzzzz expected no matches: %q", buf.String())
	}
}

func TestConsoleUnknownCommand(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("frobnicate"); err == nil {
		t.Error("unknown command expected error")
	}
}

func TestConsoleScanRequiresTarget(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("scan"); err == nil {
		t.Error("scan without target expected error")
	}
	if _, err := s.handleLine("run"); err == nil {
		t.Error("run without target expected error")
	}
}

func TestConsoleVersion(t *testing.T) {
	old := Version
	Version = "console-9.9.9"
	defer func() { Version = old }()

	s, buf := newTestSession()
	if _, err := s.handleLine("version"); err != nil {
		t.Fatalf("version: %v", err)
	}
	if got := buf.String(); got != "  [>] v console-9.9.9\n" {
		t.Errorf("version printed %q, want %q", got, "  [>] v console-9.9.9\n")
	}
}

func TestConsoleExit(t *testing.T) {
	s, _ := newTestSession()
	for _, cmd := range []string{"exit", "quit"} {
		done, err := s.handleLine(cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if !done {
			t.Errorf("%s did not leave the console", cmd)
		}
	}
}

func TestConsoleHistory(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("set THREADS 99"); err != nil {
		t.Fatalf("set: %v", err)
	}
	buf.Reset()
	if _, err := s.handleLine("history"); err != nil {
		t.Fatalf("history: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "set THREADS 99") || !strings.Contains(out, "history") {
		t.Errorf("history output missing entries: %q", out)
	}
}

func TestConsolePrompt(t *testing.T) {
	s, _ := newTestSession()
	if got := s.prompt(); got != "anansiλ > " {
		t.Errorf("prompt = %q, want %q", got, "anansiλ > ")
	}
	if _, err := s.handleLine("use probe"); err != nil {
		t.Fatalf("use probe: %v", err)
	}
	if got := s.prompt(); got != "anansiλ[probe] > " {
		t.Errorf("module prompt = %q, want %q", got, "anansiλ[probe] > ")
	}
}

func TestConsoleCompleter(t *testing.T) {
	s, _ := newTestSession()
	if got := s.complete("se"); len(got) == 0 {
		t.Error("complete(\"se\") returned no candidates")
	}
	if got := s.complete("set THR"); len(got) == 0 || got[0] != "THREADS" {
		t.Errorf("complete(\"set THR\") = %v, want THREADS", got)
	}
	if got := s.complete("use take"); len(got) == 0 || got[0] != "takeover" {
		t.Errorf("complete(\"use take\") = %v, want takeover", got)
	}
}

func TestConsoleWelcomeOnTTY(t *testing.T) {
	s, buf := newTestSession()
	s.tty = true
	s.welcome()
	out := buf.String()
	if !strings.Contains(out, "Attack Surface Intelligence Engine") {
		t.Errorf("tty welcome missing banner: %q", out)
	}
	if !strings.Contains(out, "help") {
		t.Errorf("tty welcome missing help hint: %q", out)
	}
}

func TestConsoleWelcomeQuietOnPipe(t *testing.T) {
	s, buf := newTestSession()
	s.welcome()
	if buf.Len() != 0 {
		t.Errorf("non-tty welcome should be empty, got %q", buf.String())
	}
}

func TestConsoleSeedsFromCLIFlags(t *testing.T) {
	oldDeep, oldThreads, oldModules := flagDeep, flagThreads, flagModules
	flagDeep, flagThreads = true, 250
	flagModules = []string{"discovery", "probe"}
	defer func() {
		flagDeep, flagThreads, flagModules = oldDeep, oldThreads, oldModules
	}()

	snap := snapshotConsoleOptions()
	s, _ := newTestSession()
	s.applySnapshot(snap)

	if !flagDeep {
		t.Error("flagDeep not seeded from CLI flags")
	}
	if flagThreads != 250 {
		t.Errorf("flagThreads = %d, want 250", flagThreads)
	}
	if s.values["DEEP"] != "true" {
		t.Errorf("values[DEEP] = %q, want true", s.values["DEEP"])
	}
	if s.values["THREADS"] != "250" {
		t.Errorf("values[THREADS] = %q, want 250", s.values["THREADS"])
	}
	if s.values["MODULES"] != "discovery,probe" {
		t.Errorf("values[MODULES] = %q, want discovery,probe", s.values["MODULES"])
	}
}

func TestSnapshotConsoleOptionsDefaults(t *testing.T) {
	oldDeep, oldThreads, oldModules := flagDeep, flagThreads, flagModules
	flagDeep, flagThreads = false, 100
	flagModules = append([]string(nil), defaultModules...)
	defer func() {
		flagDeep, flagThreads, flagModules = oldDeep, oldThreads, oldModules
	}()

	snap := snapshotConsoleOptions()
	if snap["DEEP"] != "false" {
		t.Errorf("snapshot DEEP = %q, want false", snap["DEEP"])
	}
	if snap["THREADS"] != "100" {
		t.Errorf("snapshot THREADS = %q, want 100", snap["THREADS"])
	}
	if _, ok := snap["RHOSTS"]; ok {
		t.Error("snapshot must not contain session-managed RHOSTS")
	}
}

func TestConsoleOptionsTruncatesLongValues(t *testing.T) {
	s, buf := newTestSession()
	s.printOptions()
	out := buf.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "MODULES") && strings.Contains(line, "Modules to run") {
			if !strings.Contains(line, "...") {
				t.Errorf("long MODULES value not truncated: %q", line)
			}
			return
		}
	}
	t.Fatal("MODULES line not found in options output")
}

func TestConsoleBannerLogoPalette(t *testing.T) {
	nBody, nFace := 0, 0
	for _, line := range strings.Split(output.AnansiASCIIArt, "\n") {
		for _, r := range line {
			switch r {
			case ' ':
			case ';':
				nBody++
			default:
				nFace++
			}
		}
	}

	var colored bytes.Buffer
	uc := newConsoleUI(&colored, true)
	uc.Banner()
	out := colored.String()
	if got := strings.Count(out, ansiCyan); got != nBody {
		t.Errorf("cyan body codes = %d, want %d", got, nBody)
	}
	if got := strings.Count(out, ansiFace); got != nFace {
		t.Errorf("white face codes = %d, want %d", got, nFace)
	}

	var plain bytes.Buffer
	up := newConsoleUI(&plain, false)
	up.Banner()
	if strings.Contains(plain.String(), "\x1b") {
		t.Error("banner must be plain when colors are disabled")
	}
}

func TestConsolePWDSession(t *testing.T) {
	s, buf := newTestSession()
	start, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if s.cwd != start {
		t.Fatalf("session cwd = %q, want %q", s.cwd, start)
	}
	buf.Reset()
	if _, err := s.handleLine("pwd"); err != nil {
		t.Fatalf("pwd: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != start {
		t.Errorf("pwd printed %q, want %q", got, start)
	}
}

func TestConsoleCD(t *testing.T) {
	s, _ := newTestSession()
	dir := t.TempDir()

	if _, err := s.handleLine("cd " + dir); err != nil {
		t.Fatalf("cd %s: %v", dir, err)
	}
	if s.cwd != filepath.Clean(dir) {
		t.Errorf("cwd after cd = %q, want %q", s.cwd, filepath.Clean(dir))
	}

	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := s.handleLine("cd nested"); err != nil {
		t.Fatalf("cd nested: %v", err)
	}
	if s.cwd != sub {
		t.Errorf("cwd after cd nested = %q, want %q", s.cwd, sub)
	}

	if _, err := s.handleLine("cd .."); err != nil {
		t.Fatalf("cd ..: %v", err)
	}
	if s.cwd != filepath.Clean(dir) {
		t.Errorf("cwd after cd .. = %q, want %q", s.cwd, filepath.Clean(dir))
	}
}

func TestConsoleCDErrors(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("cd /definitely/not/a/real/path"); err == nil {
		t.Error("cd to a missing path expected error")
	}
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.handleLine("cd " + file); err == nil {
		t.Error("cd to a file expected error")
	}
}

func TestConsoleShellKind(t *testing.T) {
	cases := map[string]string{
		"ls -la":       "",
		"!ls -la":      "shell",
		"!pwd":         "shell",
		"shell":        "interactive",
		"shell ls -la": "shell",
		"cd /tmp":      "shell",
		"pwd":          "shell",
		"scan x.com":   "",
		"  !ls":        "shell",
		"":             "",
	}
	for line, want := range cases {
		if got := shellKind(line); got != want {
			t.Errorf("shellKind(%q) = %q, want %q", line, got, want)
		}
	}
	if !isInteractiveShell("shell") {
		t.Error("isInteractiveShell(shell) = false, want true")
	}
	if isInteractiveShell("shell ls -la") {
		t.Error("isInteractiveShell(shell ls -la) = true, want false")
	}
}

func TestConsoleBangEmptyCommand(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("!"); err == nil {
		t.Error("bare ! expected error")
	}
}

func TestConsoleShellCommandOutput(t *testing.T) {
	s, _ := newTestSession()
	dir := t.TempDir()
	if _, err := s.handleLine("cd " + dir); err != nil {
		t.Fatalf("cd: %v", err)
	}
	// A one-shot shell command must run from the session cwd.
	if err := s.runShell("echo 'shell-integration-works'"); err != nil {
		t.Fatalf("runShell: %v", err)
	}
	// A failing command is not surfaced as a console error.
	if err := s.runShell("exit 3"); err != nil {
		t.Errorf("runShell exit 3: %v", err)
	}
	// A genuinely broken invocation is surfaced.
	if err := s.runShell("\x00"); err == nil {
		t.Error("runShell with a NUL byte expected error")
	}
}

func TestConsoleCompleteDir(t *testing.T) {
	s, _ := newTestSession()
	dir := t.TempDir()
	if _, err := s.handleLine("cd " + dir); err != nil {
		t.Fatalf("cd: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir alpha: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "beta"), 0o755); err != nil {
		t.Fatalf("mkdir beta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := s.completeDir("al")
	if len(got) != 2 {
		t.Fatalf("completeDir(al) = %v, want 2 entries", got)
	}
	if got[0] != "alpha/" {
		t.Errorf("completeDir(al)[0] = %q, want alpha/", got[0])
	}
}

func TestConsoleOptionBounds(t *testing.T) {
	s, _ := newTestSession()

	for _, bad := range [][2]string{
		{"THREADS", "0"},
		{"THREADS", "-5"},
		{"TIMEOUT", "0"},
		{"TIMEOUT", "-1"},
		{"DELAY", "-3"},
		{"PORTS", "80,99999"},
		{"PORTS", "80,4x3"},
	} {
		if _, err := s.handleLine("set " + bad[0] + " " + bad[1]); err == nil {
			t.Errorf("set %s %s expected error", bad[0], bad[1])
		}
	}

	for _, good := range [][2]string{
		{"THREADS", "1"},
		{"TIMEOUT", "3600"},
		{"DELAY", "0"},
		{"PORTS", "80,443,8080"},
	} {
		if _, err := s.handleLine("set " + good[0] + " " + good[1]); err != nil {
			t.Errorf("set %s %s unexpected error: %v", good[0], good[1], err)
		}
	}
}

func TestConsoleUseExploitModule(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("use exploit"); err != nil {
		t.Fatalf("use exploit: %v", err)
	}
	if s.module != "exploit" {
		t.Errorf("module = %q, want exploit", s.module)
	}
	if _, err := s.handleLine("use exploit/web/reflected-input"); err != nil {
		t.Fatalf("use exploit/web/reflected-input: %v", err)
	}
	if flagExploitSel != "web/reflected-input" {
		t.Errorf("flagExploitSel = %q, want web/reflected-input", flagExploitSel)
	}
	if _, err := s.handleLine("use exploit/web/does-not-exist"); err == nil {
		t.Error("use of an unknown exploit module expected error")
	}
	buf.Reset()
	if _, err := s.handleLine("back"); err != nil {
		t.Fatalf("back: %v", err)
	}
	if flagExploitSel != "" {
		t.Errorf("flagExploitSel after back = %q, want empty", flagExploitSel)
	}
}

func TestConsoleStatusCommand(t *testing.T) {
	s, buf := newTestSession()
	if _, err := s.handleLine("set AUTHORIZED true"); err != nil {
		t.Fatalf("set AUTHORIZED: %v", err)
	}
	buf.Reset()
	if _, err := s.handleLine("status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "AUTHORIZED: true") {
		t.Errorf("status output missing AUTHORIZED: %q", out)
	}
	if !strings.Contains(out, "module:") {
		t.Errorf("status output missing module: %q", out)
	}
}

func TestConsoleValidateRequiresTarget(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("validate"); err == nil {
		t.Error("validate without target expected error")
	}
}

func TestConsoleSetAuthorizedOption(t *testing.T) {
	s, _ := newTestSession()
	if _, err := s.handleLine("set AUTHORIZED true"); err != nil {
		t.Fatalf("set AUTHORIZED: %v", err)
	}
	if !flagAuthorized {
		t.Error("flagAuthorized not set by AUTHORIZED option")
	}
	if _, err := s.handleLine("unset AUTHORIZED"); err != nil {
		t.Fatalf("unset AUTHORIZED: %v", err)
	}
	if flagAuthorized {
		t.Error("flagAuthorized not reset by unset AUTHORIZED")
	}
}
