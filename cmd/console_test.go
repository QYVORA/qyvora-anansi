package cmd

import (
	"bytes"
	"strings"
	"testing"
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
	if got := buf.String(); got != "console-9.9.9\n" {
		t.Errorf("version printed %q, want %q", got, "console-9.9.9\n")
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
	if got := s.prompt(); got != "anansi > " {
		t.Errorf("prompt = %q, want %q", got, "anansi > ")
	}
	if _, err := s.handleLine("use probe"); err != nil {
		t.Fatalf("use probe: %v", err)
	}
	if got := s.prompt(); got != "anansi[probe] > " {
		t.Errorf("module prompt = %q, want %q", got, "anansi[probe] > ")
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
