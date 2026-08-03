package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/peterh/liner"

	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

// consoleOption describes a single configurable scan option exposed by the
// interactive console (the equivalent of a Metasploit module option).
type consoleOption struct {
	name string
	def  string
	desc string
}

// defaultModules is the canonical module set used both by the --modules flag
// default and the console's MODULES option.
var defaultModules = []string{
	"discovery", "probe", "tls", "headers", "paths", "tech", "takeover", "osint", "chain",
}

// consoleOptions lists every option settable from the console prompt.
var consoleOptions = []consoleOption{
	{name: "RHOSTS", def: "", desc: "Target domain for scans (used by 'run')"},
	{name: "DEEP", def: "false", desc: "Enable deep scan (larger wordlist, more path probing)"},
	{name: "OUT", def: "terminal", desc: "Output format: terminal | json | markdown | html"},
	{name: "OUTPUT_FILE", def: "", desc: "Write output to file instead of stdout"},
	{name: "TIMEOUT", def: "5", desc: "Per-request timeout in seconds"},
	{name: "MODULES", def: strings.Join(defaultModules, ","), desc: "Modules to run (comma-separated)"},
	{name: "WORDLIST", def: "", desc: "Path to custom subdomain wordlist"},
	{name: "THREADS", def: "100", desc: "Number of concurrent threads"},
	{name: "VERBOSE", def: "false", desc: "Show all results including not-found/failed items"},
	{name: "RECURSIVE", def: "false", desc: "Recursive subdomain brute-force on resolved subdomains"},
	{name: "MUTATE", def: "false", desc: "Subdomain mutation brute-force based on resolved prefixes"},
	{name: "DELAY", def: "0", desc: "Delay between requests in ms for rate limiting"},
	{name: "PORTS", def: "80,443", desc: "Ports to probe (comma-separated)"},
	{name: "STEALTH", def: "false", desc: "Stealth mode: random UA, jitter, skip crt.sh, reduced concurrency"},
}

// moduleDescriptions documents each scan phase for the console's use/info.
var moduleDescriptions = map[string]string{
	"discovery": "subdomain enumeration + DNS resolution",
	"probe":     "HTTP/HTTPS surface mapping",
	"tls":       "certificate analysis + SAN discovery",
	"headers":   "security header audit",
	"paths":     "exposed endpoint + file detection",
	"tech":      "CMS fingerprinting + version-specific vulnerability audit",
	"takeover":  "dangling CNAME subdomain takeover detection",
	"osint":     "organisation recon — emails, phones, WHOIS, employees",
	"chain":     "multi-step exploit path assembly from findings",
}

// consoleCommands is the set of commands offered by the console prompt.
var consoleCommands = []string{
	"back", "banner", "clear", "exit", "help", "history", "info",
	"options", "quit", "run", "scan", "search", "set", "show", "unset", "use", "version",
}

// consoleSession is the state of a single interactive console run.  It owns
// the current option values, command history and the selected module context.
type consoleSession struct {
	out     io.Writer
	tty     bool
	values  map[string]string
	history []string
	module  string
}

// newConsoleSession creates a session and resets every scan option (and the
// backing global flags) to its default value.
func newConsoleSession(out io.Writer, tty bool) *consoleSession {
	s := &consoleSession{
		out:    out,
		tty:    tty,
		values: make(map[string]string, len(consoleOptions)),
	}
	for _, o := range consoleOptions {
		s.values[o.name] = o.def
		_ = applyOption(o.name, o.def)
	}
	return s
}

// runConsole launches the interactive console.  When both stdin and stdout are
// terminals it enables line editing, tab completion and persistent history via
// liner; otherwise it degrades to plain line-by-line reading (pipe-friendly).
func runConsole() error {
	tty := isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
	return newConsoleSession(os.Stdout, tty).run()
}

// run drives the REPL using the line editor when in a terminal, or a plain
// scanner otherwise.
func (s *consoleSession) run() error {
	if s.tty {
		return s.runLiner()
	}
	return s.runPlain()
}

// runPlain reads one command per line from stdin without line editing.  This
// keeps the console usable when input is piped or redirected.
func (s *consoleSession) runPlain() error {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		done, err := s.handleLine(line)
		if err != nil {
			fmt.Fprintln(s.out, err)
		}
		if done {
			return nil
		}
	}
	return sc.Err()
}

// runLiner runs the REPL on a real terminal with arrow-key history, tab
// completion and a persistent history file (Metasploit-console style).
func (s *consoleSession) runLiner() error {
	rl := liner.NewLiner()
	defer func() { _ = rl.Close() }()
	rl.SetCtrlCAborts(true)
	rl.SetMultiLineMode(false)
	rl.SetCompleter(s.complete)

	if path, err := s.historyPath(); err == nil {
		if f, err := os.Open(path); err == nil {
			_, _ = rl.ReadHistory(f)
			_ = f.Close()
		}
	}

	for {
		line, err := rl.Prompt(s.prompt())
		if err != nil {
			if errors.Is(err, liner.ErrPromptAborted) {
				fmt.Fprintln(s.out)
				continue
			}
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(s.out)
				break
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rl.AppendHistory(line)
		done, herr := s.handleLine(line)
		if herr != nil {
			fmt.Fprintln(s.out, herr)
		}
		if done {
			break
		}
	}

	if path, err := s.historyPath(); err == nil {
		if f, err := os.Create(path); err == nil {
			_, _ = rl.WriteHistory(f)
			_ = f.Close()
		}
	}
	return nil
}

// historyPath returns the location of the console history file.
func (s *consoleSession) historyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".anansi_history"), nil
}

// prompt renders the Metasploit-style prompt.  In a terminal it is colored and
// shows the selected module context, e.g. "anansi[paths] > ".
func (s *consoleSession) prompt() string {
	p := "anansi"
	if s.module != "" {
		p += "[" + s.module + "]"
	}
	p += " > "
	if s.tty {
		return color.New(color.FgCyan, color.Bold).Sprint(p)
	}
	return p
}

// handleLine parses and dispatches a single console command.  It returns
// (true, nil) when the command should leave the console.
func (s *consoleSession) handleLine(line string) (bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return false, nil
	}
	s.history = append(s.history, line)
	fields := strings.Fields(line)
	command := strings.ToLower(fields[0])
	args := fields[1:]

	switch command {
	case "help", "?":
		s.printHelp()
	case "banner":
		s.printBanner()
	case "version":
		fmt.Fprintln(s.out, Version)
	case "history":
		for i, h := range s.history {
			fmt.Fprintf(s.out, "%4d  %s\n", i+1, h)
		}
	case "clear":
		fmt.Fprintf(s.out, "\x1b[2J\x1b[H")
	case "exit", "quit":
		return true, nil
	case "set":
		return false, s.handleSet(args)
	case "unset":
		return false, s.handleUnset(args)
	case "options", "opt":
		s.printOptions()
	case "show":
		if len(args) == 1 && strings.EqualFold(args[0], "options") {
			s.printOptions()
		} else {
			return false, errors.New("usage: show options")
		}
	case "info":
		s.printInfo(args)
	case "use":
		return false, s.handleUse(args)
	case "back":
		s.module = ""
		fmt.Fprintln(s.out, "Module deselected.")
	case "search":
		s.search(strings.Join(args, " "))
	case "scan", "run":
		return s.runScan(args)
	default:
		return false, fmt.Errorf("unknown command %q — type 'help'", command)
	}
	return false, nil
}

func (s *consoleSession) handleSet(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: set <option> <value>")
	}
	name := strings.ToUpper(args[0])
	value := strings.Join(args[1:], " ")
	if name == "RHOSTS" {
		s.values[name] = value
		fmt.Fprintf(s.out, "%s => %s\n", name, value)
		return nil
	}
	if err := applyOption(name, value); err != nil {
		return err
	}
	s.values[name] = value
	fmt.Fprintf(s.out, "%s => %s\n", name, value)
	return nil
}

func (s *consoleSession) handleUnset(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: unset <option>")
	}
	name := strings.ToUpper(args[0])
	opt := findOption(name)
	if opt == nil {
		return fmt.Errorf("unknown option %q (see options)", name)
	}
	_ = applyOption(name, opt.def)
	s.values[name] = opt.def
	fmt.Fprintf(s.out, "%s => %s\n", name, opt.def)
	return nil
}

func (s *consoleSession) handleUse(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: use <module>")
	}
	module := strings.ToLower(args[0])
	if _, ok := moduleDescriptions[module]; !ok {
		return fmt.Errorf("unknown module %q (available: %s)", module, strings.Join(defaultModules, ", "))
	}
	s.module = module
	fmt.Fprintf(s.out, "Using module %s\n", module)
	return nil
}

// runScan resolves the target (explicit argument or RHOSTS) and executes a
// scan.  When a module context is active the scan is limited to that module.
func (s *consoleSession) runScan(args []string) (bool, error) {
	target := ""
	if len(args) > 0 {
		target = strings.TrimSpace(args[0])
	}
	if target == "" {
		target = strings.TrimSpace(s.values["RHOSTS"])
	}
	if target == "" {
		return false, errors.New("target required: scan <target> or set RHOSTS <target>")
	}
	if err := s.runTargetScan(target); err != nil {
		return false, err
	}
	return false, nil
}

func (s *consoleSession) runTargetScan(target string) error {
	saved := flagModules
	restore := false
	if s.module != "" {
		flagModules = []string{s.module}
		restore = true
	}
	defer func() {
		if restore {
			flagModules = saved
		}
	}()
	return runScanTarget([]string{target}, true)
}

func (s *consoleSession) printHelp() {
	_, _ = fmt.Fprint(s.out, `
Core Commands
=============

    Command          Description
    -------          -----------
    banner           Print the ANANSI banner
    help             Show this help menu
    version          Show version information
    history          Show command history
    clear            Clear the screen
    exit             Leave the console

Module Commands
===============

    Command          Description
    -------          -----------
    use <module>     Select a scan module (e.g. use paths)
    back             Deselect the current module
    info             Show module or option information
    search <text>    Search modules and options

Scan Commands
=============

    Command          Description
    -------          -----------
    scan <target>    Run a full scan against <target>
    run [target]     Run a scan; falls back to RHOSTS, honors the selected module
    set <opt> <v>    Set a scan option (e.g. set THREADS 200)
    unset <opt>      Restore an option's default value
    options          Show the current option values
`)
}

func (s *consoleSession) printBanner() {
	fmt.Fprintln(s.out)
	for _, line := range strings.Split(output.AnansiASCIIArt, "\n") {
		fmt.Fprintln(s.out, line)
	}
	fmt.Fprintln(s.out)
	fmt.Fprintln(s.out, "  Attack Surface Intelligence Engine")
	fmt.Fprintf(s.out, "  %s — %s\n", output.CompanyName, output.CompanyURL)
	fmt.Fprintf(s.out, "  Built in %s\n\n", output.BuiltIn)
}

func (s *consoleSession) printOptions() {
	fmt.Fprintln(s.out)
	fmt.Fprintln(s.out, "Scan Options")
	fmt.Fprintln(s.out, "============")
	for _, o := range consoleOptions {
		fmt.Fprintf(s.out, "  %-12s = %-20s %s\n", o.name, s.values[o.name], o.desc)
	}
	fmt.Fprintln(s.out)
	if s.module != "" {
		fmt.Fprintf(s.out, "Current module: %s\n", s.module)
	}
}

func (s *consoleSession) printInfo(args []string) {
	if len(args) > 0 {
		name := strings.ToUpper(args[0])
		opt := findOption(name)
		if opt == nil {
			fmt.Fprintf(s.out, "unknown option %q\n", name)
			return
		}
		fmt.Fprintf(s.out, "%s (default: %s)\n  %s\n", opt.name, opt.def, opt.desc)
		return
	}
	if s.module != "" {
		desc := moduleDescriptions[s.module]
		fmt.Fprintf(s.out, "Module: %s\n  %s\n", s.module, desc)
		return
	}
	s.printOptions()
}

func (s *consoleSession) search(query string) {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		fmt.Fprintln(s.out, "usage: search <text>")
		return
	}
	found := false
	for _, o := range consoleOptions {
		if strings.Contains(strings.ToLower(o.name), query) || strings.Contains(strings.ToLower(o.desc), query) {
			fmt.Fprintf(s.out, "  [option] %-12s %s\n", o.name, o.desc)
			found = true
		}
	}
	for name, desc := range moduleDescriptions {
		if strings.Contains(strings.ToLower(name), query) || strings.Contains(strings.ToLower(desc), query) {
			fmt.Fprintf(s.out, "  [module] %-12s %s\n", name, desc)
			found = true
		}
	}
	if !found {
		fmt.Fprintf(s.out, "No matches for %q.\n", query)
	}
}

// complete provides tab completion for commands, options and module names.
func (s *consoleSession) complete(line string) []string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return append([]string(nil), consoleCommands...)
	}
	prefix := strings.ToLower(fields[len(fields)-1])
	switch {
	case len(fields) == 1:
		out := make([]string, 0, len(consoleCommands))
		for _, c := range consoleCommands {
			if strings.HasPrefix(c, prefix) {
				out = append(out, c)
			}
		}
		return out
	case strings.EqualFold(fields[0], "set") || strings.EqualFold(fields[0], "unset"):
		out := make([]string, 0, len(consoleOptions))
		for _, o := range consoleOptions {
			if strings.HasPrefix(strings.ToLower(o.name), prefix) {
				out = append(out, o.name)
			}
		}
		return out
	case strings.EqualFold(fields[0], "use"):
		out := make([]string, 0, len(defaultModules))
		for _, m := range defaultModules {
			if strings.HasPrefix(m, prefix) {
				out = append(out, m)
			}
		}
		return out
	}
	return []string{}
}

func findOption(name string) *consoleOption {
	for i := range consoleOptions {
		if consoleOptions[i].name == name {
			return &consoleOptions[i]
		}
	}
	return nil
}

// applyOption validates a value and writes it into the backing global flag
// variable.  RHOSTS is session-managed and intentionally a no-op here.
func applyOption(name, value string) error {
	switch name {
	case "DEEP":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		flagDeep = b
	case "OUT":
		flagOut = value
	case "OUTPUT_FILE":
		flagOutputFile = value
	case "TIMEOUT":
		i, err := parseInt(value)
		if err != nil {
			return err
		}
		flagTimeout = i
	case "MODULES":
		flagModules = parseList(value)
	case "WORDLIST":
		flagWordlist = value
	case "THREADS":
		i, err := parseInt(value)
		if err != nil {
			return err
		}
		flagThreads = i
	case "VERBOSE":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		flagVerbose = b
	case "RECURSIVE":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		flagRecursive = b
	case "MUTATE":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		flagMutate = b
	case "DELAY":
		i, err := parseInt(value)
		if err != nil {
			return err
		}
		flagDelay = i
	case "PORTS":
		flagPorts = parseList(value)
	case "STEALTH":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		flagStealth = b
	case "RHOSTS":
		// session-managed; nothing to apply
	default:
		return fmt.Errorf("unknown option %q (see options)", name)
	}
	return nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on", "enabled":
		return true, nil
	case "false", "0", "no", "off", "disabled":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q (use true/false)", s)
}

func parseInt(s string) (int, error) {
	i, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("expected an integer, got %q", s)
	}
	return i, nil
}

func parseList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
