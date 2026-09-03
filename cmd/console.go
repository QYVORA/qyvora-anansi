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

	"github.com/QYVORA/qyvora-anansi/internal/exploit"
	"github.com/chzyer/readline"
	"github.com/mattn/go-isatty"
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
	"discovery", "probe", "tls", "headers", "paths", "tech", "takeover", "osint", "chain", "exploit",
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
	{name: "AUTHORIZED", def: "false", desc: "Confirm authorized testing so the exploit phase may execute proofs"},
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
	"exploit":   "controlled PoC validation and exploitation of findings",
}

// consoleCommands is the set of commands offered by the console prompt.
var consoleCommands = []string{
	"back", "banner", "cd", "clear", "exit", "help", "history", "info",
	"options", "pwd", "quit", "run", "scan", "search", "set", "shell", "show", "status", "unset", "use", "validate", "version",
}

// consoleSession is the state of a single interactive console run.  It owns
// the current option values, command history and the selected module context.
type consoleSession struct {
	out     io.Writer
	tty     bool
	ui      *consoleUI
	rl      *readline.Instance
	values  map[string]string
	history []string
	module  string
	cwd     string
}

// newConsoleSession creates a session and resets every scan option (and the
// backing global flags) to its default value. The session working directory
// starts at the directory the tool was launched from.
func newConsoleSession(out io.Writer, tty bool) *consoleSession {
	s := &consoleSession{
		out:    out,
		tty:    tty,
		ui:     newConsoleUI(out, tty),
		values: make(map[string]string, len(consoleOptions)),
	}
	if cwd, err := os.Getwd(); err == nil {
		s.cwd = cwd
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
//
// Any CLI flags passed without a target (e.g. `anansi --deep`) are inherited by
// the console so the REPL starts where the command line left off.
func runConsole() error {
	tty := isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
	snap := snapshotConsoleOptions()
	s := newConsoleSession(os.Stdout, tty)
	s.applySnapshot(snap)
	return s.run()
}

// snapshotConsoleOptions reads the current global flag values so a console
// started alongside CLI flags keeps them as its initial options.  RHOSTS is
// session-managed and intentionally absent (there is no CLI flag for it).
func snapshotConsoleOptions() map[string]string {
	return map[string]string{
		"DEEP":        strconv.FormatBool(flagDeep),
		"OUT":         flagOut,
		"OUTPUT_FILE": flagOutputFile,
		"TIMEOUT":     strconv.Itoa(flagTimeout),
		"MODULES":     strings.Join(flagModules, ","),
		"WORDLIST":    flagWordlist,
		"THREADS":     strconv.Itoa(flagThreads),
		"VERBOSE":     strconv.FormatBool(flagVerbose),
		"RECURSIVE":   strconv.FormatBool(flagRecursive),
		"MUTATE":      strconv.FormatBool(flagMutate),
		"DELAY":       strconv.Itoa(flagDelay),
		"PORTS":       strings.Join(flagPorts, ","),
		"STEALTH":     strconv.FormatBool(flagStealth),
		"AUTHORIZED":  strconv.FormatBool(flagAuthorized),
	}
}

// applySnapshot copies captured option values into the session state and the
// backing global flags.  Unknown or absent names are ignored.
func (s *consoleSession) applySnapshot(snapshot map[string]string) {
	for _, o := range consoleOptions {
		if v, ok := snapshot[o.name]; ok {
			s.values[o.name] = v
			_ = applyOption(o.name, v)
		}
	}
}

// run drives the REPL using the line editor when in a terminal, or a plain
// scanner otherwise.
func (s *consoleSession) run() error {
	if s.tty {
		s.welcome()
		return s.runLiner()
	}
	return s.runPlain()
}

// welcome prints the startup banner, version footer and a help hint on a real
// terminal only (msfconsole-style).  Piped sessions stay quiet so scripts get
// clean output.
func (s *consoleSession) welcome() {
	if !s.tty {
		return
	}
	s.ui.Banner()
	s.ui.BannerFoot()
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
			s.ui.Err("%v", err)
		}
		if done {
			return nil
		}
	}
	return sc.Err()
}

// runLiner runs the REPL on a real terminal with arrow-key history, tab
// completion, a colored prompt and a persistent history file (Metasploit-
// console style).  The line editor is readline (the same library as the
// sibling JABARI console), which unlike liner accepts ANSI-colored prompts.
func (s *consoleSession) runLiner() error {
	path, _ := s.historyPath()
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          s.prompt(),
		HistoryFile:     path,
		AutoComplete:    sessionCompleter{s},
		InterruptPrompt: "^C",
	})
	if err != nil {
		// The line editor could not start (e.g. a broken stdin or a pty
		// with no window size).  Rather than dying with a cryptic error and
		// dumping cobra usage, degrade gracefully to plain line-by-line
		// reading.
		fmt.Fprintf(s.out, "line editing unavailable (%v); continuing in plain mode\n", err)
		return s.runPlain()
	}
	defer func() { _ = rl.Close() }()
	s.rl = rl

	for {
		if w := terminalWidth(); w > 0 {
			s.ui.width = w
		}
		s.ui.HUD(s)
		line, err := rl.Readline()
		if err != nil {
			if errors.Is(err, readline.ErrInterrupt) {
				// Ctrl-C aborts the current line; return to the prompt.
				fmt.Fprintln(s.out)
				continue
			}
			// EOF (Ctrl-D): leave the console.
			fmt.Fprintln(s.out)
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		done, herr := s.handleLine(line)
		s.refreshPrompt()
		if herr != nil {
			s.ui.Err("%v", herr)
		}
		if done {
			break
		}
	}
	return nil
}

// refreshPrompt re-renders the readline prompt after the module context
// changes (use/back) so it stays in sync with the session state.
func (s *consoleSession) refreshPrompt() {
	if s.rl != nil {
		s.rl.SetPrompt(s.prompt())
	}
}

// historyPath returns the location of the console history file. It lives in
// ~/.qyvora so all QYVORA frameworks share one namespace; the parent
// directory is created on demand.
func (s *consoleSession) historyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".qyvora")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "anansi_history"), nil
}

// prompt renders the Metasploit-style prompt.  In a terminal it is colored
// green (the ANANSI accent) and shows the selected module context, e.g.
// "anansiλ[paths] > ".
func (s *consoleSession) prompt() string {
	p := "anansi"
	if s.module != "" {
		p += "[" + s.module + "]"
	}
	if s.tty {
		return s.ui.Prompt(p)
	}
	return p + " > "
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

	// Shell passthrough: "!<command>" runs a system command and returns to
	// the console. This is the Metasploit/bettercap escape hatch so the
	// operator is never isolated from the host.
	if strings.HasPrefix(line, "!") {
		if len(line) == 1 {
			return false, errors.New("usage: !<command> — run a system command, e.g. !ls -la")
		}
		return false, s.runShell(strings.TrimSpace(line[1:]))
	}

	switch command {
	case "help", "?":
		s.printHelp()
	case "banner":
		s.ui.Banner()
	case "version":
		s.ui.Status(">", "v %s", Version)
	case "history":
		for i, h := range s.history {
			fmt.Fprintf(s.out, "%4d  %s\n", i+1, h)
		}
	case "clear":
		fmt.Fprintf(s.out, "\x1b[2J\x1b[H")
	case "exit", "quit":
		return true, nil
	case "shell":
		if isInteractiveShell(line) {
			return false, s.runInteractiveShell()
		}
		return false, s.runShell(strings.Join(args, " "))
	case "cd":
		if err := s.changeDir(strings.Join(args, " ")); err != nil {
			return false, err
		}
		s.ui.Status(">", "cwd: %s", s.cwd)
	case "pwd":
		fmt.Fprintln(s.out, s.cwd)
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
		flagExploitSel = ""
		s.ui.Status("-", "Module deselected.")
	case "search":
		s.search(strings.Join(args, " "))
	case "validate":
		return false, s.handleValidate(args)
	case "status":
		return false, s.handleStatus()
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
		s.ui.Status("*", "%s => %s", name, value)
		return nil
	}
	if err := applyOption(name, value); err != nil {
		return err
	}
	s.values[name] = value
	s.ui.Status("*", "%s => %s", name, value)
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
	s.ui.Status("-", "%s => %s (default)", name, opt.def)
	return nil
}

func (s *consoleSession) handleUse(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: use <module>")
	}
	module := strings.ToLower(args[0])
	// A targeted exploit module: `use exploit/<id>`.
	if strings.HasPrefix(module, "exploit/") {
		id := strings.TrimPrefix(module, "exploit/")
		if _, ok := exploit.DefaultRegistry.Get(id); !ok {
			return fmt.Errorf("unknown exploit module %q (see 'exploit list')", id)
		}
		s.module = module
		flagExploitSel = id
		s.ui.Status("*", "Using exploit module %s", id)
		return nil
	}
	if _, ok := moduleDescriptions[module]; !ok {
		return fmt.Errorf("unknown module %q (available: %s)", module, strings.Join(defaultModules, ", "))
	}
	s.module = module
	flagExploitSel = ""
	s.ui.Status("*", "Using module %s", module)
	return nil
}

// runScan resolves the target (explicit argument or RHOSTS) and executes a
// scan.  When a module context is active the scan is limited to that module.
func (s *consoleSession) runScan(args []string) (bool, error) {
	target := ""
	if len(args) > 1 {
		return false, errors.New("usage: scan <target> — extra arguments ignored, got " + strings.Join(args, " "))
	}
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

// handleValidate runs the exploit phase in validation-only mode: the scan
// executes with authorization assumed and proof execution suppressed, so
// findings are classified as exploitable without any active PoC request.
func (s *consoleSession) handleValidate(args []string) error {
	target := ""
	if len(args) > 1 {
		return errors.New("usage: validate <target> — extra arguments ignored, got " + strings.Join(args, " "))
	}
	if len(args) > 0 {
		target = strings.TrimSpace(args[0])
	}
	if target == "" {
		target = strings.TrimSpace(s.values["RHOSTS"])
	}
	if target == "" {
		return errors.New("target required: validate <target> or set RHOSTS <target>")
	}
	savedAuth, savedDry := flagAuthorized, flagExploitDry
	flagAuthorized, flagExploitDry = true, true
	defer func() { flagAuthorized, flagExploitDry = savedAuth, savedDry }()
	return s.runTargetScan(target)
}

// handleStatus prints the console session state relevant to the PoC layer:
// the selected module, authorization status and the validation mode.
func (s *consoleSession) handleStatus() error {
	module := s.module
	if module == "" {
		module = "(none)"
	}
	s.ui.Status(">", "module: %s", module)
	s.ui.Status(">", "AUTHORIZED: %s", s.values["AUTHORIZED"])
	s.ui.Status(">", "RHOSTS: %s", s.values["RHOSTS"])
	if s.module == "exploit" || strings.HasPrefix(s.module, "exploit/") {
		s.ui.Status(">", "exploit mode: %s", map[bool]string{true: "validation-only (dry run)", false: "active (requires AUTHORIZED)"}[flagExploitDry])
		if flagExploitSel != "" {
			s.ui.Status(">", "targeted module: %s", flagExploitSel)
		}
	}
	return nil
}

func (s *consoleSession) runTargetScan(target string) error {
	saved := flagModules
	restore := false
	if s.module != "" {
		if strings.HasPrefix(s.module, "exploit/") {
			// A targeted exploit module runs the exploit phase restricted
			// to that module; flagExploitSel is already set by `use`.
			flagModules = []string{"exploit"}
		} else {
			flagModules = []string{s.module}
		}
		restore = true
	}
	defer func() {
		if restore {
			flagModules = saved
			flagExploitSel = ""
		}
	}()
	return runScanTarget([]string{target}, true)
}

func (s *consoleSession) printHelp() {
	u := s.ui
	u.Section("Core Commands")
	u.Table([]string{"Command", "Description"}, [][]string{
		{"banner", "Print the ANANSI banner"},
		{"help", "Show this help menu"},
		{"version", "Show version information"},
		{"history", "Show command history"},
		{"clear", "Clear the screen"},
		{"exit", "Leave the console"},
	})
	u.Section("Module Commands")
	u.Table([]string{"Command", "Description"}, [][]string{
		{"use <module>", "Select a scan module (e.g. use paths, use exploit)"},
		{"use exploit/<id>", "Select a single PoC module (e.g. use exploit/web/reflected-input)"},
		{"back", "Deselect the current module"},
		{"info", "Show module or option information"},
		{"search <text>", "Search modules and options"},
	})
	u.Section("Scan Commands")
	u.Table([]string{"Command", "Description"}, [][]string{
		{"scan <target>", "Run a full scan against <target>"},
		{"run [target]", "Run a scan; falls back to RHOSTS, honors the selected module"},
		{"validate [target]", "Run the exploit phase in validation-only mode (no active proof requests)"},
		{"status", "Show module, authorization and exploit-mode state"},
		{"set <opt> <v>", "Set a scan option (e.g. set THREADS 200, set AUTHORIZED true)"},
		{"unset <opt>", "Restore an option's default value"},
		{"options", "Show the current option values"},
	})
	u.Section("Shell Commands")
	u.Table([]string{"Command", "Description"}, [][]string{
		{"!<command>", "Run a system command (e.g. !ls -la)"},
		{"shell [command]", "Drop into an interactive shell, or run one command"},
		{"cd <dir>", "Change the console working directory"},
		{"pwd", "Print the console working directory"},
	})
	u.Rule()
}

func (s *consoleSession) printOptions() {
	u := s.ui
	fmt.Fprintln(u.w)
	u.Section("Scan Options")
	for _, o := range consoleOptions {
		val := s.values[o.name]
		if len(val) > 24 {
			val = val[:21] + "..."
		}
		fmt.Fprintf(u.w, "  %s %s %s %s\n",
			u.paint(cpDim, o.name),
			u.paint(cpWhite, "="),
			u.paint(cpWhite, val),
			u.paint(cpDim, o.desc))
	}
	fmt.Fprintln(u.w)
	if s.module != "" {
		u.Status("*", "Current module: %s", s.module)
	}
}

func (s *consoleSession) printInfo(args []string) {
	if len(args) > 0 {
		name := strings.ToUpper(args[0])
		opt := findOption(name)
		if opt == nil {
			s.ui.Status("!", "unknown option %q", name)
			return
		}
		s.ui.Status("*", "%s (default: %s)", opt.name, opt.def)
		fmt.Fprintf(s.out, "  %s\n", opt.desc)
		return
	}
	if s.module != "" {
		desc := moduleDescriptions[s.module]
		s.ui.Status("*", "Module: %s", s.module)
		fmt.Fprintf(s.out, "  %s\n", desc)
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
			fmt.Fprintf(s.out, "  %s %-12s %s\n", s.ui.paint(cpDim, "[option]"), s.ui.paint(cpWhite, o.name), o.desc)
			found = true
		}
	}
	for name, desc := range moduleDescriptions {
		if strings.Contains(strings.ToLower(name), query) || strings.Contains(strings.ToLower(desc), query) {
			fmt.Fprintf(s.out, "  %s %-12s %s\n", s.ui.paint(cpDim, "[module]"), s.ui.paint(cpWhite, name), desc)
			found = true
		}
	}
	for _, m := range exploit.DefaultRegistry.All() {
		meta := m.Meta()
		hay := strings.ToLower(meta.ID + " " + meta.Name + " " + meta.Description)
		if strings.Contains(hay, query) {
			fmt.Fprintf(s.out, "  %s %-12s %s\n", s.ui.paint(cpDim, "[exploit]"), s.ui.paint(cpWhite, meta.ID), meta.Description)
			found = true
		}
	}
	if !found {
		s.ui.Status("!", "No matches for %q.", query)
	}
}

// complete provides tab completion for commands, options, module names and
// (for cd) directories in the console working directory. It returns candidate
// tokens for the last word on the line.
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
		if prefix == "" || strings.HasPrefix(prefix, "exploit") {
			for _, id := range exploit.DefaultRegistry.IDs() {
				if strings.HasPrefix("exploit/"+id, prefix) {
					out = append(out, "exploit/"+id)
				}
			}
		}
		return out
	case strings.EqualFold(fields[0], "cd"):
		return s.completeDir(prefix)
	}
	return []string{}
}

// completeDir completes a directory path under the console working directory,
// appending a trailing "/" to directory entries so navigation is obvious.
func (s *consoleSession) completeDir(prefix string) []string {
	base := s.cwd
	dirPart := "."
	if prefix != "" {
		if filepath.IsAbs(prefix) {
			base = "/"
			dirPart = filepath.Dir(prefix)
		} else {
			dirPart = filepath.Dir(prefix)
			if dirPart == "." {
				dirPart = "."
			} else {
				base = filepath.Join(s.cwd, dirPart)
			}
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return []string{}
	}
	namePart := filepath.Base(prefix)
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, namePart) {
			continue
		}
		cand := name
		if dirPart != "." && dirPart != "/" {
			cand = filepath.Join(dirPart, name)
		}
		if e.IsDir() {
			cand += "/"
		}
		out = append(out, cand)
	}
	return out
}

// autoComplete adapts the token completer to the readline interface: it
// returns the candidate completions for the word under the cursor together
// with the number of typed runes to replace.
func (s *consoleSession) autoComplete(line []rune, pos int) ([][]rune, int) {
	typed := string(line[:pos])
	cands := s.complete(typed)
	length := 0
	if fields := strings.Fields(typed); len(fields) > 0 {
		length = len([]rune(fields[len(fields)-1]))
	}
	out := make([][]rune, 0, len(cands))
	for _, c := range cands {
		out = append(out, []rune(c))
	}
	return out, length
}

// sessionCompleter adapts the session's token completer to readline's
// AutoCompleter interface.
type sessionCompleter struct {
	s *consoleSession
}

func (c sessionCompleter) Do(line []rune, pos int) ([][]rune, int) {
	return c.s.autoComplete(line, pos)
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
		i, err := parseIntRange("TIMEOUT", value, 1, 3600)
		if err != nil {
			return err
		}
		flagTimeout = i
	case "MODULES":
		flagModules = parseList(value)
	case "WORDLIST":
		flagWordlist = value
	case "THREADS":
		i, err := parseIntRange("THREADS", value, 1, 100000)
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
		i, err := parseIntRange("DELAY", value, 0, 60000)
		if err != nil {
			return err
		}
		flagDelay = i
	case "PORTS":
		if err := validatePorts(value); err != nil {
			return err
		}
		flagPorts = parseList(value)
	case "STEALTH":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		flagStealth = b
	case "AUTHORIZED":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		flagAuthorized = b
	case "RHOSTS":
		// session-managed; nothing to apply
	default:
		return fmt.Errorf("unknown option %q (see options)", name)
	}
	return nil
}

// parseIntRange parses an integer option and enforces [min, max] so nonsense
// values (negative timeouts, zero threads) cannot silently corrupt a scan.
func parseIntRange(name, value string, min, max int) (int, error) {
	i, err := parseInt(value)
	if err != nil {
		return 0, err
	}
	if i < min || i > max {
		return 0, fmt.Errorf("%s: value %d out of range [%d, %d]", name, i, min, max)
	}
	return i, nil
}

// validatePorts rejects non-numeric or out-of-range port tokens so a typo
// like "80,4x3" fails at the prompt instead of mid-scan.
func validatePorts(value string) error {
	for _, p := range strings.Split(value, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("PORTS: invalid port %q (use 1-65535)", p)
		}
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
