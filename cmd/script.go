package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-script/ast"
	"github.com/QYVORA/qyvora-script/binding"
	"github.com/QYVORA/qyvora-script/interpreter"
	"github.com/QYVORA/qyvora-script/parser"

	"github.com/QYVORA/qyvora-anansi/internal/exploit"
	"github.com/QYVORA/qyvora-anansi/internal/output"
)

// allowShellOut gates the shared engine's exec/run.cmd construct. It is bound
// by the persistent --allow-shellout flag; the binding also honours
// interpreter.AllowShellOutEnv.
var allowShellOut bool

// newScriptCmd adds the flat `script` utility that runs the shared
// qyvora-script engine (ARCH-004 Part C). `script run <file>` executes a
// script; `script build <file>` prints a dry-run plan. A bare `script <file>`
// runs the file for convenience.
func newScriptCmd() *cobra.Command {
	run := func(dryRun bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			return runScriptFile(cmd, args[0], dryRun)
		}
	}
	cmd := &cobra.Command{
		Use:   "script <file>",
		Short: "run a .qs script with the shared scripting engine",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE:  run(false),
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "run <file>",
			Short: "execute a script file",
			Args:  usageArgs(cobra.ExactArgs(1)),
			RunE:  run(false),
		},
		&cobra.Command{
			Use:   "build <file>",
			Short: "validate a script file and print a dry-run plan",
			Args:  usageArgs(cobra.ExactArgs(1)),
			RunE:  run(true),
		},
	)
	return cmd
}

// runScriptFile parses (build) or executes (run) a script against anansi's
// binding.
func runScriptFile(cmd *cobra.Command, path string, dryRun bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading script: %w", err)
	}
	prog, err := parser.Parse(string(src))
	if err != nil {
		return &usageError{err}
	}
	if dryRun {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "script plan "+path)
		for _, line := range ast.Describe(prog) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  -", line)
		}
		return nil
	}
	b := &anansiBinding{
		ctx:   cmd.Context(),
		allow: allowShellOut,
		cfg:   map[string]string{},
	}
	engine := interpreter.NewEngine(b)
	engine.Events = os.Stderr
	if err := engine.RunProgram(prog); err != nil {
		return &usageError{err}
	}
	return nil
}

// anansiBinding implements binding.Binding against anansi's attack-surface
// scan and exploit module surface. "anansi.scan" runs a full scan; the exploit
// modules are exposed as "anansi.exploit.<id>" capabilities (they require a
// live, authorized target and are refused from a script).
type anansiBinding struct {
	ctx   context.Context
	allow bool
	cfg   map[string]string
	last  *output.Report
}

var _ binding.Binding = (*anansiBinding)(nil)

// Capabilities lists the scan plus every exploit module id.
func (b *anansiBinding) Capabilities() []string {
	mods := exploit.DefaultRegistry.IDs()
	ids := make([]string, 0, 1+len(mods))
	ids = append(ids, "anansi.scan")
	for _, id := range mods {
		ids = append(ids, "anansi.exploit."+id)
	}
	return ids
}

// AllowShellOut reports whether exec/run.cmd may run. Unlike the other
// frameworks, anansi deliberately forbids all environment access (see
// security_test.go), so the QYVORA_ALLOW_SHELLOUT environment variable is not
// honoured here: shell-out is enabled only by the explicit --allow-shellout
// flag.
func (b *anansiBinding) AllowShellOut() bool { return b.allow }

// Call dispatches one engine capability invocation.
func (b *anansiBinding) Call(capabilityID string, args []binding.Value) (binding.Value, error) {
	switch capabilityID {
	case binding.CapEcho:
		_, _ = fmt.Fprintln(os.Stdout, asStr(args, 0))
		return nil, nil

	case binding.CapSetConfig:
		b.cfg[asStr(args, 0)] = asStr(args, 1)
		return nil, nil

	case binding.CapGetConfig:
		return b.cfg[asStr(args, 0)], nil

	case binding.CapStart:
		return nil, b.start(asStr(args, 0))

	case binding.CapStop, binding.CapIsRunning:
		if capabilityID == binding.CapIsRunning {
			return false, nil
		}
		return nil, nil

	case binding.CapShow:
		return nil, b.show(asStr(args, 0))

	case binding.CapReport:
		return nil, b.report(asStr(args, 0))

	case binding.CapProp:
		return b.prop(asStr(args, 0)), nil

	case binding.CapExec:
		return nil, b.exec(asStr(args, 0))
	}
	return nil, fmt.Errorf("unknown capability %q", capabilityID)
}

// start dispatches a module id to the matching anansi operation.
func (b *anansiBinding) start(id string) error {
	switch id {
	case "anansi.scan", "assess", "scan", "":
		return b.scan()
	}
	if strings.HasPrefix(id, "anansi.exploit.") {
		mod := strings.TrimPrefix(id, "anansi.exploit.")
		if _, ok := exploit.DefaultRegistry.Get(mod); !ok {
			return fmt.Errorf("unknown exploit module %q", mod)
		}
		return fmt.Errorf("exploit module %q requires a live, authorized target; run it via the CLI (anansi exploit run %s <url> --authorized)", mod, mod)
	}
	return fmt.Errorf("unknown module %q", id)
}

// scan runs anansi's attack-surface scan against the configured target and
// captures the report. It routes the machine JSON report through a temp file
// so the full report is available for $(...) interpolation.
func (b *anansiBinding) scan() error {
	target := firstNonEmpty(b.cfg["scan.target"], b.cfg["target"], b.cfg["assess.target"])
	if target == "" {
		return fmt.Errorf("no target; set scan.target in the script")
	}
	tmp, err := os.CreateTemp("", "anansi-script-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(name) }()

	savedOut, savedFile := flagOut, flagOutputFile
	savedMods, savedAuth := flagModules, flagAuthorized
	defer func() {
		flagOut, flagOutputFile = savedOut, savedFile
		flagModules, flagAuthorized = savedMods, savedAuth
	}()
	flagOut = "json"
	flagOutputFile = name
	if v := firstNonEmpty(b.cfg["scan.modules"], b.cfg["modules"]); v != "" {
		flagModules = splitList(v)
	}
	if isTrue(b.cfg["scan.authorized"]) {
		flagAuthorized = true
	}

	if err := runScanTarget(b.ctx, []string{target}); err != nil {
		return err
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("reading scan report: %w", err)
	}
	var rep output.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return fmt.Errorf("parsing scan report: %w", err)
	}
	b.last = &rep
	return nil
}

// show prints capability metadata for a module id.
func (b *anansiBinding) show(id string) error {
	rows := make([][]string, 0, 1+len(exploit.DefaultRegistry.IDs()))
	if id == "anansi.scan" || id == "assess" || id == "" {
		rows = append(rows, []string{"anansi.scan", "run a full attack-surface scan", "recon"})
	}
	for _, m := range exploit.DefaultRegistry.All() {
		meta := m.Meta()
		if id == "" || id == "anansi.exploit."+meta.ID {
			rows = append(rows, []string{"anansi.exploit." + meta.ID, meta.Name, string(meta.Risk)})
		}
	}
	if len(rows) == 0 {
		return fmt.Errorf("unknown module %q", id)
	}
	printScriptTable(rows)
	return nil
}

// report writes a JSON scan report for the most recent run.
func (b *anansiBinding) report(path string) error {
	if b.last == nil {
		return fmt.Errorf("no scan to report; run a module first")
	}
	if path == "" {
		path = "anansi-report.json"
	}
	data, err := json.MarshalIndent(b.last, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(os.Stdout, "report written to "+path)
	return nil
}

// prop resolves live properties for $(...) interpolation from the last scan.
func (b *anansiBinding) prop(name string) binding.Value {
	r := b.last
	if r == nil {
		return nil
	}
	switch name {
	case "result.target":
		return r.Target
	case "result.subdomains":
		return strconv.Itoa(len(r.Subdomains))
	case "result.probes":
		return strconv.Itoa(len(r.ProbeResults))
	case "result.tls":
		return strconv.Itoa(len(r.TLSResults))
	case "result.headers":
		return strconv.Itoa(len(r.HeaderResults))
	case "result.findings":
		return strconv.Itoa(len(r.Findings))
	case "result.osint":
		return strconv.Itoa(len(r.OSINTResults))
	case "result.technology":
		return strconv.Itoa(len(r.TechResults))
	case "result.chains":
		return strconv.Itoa(len(r.Chains))
	case "result.exploits":
		return strconv.Itoa(len(r.ExploitResults))
	case "result.duration":
		return (time.Duration(r.Duration)).String()
	}
	return nil
}

// exec runs a one-shot anansi command line. The interpreter only reaches here
// after AllowShellOut reported true.
func (b *anansiBinding) exec(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if code := ExecuteArgsContext(b.ctx, strings.Fields(line)); code != 0 {
		return fmt.Errorf("command exited with code %d", code)
	}
	return nil
}

// printScriptTable renders a simple capability table for `show`.
func printScriptTable(rows [][]string) {
	for _, r := range rows {
		_, _ = fmt.Fprintf(os.Stdout, "%-32s %s\n", r[0], strings.Join(r[1:], "  "))
	}
}

func asStr(args []binding.Value, i int) string {
	if i >= len(args) || args[i] == nil {
		return ""
	}
	if s, ok := args[i].(string); ok {
		return s
	}
	return fmt.Sprintf("%v", args[i])
}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
