package cmd

import "testing"

// The TUI is the reason the command tree is rebuilt per invocation, so this
// pins the behaviour that makes it safe rather than the shape of the tree.
//
// Cobra binds each flag to a package-level variable when it is registered, and
// it does not clear a flag that the next command line omits. Anansi scans
// hosts, so a leak is not cosmetic: `--deep` typed for one target would silently
// widen the next one's wordlist, and `--modules exploit` would carry active
// probing into an unrelated scan. Rebuilding the tree reapplies every default,
// which is what makes each command run with exactly the flags it was given.
func TestFlagsDoNotLeakBetweenInvocations(t *testing.T) {
	t.Cleanup(func() {
		// Leave the globals at their defaults for the next test.
		_ = newRootCmd()
	})

	_ = newRootCmd()
	flagDeep = true
	flagTimeout = 99
	flagModules = []string{"exploit"}
	flagPorts = []string{"22"}

	_ = newRootCmd()

	if flagDeep {
		t.Error("--deep from the previous invocation is still set")
	}
	if flagTimeout != 5 {
		t.Errorf("timeout=%d, want the registered default 5", flagTimeout)
	}
	if len(flagModules) == 1 && flagModules[0] == "exploit" {
		t.Error("--modules from the previous invocation is still set")
	}
	if len(flagPorts) == 1 && flagPorts[0] == "22" {
		t.Error("--ports from the previous invocation is still set")
	}
}

// Two invocations in a row must both produce a usable tree. This guards the
// per-invocation build itself: a tree that is reused would make the TUI's
// history replay a command against state the earlier command left behind.
func TestEachInvocationGetsItsOwnTree(t *testing.T) {
	first := newRootCmd()
	second := newRootCmd()

	if first == second {
		t.Fatal("newRootCmd returned the same command twice; state would be shared")
	}
	if err := first.Flags().Set("version", "true"); err != nil {
		t.Fatalf("setting --version on the first tree: %v", err)
	}
	show, err := second.Flags().GetBool("version")
	if err != nil {
		t.Fatalf("reading --version on the second tree: %v", err)
	}
	if show {
		t.Error("--version set on the first tree is visible on the second")
	}
}
