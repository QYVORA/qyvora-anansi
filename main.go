// Package main is the entry point for the ANANSI CLI application.
// This file simply delegates to the cmd package which handles all CLI logic.
package main

import "github.com/QYVORA/qyvora-anansi/cmd"

// main is the entry point. It calls cmd.Execute() which sets up and runs
// the Cobra CLI framework, parsing flags and executing the scan logic.
func main() {
	cmd.Execute()
}
