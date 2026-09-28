package cmd

// defaultModules is the canonical module set used as the --modules flag default.
//
// It lived in the interactive console, which was the only other consumer. The
// console is gone, replaced by the shared TUI, so the list moved here beside
// the flag that depends on it: a default that lives in a removed file is a
// default that stops being maintainable.
var defaultModules = []string{
	"discovery", "probe", "tls", "headers", "paths", "tech", "takeover", "osint", "chain", "exploit",
}
