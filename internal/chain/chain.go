// Package chain assembles the scan's individual vulnerability findings into
// multi-step exploit chains (kill paths).  Every finding is classified into one
// or more of the 30 recognised vulnerability classes; chains are then built by
// matching those classes against curated kill-path templates, or by a generic
// escalation path ordered from the least to the most severe finding.  Each step
// carries the recommended exploitation technique for its class.
package chain

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/QYVORA/qyvora-anansi-cli/internal/assets"
	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

// vulnClass describes one of the recognised vulnerability classes.  Keywords
// are matched (substring, case-insensitive) against a finding's title to
// classify it.  Matching is deliberately title-only: descriptions and evidence
// are free-form and cause false positives (e.g. the word "credentials" inside a
// CORS finding, or "admin panel" inside an RCE description).
type vulnClass struct {
	id        string
	name      string
	keywords  []string
	technique string
}

// chainTemplate is a curated kill-path: an ordered sequence of class IDs that,
// when all present on the same asset, describe a realistic attack path.
type chainTemplate struct {
	name    string
	steps   []string
	summary string
}

const (
	maxChainsPerAsset = 3
	maxTotalChains    = 12
)

var (
	loadOnce  sync.Once
	classes   []vulnClass
	templates []chainTemplate
)

func load() {
	loadOnce.Do(func() {
		for _, line := range assets.LoadData("wordlists/chain/classes.txt") {
			parts := strings.Split(line, "|")
			if len(parts) != 4 {
				continue
			}
			classes = append(classes, vulnClass{
				id:        strings.TrimSpace(parts[0]),
				name:      strings.TrimSpace(parts[1]),
				keywords:  splitList(parts[2]),
				technique: strings.TrimSpace(parts[3]),
			})
		}

		for _, line := range assets.LoadData("wordlists/chain/chains.txt") {
			parts := strings.Split(line, "|")
			if len(parts) != 3 {
				continue
			}
			templates = append(templates, chainTemplate{
				name:    strings.TrimSpace(parts[0]),
				steps:   splitList(parts[1]),
				summary: strings.TrimSpace(parts[2]),
			})
		}
	})
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Run classifies every finding, groups them by normalised host, and returns
// ranked exploit chains.  Chains matching a curated kill-path template are
// preferred; any host with at least two distinct classes also receives a
// generic escalation chain.  Output is capped to keep reports readable.
func Run(findings []output.Finding) []output.ExploitChain {
	load()
	if len(findings) == 0 || len(classes) == 0 || len(templates) == 0 {
		return nil
	}

	byHost := groupByHost(findings)
	var chains []output.ExploitChain

	for _, host := range sortedHosts(byHost) {
		hostFindings := byHost[host]
		var assetChains []output.ExploitChain
		templateSets := map[string]bool{}
		for _, t := range templates {
			if c, ok := buildTemplateChain(t, hostFindings); ok {
				assetChains = append(assetChains, c)
				templateSets[classSet(c)] = true
			}
		}
		if c, ok := buildGenericChain(hostFindings); ok && !templateSets[classSet(c)] {
			assetChains = append(assetChains, c)
		}
		sortChains(assetChains)
		if len(assetChains) > maxChainsPerAsset {
			assetChains = assetChains[:maxChainsPerAsset]
		}
		chains = append(chains, assetChains...)
	}

	chains = dedupeChains(chains)
	sortChains(chains)
	if len(chains) > maxTotalChains {
		chains = chains[:maxTotalChains]
	}
	for i := range chains {
		chains[i].ID = fmt.Sprintf("chain-%d", i+1)
	}
	return chains
}

// groupByHost maps a normalised host to all findings on it.
func groupByHost(findings []output.Finding) map[string][]output.Finding {
	m := map[string][]output.Finding{}
	for _, f := range findings {
		host := normalizeHost(f.AffectedAsset)
		m[host] = append(m[host], f)
	}
	return m
}

func sortedHosts(m map[string][]output.Finding) []string {
	hosts := make([]string, 0, len(m))
	for h := range m {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// normalizeHost reduces an affected-asset string to its host part so that
// findings on "https://host/.env", "http://host", and "host:443" group together.
func normalizeHost(asset string) string {
	a := strings.TrimSpace(asset)
	a = strings.TrimPrefix(a, "https://")
	a = strings.TrimPrefix(a, "http://")
	if i := strings.IndexAny(a, "/?:"); i >= 0 {
		a = a[:i]
	}
	a = strings.TrimSuffix(a, ".")
	a = strings.TrimPrefix(a, "www.")
	return strings.ToLower(a)
}

// classify returns the class IDs a finding belongs to.
func classify(f output.Finding) []string {
	load()
	hay := strings.ToLower(f.Title)
	var ids []string
	for _, c := range classes {
		for _, kw := range c.keywords {
			if strings.Contains(hay, kw) {
				ids = append(ids, c.id)
				break
			}
		}
	}
	return ids
}

// classifyAll buckets findings by class ID.  A finding may appear in several
// buckets when it maps to multiple classes.
func classifyAll(findings []output.Finding) map[string][]output.Finding {
	m := map[string][]output.Finding{}
	for _, f := range findings {
		for _, id := range classify(f) {
			m[id] = append(m[id], f)
		}
	}
	return m
}

// buildTemplateChain assembles a chain for a curated kill path.  It matches
// only when every required class has at least one finding on the host.
func buildTemplateChain(t chainTemplate, findings []output.Finding) (output.ExploitChain, bool) {
	byClass := classifyAll(findings)
	steps := make([]output.ChainStep, 0, len(t.steps))
	for i, id := range t.steps {
		fs := byClass[id]
		if len(fs) == 0 {
			return output.ExploitChain{}, false
		}
		steps = append(steps, buildStep(i+1, id, pickBest(fs)))
	}
	return finishChain(t.name, t.summary, steps), true
}

// buildGenericChain creates an escalation path from whatever distinct classes
// are present on a host, ordered from the least to the most severe finding.
func buildGenericChain(findings []output.Finding) (output.ExploitChain, bool) {
	byClass := classifyAll(findings)
	order := make([]string, 0, len(byClass))
	for id := range byClass {
		order = append(order, id)
	}
	if len(order) < 2 {
		return output.ExploitChain{}, false
	}
	sort.Slice(order, func(i, j int) bool {
		ri := maxRank(byClass[order[i]])
		rj := maxRank(byClass[order[j]])
		if ri != rj {
			return ri < rj
		}
		return order[i] < order[j]
	})

	steps := make([]output.ChainStep, 0, len(order))
	for i, id := range order {
		steps = append(steps, buildStep(i+1, id, pickBest(byClass[id])))
	}
	return finishChain("Escalation Path", "Generic escalation path: "+classNames(steps)+".", steps), true
}

// buildStep wraps a finding as a chain step, attaching the class name and the
// recommended exploitation technique.
func buildStep(order int, classID string, f output.Finding) output.ChainStep {
	name, technique := classID, ""
	for _, c := range classes {
		if c.id == classID {
			name, technique = c.name, c.technique
			break
		}
	}
	return output.ChainStep{
		Order:           order,
		Class:           name,
		ClassID:         classID,
		Severity:        f.Severity,
		FindingTitle:    f.Title,
		FindingSeverity: f.Severity,
		AffectedAsset:   f.AffectedAsset,
		Technique:       technique,
	}
}

// finishChain computes the chain severity and ranking score.
func finishChain(name, summary string, steps []output.ChainStep) output.ExploitChain {
	sev := output.Info
	score := 0
	for _, s := range steps {
		if severityRank(s.Severity) > severityRank(sev) {
			sev = s.Severity
		}
		score += severityWeight(s.Severity)
	}
	score += len(steps) * 2
	return output.ExploitChain{
		Name:     name,
		Summary:  summary,
		Severity: sev,
		Score:    score,
		Steps:    steps,
	}
}

// pickBest returns the most severe finding among a class's candidates.
func pickBest(fs []output.Finding) output.Finding {
	best := fs[0]
	for _, f := range fs[1:] {
		if severityRank(f.Severity) > severityRank(best.Severity) {
			best = f
		}
	}
	return best
}

func maxRank(fs []output.Finding) int {
	r := 0
	for _, f := range fs {
		if severityRank(f.Severity) > r {
			r = severityRank(f.Severity)
		}
	}
	return r
}

func classNames(steps []output.ChainStep) string {
	names := make([]string, 0, len(steps))
	for _, s := range steps {
		names = append(names, s.Class)
	}
	return strings.Join(names, " → ")
}

// classSet returns the sorted, unique class IDs of a chain's steps.  It is
// used to detect when a generic escalation path would duplicate a curated
// template chain on the same host regardless of step ordering.
func classSet(c output.ExploitChain) string {
	ids := make([]string, 0, len(c.Steps))
	for _, s := range c.Steps {
		ids = append(ids, s.ClassID)
	}
	sort.Strings(ids)
	return strings.Join(ids, "→")
}

// dedupeChains removes chains whose ordered (class, finding, asset) sequence
// already appeared (e.g. a template chain identical to a generic escalation
// path, or the same chain assembled on the same host twice).
func dedupeChains(chains []output.ExploitChain) []output.ExploitChain {
	seen := map[string]struct{}{}
	var out []output.ExploitChain
	for _, c := range chains {
		var key []string
		for _, s := range c.Steps {
			key = append(key, s.ClassID+"\x00"+s.FindingTitle+"\x00"+s.AffectedAsset)
		}
		k := strings.Join(key, "\x01")
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	return out
}

// sortChains orders chains by score (desc), severity (desc), length (desc),
// then name (asc).
func sortChains(chains []output.ExploitChain) {
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Score != chains[j].Score {
			return chains[i].Score > chains[j].Score
		}
		if chains[i].Severity != chains[j].Severity {
			return severityRank(chains[i].Severity) > severityRank(chains[j].Severity)
		}
		if len(chains[i].Steps) != len(chains[j].Steps) {
			return len(chains[i].Steps) > len(chains[j].Steps)
		}
		return chains[i].Name < chains[j].Name
	})
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case output.Critical:
		return 4
	case output.High:
		return 3
	case output.Medium:
		return 2
	case output.Low:
		return 1
	}
	return 0
}

func severityWeight(sev string) int {
	switch strings.ToUpper(sev) {
	case output.Critical:
		return 20
	case output.High:
		return 10
	case output.Medium:
		return 5
	case output.Low:
		return 2
	}
	return 0
}
