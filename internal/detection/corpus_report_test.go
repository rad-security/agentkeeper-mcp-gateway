package detection

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestPoisoningCorpusReport is a red-team report, not a pass/fail gate. It runs
// the tool-poisoning detector against two hand-built corpora and prints what it
// got wrong in each direction: legitimate definitions it flagged, and attack
// definitions it missed or under-reacted to. The test fails only when a corpus
// file cannot be read or parsed; findings never fail it.
//
// Run with:
//
//	POISON_CORPUS_REPORT=1 go test ./internal/detection/ -run TestPoisoningCorpusReport -v
//
// It skips unless POISON_CORPUS_REPORT=1 so that ordinary `go test` stays quiet.

type corpusParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type benignDef struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Parameters  []corpusParam `json:"parameters"`
	SourceStyle string        `json:"source_style"`
}

type poisonedDef struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Parameters  []corpusParam `json:"parameters"`
	Fragments   []string      `json:"fragments"`
	Technique   string        `json:"technique"`
	Expect      string        `json:"expect"` // "hard_block" | "at_least_warn"
}

func (d benignDef) toolDescription() ToolDescription {
	return toToolDescription(d.Name, d.Description, d.Parameters, nil)
}

func (d poisonedDef) toolDescription() ToolDescription {
	return toToolDescription(d.Name, d.Description, d.Parameters, d.Fragments)
}

func toToolDescription(name, desc string, params []corpusParam, fragments []string) ToolDescription {
	t := ToolDescription{Name: name, Description: desc, Fragments: fragments}
	for _, p := range params {
		t.Parameters = append(t.Parameters, ToolParam{Name: p.Name, Description: p.Description})
	}
	return t
}

func loadCorpus(t *testing.T, path string, out interface{}) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("parse corpus %s: %v", path, err)
	}
}

// clip trims a definition to a single readable line for the report.
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func TestPoisoningCorpusReport(t *testing.T) {
	if os.Getenv("POISON_CORPUS_REPORT") != "1" {
		t.Skip("set POISON_CORPUS_REPORT=1 to run the tool-poisoning corpus report")
	}

	var benign []benignDef
	var poisoned []poisonedDef
	loadCorpus(t, "testdata/benign_tool_definitions.json", &benign)
	loadCorpus(t, "testdata/poisoned_tool_definitions.json", &poisoned)
	if len(benign) == 0 || len(poisoned) == 0 {
		t.Fatalf("empty corpus: benign=%d poisoned=%d", len(benign), len(poisoned))
	}

	engine := NewEngine()
	eval := func(tool ToolDescription) (Result, bool) {
		results := engine.EvaluateToolDescriptions([]ToolDescription{tool})
		if len(results) == 0 {
			return Result{}, false
		}
		return results[0], true
	}

	// ---- Benign side: false positives ---------------------------------------
	benignFlagged, benignHardBlocked := 0, 0
	byRule := map[string][]string{}
	t.Logf("================ BENIGN FALSE POSITIVES ================")
	for _, d := range benign {
		result, found := eval(d.toolDescription())
		if !found {
			continue
		}
		benignFlagged++
		hb := "no"
		if result.HardBlock {
			hb = "YES"
			benignHardBlocked++
		}
		t.Logf("[FP] name=%q rule=%s severity=%s hard_block=%s source_style=%q\n     desc: %s",
			d.Name, result.PatternName, result.Severity, hb, d.SourceStyle, clip(d.Description, 200))
		key := result.PatternName
		if result.HardBlock {
			key += " (HARD BLOCK)"
		}
		byRule[key] = append(byRule[key], d.Name)
	}
	t.Logf("---------------- benign false positives grouped by rule ----------------")
	for _, rule := range sortedKeys(byRule) {
		t.Logf("  %s: %d  [%s]", rule, len(byRule[rule]), strings.Join(byRule[rule], ", "))
	}

	// ---- Poisoned side: misses and under-reactions --------------------------
	poisonMissed, poisonUnder, poisonHardBlocked := 0, 0, 0
	missedByTech := map[string][]string{}
	underByTech := map[string][]string{}
	t.Logf("================ POISONED MISSES ================")
	for _, d := range poisoned {
		result, found := eval(d.toolDescription())
		switch {
		case !found:
			poisonMissed++
			missedByTech[d.Technique] = append(missedByTech[d.Technique], d.Name)
			t.Logf("[MISS] technique=%s name=%q expect=%s\n     def: %s",
				d.Technique, d.Name, d.Expect, clip(reportText(d), 220))
		case result.HardBlock:
			poisonHardBlocked++
		case d.Expect == "hard_block":
			// a finding, but only a warning where a block was expected
			poisonUnder++
			underByTech[d.Technique] = append(underByTech[d.Technique], d.Name)
			t.Logf("[UNDER] technique=%s name=%q reported rule=%s severity=%s (warn, expected hard block)\n     def: %s",
				d.Technique, d.Name, result.PatternName, result.Severity, clip(reportText(d), 220))
		}
	}
	t.Logf("---------------- poisoned misses grouped by technique ----------------")
	for _, tech := range sortedKeys(missedByTech) {
		t.Logf("  MISS %s: %d  [%s]", tech, len(missedByTech[tech]), strings.Join(missedByTech[tech], ", "))
	}
	t.Logf("---------------- poisoned under-reactions grouped by technique ----------------")
	for _, tech := range sortedKeys(underByTech) {
		t.Logf("  UNDER %s: %d  [%s]", tech, len(underByTech[tech]), strings.Join(underByTech[tech], ", "))
	}

	// ---- Counts -------------------------------------------------------------
	t.Logf("================ COUNTS ================")
	t.Logf("benign:   total=%d  flagged=%d  hard_blocked=%d", len(benign), benignFlagged, benignHardBlocked)
	t.Logf("poisoned: total=%d  missed=%d  under_reacted=%d  hard_blocked=%d",
		len(poisoned), poisonMissed, poisonUnder, poisonHardBlocked)
}

func reportText(d poisonedDef) string {
	parts := []string{d.Description}
	for _, p := range d.Parameters {
		parts = append(parts, p.Name+": "+p.Description)
	}
	parts = append(parts, d.Fragments...)
	return strings.Join(parts, " | ")
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
