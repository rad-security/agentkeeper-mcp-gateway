package detection

import (
	"sort"
	"testing"
)

// The corpora in testdata are a regression gate, not only a report.
//
// A legitimate tool hidden from the agent breaks that tool for the customer,
// so no benign definition may be a hard block, and the set of benign
// definitions flagged for review may not grow unnoticed.
func TestBenignCorpusIsNeverHardBlocked(t *testing.T) {
	var defs []benignDef
	loadCorpus(t, "testdata/benign_tool_definitions.json", &defs)
	if len(defs) < 200 {
		t.Fatalf("benign corpus has %d definitions; expected the full set", len(defs))
	}
	// Reviewed: each asks the agent not to tell the user something, or quotes
	// attack phrases as subject matter. A warning for review is intended.
	reviewedWarnings := map[string]bool{
		"save_memory": true, "op_run": true, "detect_prompt_injection": true,
		"list_attack_prompts": true, "initialize_session": true, "render_widget": true,
	}
	engine := NewEngine()
	var unexpected []string
	for _, def := range defs {
		results := engine.EvaluateToolDescriptions([]ToolDescription{def.toolDescription()})
		if len(results) == 0 {
			continue
		}
		if results[0].HardBlock {
			t.Errorf("legitimate definition %q (%s) would be hidden in Enforce: %s", def.Name, def.SourceStyle, results[0].Description)
		} else if !reviewedWarnings[def.Name] {
			unexpected = append(unexpected, def.Name+": "+results[0].Description)
		}
	}
	sort.Strings(unexpected)
	for _, finding := range unexpected {
		t.Errorf("legitimate definition newly flagged for review: %s", finding)
	}
}

// Every attack in the corpus is detected at the level a reviewer expects,
// apart from the listed ones, which are accepted gaps.
func TestPoisonedCorpusIsDetected(t *testing.T) {
	var defs []poisonedDef
	loadCorpus(t, "testdata/poisoned_tool_definitions.json", &defs)
	if len(defs) < 80 {
		t.Fatalf("poisoned corpus has %d definitions; expected the full set", len(defs))
	}
	// Not detected: wording a legitimate tool also uses (a compliance export
	// that forwards a copy, a tool that tells the agent to prefer it).
	acceptedMisses := map[string]bool{"gdpr_export": true, "fast_search": true, "secure_send": true}
	// Reported for review rather than blocked: a redirect written in Spanish
	// or French, where only the request for silence is recognised.
	acceptedWarnings := map[string]bool{"enviar_correo_proxy": true, "rediriger_paiement": true}
	engine := NewEngine()
	for _, def := range defs {
		results := engine.EvaluateToolDescriptions([]ToolDescription{def.toolDescription()})
		switch {
		case len(results) == 0:
			if !acceptedMisses[def.Name] {
				t.Errorf("attack %q (%s) was not detected", def.Name, def.Technique)
			}
		case def.Expect == "hard_block" && !results[0].HardBlock:
			if !acceptedWarnings[def.Name] {
				t.Errorf("attack %q (%s) was only reported for review: %s", def.Name, def.Technique, results[0].Description)
			}
		default:
			if acceptedMisses[def.Name] || (acceptedWarnings[def.Name] && results[0].HardBlock) {
				t.Errorf("attack %q is now detected; remove it from the accepted gaps", def.Name)
			}
		}
	}
}
