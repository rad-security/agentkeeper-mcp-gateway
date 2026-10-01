package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
)

// TestScanDefinitionDirectories runs the definition check over directories of
// real tool definitions (one JSON object per file, as tools/list returns them)
// and prints every finding. It is a measurement aid, skipped unless
// AGENTKEEPER_DEFINITION_DIRS names directories, separated by the OS list
// separator.
func TestScanDefinitionDirectories(t *testing.T) {
	dirs := filepath.SplitList(os.Getenv("AGENTKEEPER_DEFINITION_DIRS"))
	if len(dirs) == 0 {
		t.Skip("set AGENTKEEPER_DEFINITION_DIRS to directories of tool definition JSON files")
	}
	engine := detection.NewEngine()
	total, flagged, hard := 0, 0, 0
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		sort.Strings(files)
		for _, file := range files {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var tool map[string]interface{}
			if json.Unmarshal(raw, &tool) != nil || tool["name"] == nil {
				continue
			}
			total++
			for _, result := range engine.EvaluateToolDescriptions([]detection.ToolDescription{toolDescriptionFromMap(tool)}) {
				flagged++
				if result.HardBlock {
					hard++
				}
				t.Logf("FINDING hard_block=%v severity=%s rule=%s file=%s :: %s", result.HardBlock, result.Severity, result.PatternName, filepath.Base(file), result.Description)
			}
		}
	}
	t.Logf("definitions=%d flagged=%d hard_blocked=%d", total, flagged, hard)
}
