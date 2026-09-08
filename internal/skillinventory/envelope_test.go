package skillinventory

import (
	"encoding/json"
	"strings"
	"testing"
)

const fixtureEpoch = "bd239f57-6b7d-4b93-85bb-b7cf2334ed8a"
const fixtureScan = "b8bb56d8-f716-4097-a163-5b2d4e66c604"

func TestEnvelopeChunkLimitsAndCompleteness(t *testing.T) {
	collection := CollectionV2{StartedAt: "2026-09-07T00:00:00Z", CompletedAt: "2026-09-07T00:00:01Z", Sources: []SourceV2{{RootID: strings.Repeat("a", 64), Surface: "claude_code", SourceClass: "persistent_standalone", Status: "complete", Reasons: []string{}}}}
	for i := 0; i < 451; i++ {
		collection.Observations = append(collection.Observations, ObservationV2{RootID: collection.Sources[0].RootID, LocationID: opaqueID(string(rune(i))), SkillName: "example", Presence: "present", Assessment: notAssessed("scan_budget_exhausted")})
	}
	chunks, err := ChunkCollection(collection, fixtureEpoch, 1, fixtureScan)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 3 || len(chunks[2].Observations) != 51 {
		t.Fatalf("bad chunks: %d", len(chunks))
	}
	for i, chunk := range chunks {
		encoded, _ := json.Marshal(chunk)
		if len(encoded) > maxEnvelopeBytes || chunk.ChunkIndex != i || chunk.ChunkCount != 3 || len(chunk.Sources) != 1 {
			t.Fatal("bad envelope metadata")
		}
	}
	if _, err := ChunkCollection(collection, "new-epoch", 1, fixtureScan); err == nil {
		t.Fatal("accepted invalid epoch")
	}
}

func TestEnvelopeChunksByBytesWithoutDroppingFindings(t *testing.T) {
	collection := CollectionV2{StartedAt: "2026-09-07T00:00:00Z", CompletedAt: "2026-09-07T00:00:01Z", Sources: []SourceV2{{RootID: strings.Repeat("a", 64), Surface: "claude_code", SourceClass: "persistent_standalone", Status: "complete", Reasons: []string{}}}}
	for i := 0; i < 30; i++ {
		a := notAssessed("fixture")
		for j := 0; j < 200; j++ {
			a.Findings = append(a.Findings, SkillFinding{RuleID: "fixture", Severity: "high", Confidence: "high", Path: strings.Repeat("x", 500), Line: 1})
		}
		a.Risk = "high"
		collection.Observations = append(collection.Observations, ObservationV2{RootID: collection.Sources[0].RootID, LocationID: opaqueID(string(rune(i))), SkillName: "example", Presence: "present", Assessment: a})
	}
	chunks, err := ChunkCollection(collection, fixtureEpoch, 1, fixtureScan)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatal("did not split by bytes")
	}
	count := 0
	for _, chunk := range chunks {
		encoded, _ := json.Marshal(chunk)
		if len(encoded) > maxEnvelopeBytes {
			t.Fatal("oversized chunk")
		}
		for _, item := range chunk.Observations {
			count++
			if len(item.Assessment.Findings) != 200 {
				t.Fatal("dropped findings")
			}
		}
	}
	if count != 30 {
		t.Fatal("dropped observations")
	}
}
