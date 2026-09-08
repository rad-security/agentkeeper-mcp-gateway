package skillinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type assessmentPlan struct {
	previous   map[string]string
	prioritize bool
}

// CollectV2WithAssessmentHints prioritizes metadata changes in the background.
// Callers must alternate a priority-applied pass with a normal pass, retaining
// NextAssessmentOffset and AssessmentHints. Hints are not content attestations.
func CollectV2WithAssessmentHints(ctx context.Context, opts ScanOptions, offset int, previous map[string]string, prioritize bool) (CollectionV2, error) {
	if len(previous) > 1000 {
		return CollectionV2{}, fmt.Errorf("assessment hint limit exceeded")
	}
	for key, value := range previous {
		if !validAssessmentHint(key) || !validAssessmentHint(value) {
			return CollectionV2{}, fmt.Errorf("invalid assessment hint")
		}
	}
	return collectV2(ctx, opts, offset, false, &assessmentPlan{previous, prioritize})
}

func validAssessmentHint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

type metadataEntry struct {
	Root     string
	Location string
	Plugin   string
	Size     int64
	Mode     uint32
	Modified int64
	Identity map[string]json.RawMessage
}

func candidateMetadata(sources []SourceV2, candidate packageCandidate) metadataEntry {
	// Do not include access time: scanning must not manufacture a change signal.
	raw, _ := json.Marshal(candidate.skillInfo.Sys())
	var stat map[string]json.RawMessage
	_ = json.Unmarshal(raw, &stat)
	identity := map[string]json.RawMessage{}
	for _, key := range []string{"Dev", "Ino", "Ctim", "Ctimespec", "Ctime", "Ctimensec"} {
		if value, ok := stat[key]; ok {
			identity[key] = value
		}
	}
	return metadataEntry{sources[candidate.source].RootID, opaqueID(strings.Join(candidate.rel, "/")), candidate.pluginID, candidate.skillInfo.Size(), uint32(candidate.skillInfo.Mode()), candidate.skillInfo.ModTime().UnixNano(), identity}
}

func assessmentOrder(sources []SourceV2, candidates []packageCandidate, offset int, plan *assessmentPlan) (order []int, keys []string, hints []string, priority []bool) {
	count := len(candidates)
	if plan != nil {
		keys, hints, priority = make([]string, count), make([]string, count), make([]bool, count)
		for index, candidate := range candidates {
			entry := candidateMetadata(sources, candidate)
			keys[index] = opaqueID(entry.Root, entry.Location)
			raw, _ := json.Marshal(struct {
				Scanner string
				Entry   metadataEntry
			}{AssessmentVersion, entry})
			hints[index] = opaqueID(string(raw))
			priority[index] = plan.prioritize && plan.previous[keys[index]] != hints[index]
		}
		for step := range candidates {
			index := (offset + step) % count
			if priority[index] {
				order = append(order, index)
			}
		}
	}
	for step := range candidates {
		index := (offset + step) % count
		if plan == nil || !priority[index] {
			order = append(order, index)
		}
	}
	return
}

func stableAssessmentAttempt(assessment PackageAssessment) bool {
	if assessment.Status != "complete" && assessment.Status != "partial" {
		return false
	}
	for _, reason := range assessment.Reasons {
		if strings.Contains(reason, "changed") || reason == "scan_deadline" || strings.Contains(reason, "unavailable") {
			return false
		}
	}
	return true
}
