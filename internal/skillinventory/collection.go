package skillinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const CollectorVersion = "skill-sources-v1"

type SourceV2 struct {
	RootID      string   `json:"root_id"`
	Surface     string   `json:"surface"`
	SourceClass string   `json:"source_class"`
	Status      string   `json:"status"`
	Reasons     []string `json:"reasons"`
}
type ObservationV2 struct {
	RootID      string            `json:"root_id"`
	LocationID  string            `json:"location_id"`
	SkillName   string            `json:"skill_name"`
	PluginID    string            `json:"plugin_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	Presence    string            `json:"presence"`
	Enabled     *bool             `json:"enabled"`
	SkillMDHash string            `json:"skill_md_hash,omitempty"`
	Assessment  PackageAssessment `json:"assessment"`
}
type CollectionV2 struct {
	MetadataProbe        bool            `json:"metadata_probe"`
	ChangeFingerprint    string          `json:"change_fingerprint"`
	MetadataComplete     bool            `json:"metadata_complete"`
	NextAssessmentOffset int             `json:"next_assessment_offset"`
	StartedAt            string          `json:"started_at"`
	CompletedAt          string          `json:"completed_at"`
	Sources              []SourceV2      `json:"sources"`
	Observations         []ObservationV2 `json:"observations"`
}

type sourceSpec struct {
	path, surface, class, presence string
	patterns                       [][]string
	recursive                      bool
}
type sourceHandle struct {
	spec   sourceSpec
	root   *os.File
	result *SourceV2
}
type packageCandidate struct {
	source    int
	rel       []string
	info      os.FileInfo
	pluginID  string
	skillInfo os.FileInfo
}

// CollectV2 enumerates only recognized skill locations. It never reads chat
// transcripts, account databases, arbitrary upload files, or executes a skill.
// Enumeration precedes assessment: a slow package cannot erase later skills.
// This is an inventory operation, never an invocation-time enforcement gate.
func CollectV2(ctx context.Context, opts ScanOptions) (CollectionV2, error) {
	return CollectV2FromCursor(ctx, opts, 0)
}

// Coordinators retain NextAssessmentOffset between passes so a bounded scan
// eventually assesses every observed package instead of starving later sources.
func CollectV2FromCursor(ctx context.Context, opts ScanOptions, assessmentOffset int) (CollectionV2, error) {
	return collectV2(ctx, opts, assessmentOffset, false)
}

// ProbeV2 reads source manifests and filesystem metadata, never skill bodies.
// It is a change hint for scheduling, not content identity or a safety verdict.
func ProbeV2(ctx context.Context, opts ScanOptions) (CollectionV2, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return collectV2(ctx, opts, 0, true)
}

func collectV2(ctx context.Context, opts ScanOptions, assessmentOffset int, metadataOnly bool) (CollectionV2, error) {
	home := opts.Home
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return CollectionV2{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result := CollectionV2{MetadataProbe: metadataOnly, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Sources: []SourceV2{}, Observations: []ObservationV2{}}
	specs := collectionSources(home, opts.CWD)
	unique := map[string]bool{}
	deduplicated := []sourceSpec{}
	for _, spec := range specs {
		abs, err := filepath.Abs(spec.path)
		if err != nil {
			return CollectionV2{}, err
		}
		key := opaqueID(spec.surface, spec.class, abs)
		if !unique[key] {
			deduplicated = append(deduplicated, spec)
			unique[key] = true
		}
	}
	specs = deduplicated
	// Allocate first: pointers into Sources must stay valid throughout collection.
	result.Sources = make([]SourceV2, len(specs))
	handles := make([]sourceHandle, len(specs))
	candidates := []packageCandidate{}
	entries := 0
	for i, spec := range specs {
		abs, err := filepath.Abs(spec.path)
		if err != nil {
			return CollectionV2{}, err
		}
		source := &result.Sources[i]
		*source = SourceV2{opaqueID(spec.surface, spec.class, abs), spec.surface, spec.class, "complete", []string{}}
		handles[i] = sourceHandle{spec: spec, result: source}
		if spec.class == "account_only" || (runtime.GOOS != "darwin" && runtime.GOOS != "linux") {
			source.Status, source.Reasons = "unsupported", []string{"source_not_supported"}
			continue
		}
		if ctx.Err() != nil {
			markSource(source, "scan_deadline")
			continue
		}
		root, err := openCollectionRoot(abs, home, opts.CWD)
		if err != nil {
			source.Status, source.Reasons = "unavailable", []string{"root_unavailable"}
			continue
		}
		handles[i].root = root
		defer root.Close()
		plugins := map[string]string{}
		excluded := map[string]string{}
		if spec.surface == "claude_code" && spec.presence == "installed" {
			var reasons []string
			plugins, reasons = readInstalledPluginPaths(root)
			for _, reason := range reasons {
				markSource(source, reason)
			}
			prefixes := make([]string, 0, len(plugins))
			for prefix := range plugins {
				prefixes = append(prefixes, prefix)
			}
			sort.Strings(prefixes)
			for _, prefix := range prefixes {
				spec.patterns = append(spec.patterns, append(strings.Split(prefix, "/"), "skills", "*"))
			}
		}
		if spec.surface == "claude_code" && spec.class == "marketplace_cache" {
			// One physical install should not also appear as an uninstalled cache.
			excluded, _ = readInstalledPluginPaths(root)
		}
		seen := map[string]bool{}
		visit := func(rel []string, dir *os.File) {
			if len(rel) >= 2 && excluded[strings.Join(rel[:len(rel)-2], "/")] != "" {
				return
			}
			key := strings.Join(rel, "/")
			if seen[key] {
				return
			}
			seen[key] = true
			if len(candidates) >= 1000 {
				markSource(source, "observation_limit")
				return
			}
			file, err := openAssessmentChild(dir, "SKILL.md", false)
			if os.IsNotExist(err) {
				return
			}
			if err != nil {
				markSource(source, "skill_file_unavailable")
				return
			}
			skillInfo, statErr := file.Stat()
			file.Close()
			if statErr != nil {
				markSource(source, "skill_file_unavailable")
				return
			}
			info, err := dir.Stat()
			if err != nil {
				markSource(source, "directory_unavailable")
				return
			}
			pluginID := ""
			if len(rel) >= 2 {
				pluginID = plugins[strings.Join(rel[:len(rel)-2], "/")]
			}
			candidates = append(candidates, packageCandidate{i, append([]string{}, rel...), info, pluginID, skillInfo})
		}
		if spec.recursive {
			enumerateSource(ctx, root, nil, nil, true, source, &entries, visit)
		} else {
			for _, pattern := range spec.patterns {
				fresh, err := reopenAssessmentDir(root)
				if err != nil {
					markSource(source, "directory_unavailable")
					break
				}
				enumerateSource(ctx, fresh, nil, pattern, false, source, &entries, visit)
				fresh.Close()
			}
		}
	}
	// Stable ordering makes bounded assessment deterministic across directory order.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].source != candidates[j].source {
			return candidates[i].source < candidates[j].source
		}
		return strings.Join(candidates[i].rel, "/") < strings.Join(candidates[j].rel, "/")
	})
	remaining := DefaultAssessmentLimits()
	for i := range result.Sources {
		sort.Strings(result.Sources[i].Reasons)
	}
	result.MetadataComplete = ctx.Err() == nil
	for _, source := range result.Sources {
		for _, reason := range source.Reasons {
			if reason == "entry_limit" || reason == "observation_limit" || reason == "scan_deadline" || reason == "depth_limit" {
				result.MetadataComplete = false
			}
		}
	}
	if result.MetadataComplete {
		result.ChangeFingerprint = metadataFingerprint(result.Sources, candidates)
	}
	if assessmentOffset < 0 {
		assessmentOffset = 0
	}
	if len(candidates) > 0 {
		assessmentOffset %= len(candidates)
		result.NextAssessmentOffset = assessmentOffset
	}
	for step := range candidates {
		index := (assessmentOffset + step) % len(candidates)
		candidate := candidates[index]
		handle := handles[candidate.source]
		rel := candidate.rel
		observation := ObservationV2{RootID: handle.result.RootID, LocationID: opaqueID(strings.Join(rel, "/")), SkillName: rel[len(rel)-1], Presence: handle.spec.presence, Assessment: notAssessed("scan_budget_exhausted")}
		observation.PluginID = candidate.pluginID
		if handle.spec.class == "session_copy" || handle.spec.class == "session_upload" {
			observation.SessionID = opaqueID(strings.Join(rel[:3], "/"))
		}
		if handle.spec.class == "session_upload" {
			observation.SkillName = "Uploaded skill"
		}
		if metadataOnly {
			observation.Assessment = notAssessed("metadata_probe")
		}
		if !metadataOnly && ctx.Err() == nil && remaining.MaxFiles > 0 && remaining.MaxTotalBytes > 0 {
			result.NextAssessmentOffset = (index + 1) % len(candidates)
			opener := func() (*os.File, error) { return openCandidate(handle.root, candidate) }
			if handle.spec.class == "session_upload" {
				observation.Assessment, observation.SkillMDHash = assessUploadedSkill(ctx, opener, remaining)
			} else {
				observation.Assessment = assessPackage(ctx, opener, remaining)
				observation.SkillMDHash = observation.Assessment.SkillMDHash
			}
			remaining.MaxFiles -= observation.Assessment.FilesScanned
			remaining.MaxTotalBytes -= observation.Assessment.BytesScanned
		}
		result.Observations = append(result.Observations, observation)
	}
	result.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return result, nil
}

func metadataFingerprint(sources []SourceV2, candidates []packageCandidate) string {
	type entry struct {
		Root     string
		Location string
		Plugin   string
		Size     int64
		Mode     uint32
		Modified int64
		Identity map[string]json.RawMessage
	}
	entries := make([]entry, 0, len(candidates))
	for _, candidate := range candidates {
		// Exclude access time: assessing a file must not trigger a rescan loop.
		// Inode and change time distinguish atomic replacements and ordinary
		// writes that restore mtime. This remains a hint, never byte attestation.
		raw, _ := json.Marshal(candidate.skillInfo.Sys())
		var stat map[string]json.RawMessage
		_ = json.Unmarshal(raw, &stat)
		identity := map[string]json.RawMessage{}
		for _, key := range []string{"Dev", "Ino", "Ctim", "Ctimespec", "Ctime", "Ctimensec"} {
			if value, ok := stat[key]; ok {
				identity[key] = value
			}
		}
		entries = append(entries, entry{sources[candidate.source].RootID, opaqueID(strings.Join(candidate.rel, "/")), candidate.pluginID, candidate.skillInfo.Size(), uint32(candidate.skillInfo.Mode()), candidate.skillInfo.ModTime().UnixNano(), identity})
	}
	encoded, _ := json.Marshal(struct {
		Sources []SourceV2
		Entries []entry
	}{sources, entries})
	return opaqueID(string(encoded))
}

func opaqueID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}
func markSource(source *SourceV2, reason string) {
	source.Status = "partial"
	for _, old := range source.Reasons {
		if old == reason {
			return
		}
	}
	source.Reasons = append(source.Reasons, reason)
}
func notAssessed(reason string) PackageAssessment {
	return PackageAssessment{Version: AssessmentVersion, Status: "not_assessed", DigestStatus: "incomplete", Risk: "unknown", Findings: []SkillFinding{}, Reasons: []string{reason}}
}

func collectionSources(home, cwd string) []sourceSpec {
	claude := filepath.Join(home, ".claude")
	specs := []sourceSpec{
		{filepath.Join(claude, "skills"), "claude_code", "persistent_standalone", "present", [][]string{{"*"}}, false},
		{filepath.Join(claude, "plugins"), "claude_code", "persistent_plugin", "installed", nil, false},
		// A cache directory proves presence, not installation or enablement.
		{filepath.Join(claude, "plugins"), "claude_code", "marketplace_cache", "cached", [][]string{{"cache", "*", "*", "*", "skills", "*"}, {"marketplaces", "*", "skills", "*"}, {"marketplaces", "*", "plugins", "*", "skills", "*"}}, false},
	}
	if cwd != "" {
		specs = append(specs, sourceSpec{filepath.Join(cwd, ".claude", "skills"), "claude_code", "persistent_standalone", "present", [][]string{{"*"}}, false}, sourceSpec{filepath.Join(cwd, ".claude", "plugins"), "claude_code", "persistent_plugin", "present", [][]string{{"*", "*", "skills", "*"}}, false})
	}
	app := coworkAppSupportDir(home)
	sessions := filepath.Join(app, "local-agent-mode-sessions")
	return append(specs,
		sourceSpec{filepath.Join(sessions, "skills-plugin"), "cowork", "persistent_plugin", "present", nil, true},
		sourceSpec{sessions, "cowork", "session_copy", "session", [][]string{{"*", "*", "local_*", ".claude", "skills", "*"}}, false},
		sourceSpec{sessions, "cowork", "session_upload", "session", [][]string{{"*", "*", "local_*", "uploads"}}, false},
		sourceSpec{app, "cowork", "account_only", "present", nil, false},
	)
}
