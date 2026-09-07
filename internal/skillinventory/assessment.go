package skillinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// AssessmentVersion identifies the algorithm, limits contract and rule catalog.
const AssessmentVersion = "skill-package-v1"

// Rule catalog upgrades must not change artifact identity for unchanged bytes.
const PackageDigestVersion = "sha256-skill-manifest-v1"

type AssessmentLimits struct {
	MaxFiles      int
	MaxDepth      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFindings   int
	Timeout       time.Duration
}

func DefaultAssessmentLimits() AssessmentLimits {
	return AssessmentLimits{1000, 8, 2 << 20, 20 << 20, 200, 10 * time.Second}
}

// PackageAssessment deliberately contains no file contents or matched secrets.
// A digest describes bytes, never their safety. Partial assessment is not clean.
type PackageAssessment struct {
	Version       string         `json:"version"`
	Status        string         `json:"status"`        // complete, partial, failed
	DigestStatus  string         `json:"digest_status"` // complete, incomplete
	PackageDigest string         `json:"package_digest,omitempty"`
	Risk          string         `json:"risk"` // high, medium, low, unknown
	FilesScanned  int            `json:"files_scanned"`
	BytesScanned  int64          `json:"bytes_scanned"`
	Findings      []SkillFinding `json:"findings"`
	Reasons       []string       `json:"reasons"`
}

type SkillFinding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Path       string `json:"path"`
	Line       int    `json:"line"`
}

type manifestEntry struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Executable bool   `json:"executable"`
	SHA256     string `json:"sha256"`
}

// AssessPackage reads a bounded directory through descriptor-relative traversal.
// It never follows package symlinks, executes code, imports modules or uses the
// network. Call asynchronously from inventory work, never on a tool hot path.
func AssessPackage(ctx context.Context, root string, limits AssessmentLimits) PackageAssessment {
	a := PackageAssessment{Version: AssessmentVersion, Status: "complete", DigestStatus: "complete", Risk: "unknown", Findings: []SkillFinding{}, Reasons: []string{}}
	if limits.MaxFiles <= 0 || limits.MaxDepth < 0 || limits.MaxFileBytes <= 0 || limits.MaxTotalBytes <= 0 || limits.MaxFindings <= 0 || limits.Timeout <= 0 {
		a.Status, a.DigestStatus = "failed", "incomplete"
		a.Reasons = append(a.Reasons, "invalid_limits")
		return a
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	mark := func(reason string, digestIncomplete bool) {
		a.Status = "partial"
		if digestIncomplete {
			a.DigestStatus = "incomplete"
		}
		for _, existing := range a.Reasons {
			if existing == reason {
				return
			}
		}
		a.Reasons = append(a.Reasons, reason)
	}
	dir, err := openAssessmentRoot(root)
	if err != nil {
		a.Status, a.DigestStatus = "failed", "incomplete"
		a.Reasons = append(a.Reasons, "root_unavailable_or_unsupported")
		return a
	}
	defer dir.Close()
	manifest := []manifestEntry{}
	entriesSeen := 0
	var walk func(*os.File, string, int)
	walk = func(parent *os.File, prefix string, depth int) {
		before, err := parent.Stat()
		if err != nil {
			mark("unreadable_directory", true)
			return
		}
		for {
			if ctx.Err() != nil {
				mark("scan_deadline", true)
				return
			}
			entries, readErr := parent.ReadDir(100)
			for _, entry := range entries {
				entriesSeen++
				if entriesSeen > limits.MaxFiles*4 {
					mark("entry_limit", true)
					return
				}
				if ctx.Err() != nil {
					mark("scan_deadline", true)
					return
				}
				name := entry.Name()
				rel := name
				if prefix != "" {
					rel = prefix + "/" + name
				}
				if !validAssessmentRelativePath(rel) {
					mark("invalid_filename", true)
					continue
				}
				info, err := entry.Info()
				if err != nil {
					mark("unreadable_entry", true)
					continue
				}
				if info.Mode()&os.ModeSymlink != 0 {
					mark("symlink_skipped", true)
					continue
				}
				if !info.IsDir() && !info.Mode().IsRegular() {
					mark("special_file_skipped", true)
					continue
				}
				child, err := openAssessmentChild(parent, name, info.IsDir())
				if err != nil {
					mark("unreadable_or_changed_entry", true)
					continue
				}
				opened, statErr := child.Stat()
				if statErr != nil || !os.SameFile(info, opened) {
					child.Close()
					mark("changed_during_scan", true)
					continue
				}
				if info.IsDir() {
					if depth >= limits.MaxDepth {
						mark("depth_limit", true)
					} else {
						walk(child, rel, depth+1)
					}
					child.Close()
					continue
				}
				if a.FilesScanned >= limits.MaxFiles {
					child.Close()
					mark("file_limit", true)
					return
				}
				if info.Size() > limits.MaxFileBytes {
					child.Close()
					mark("file_byte_limit", true)
					continue
				}
				remaining := limits.MaxTotalBytes - a.BytesScanned
				if info.Size() > remaining {
					child.Close()
					mark("total_byte_limit", true)
					continue
				}
				bound := limits.MaxFileBytes
				if remaining < bound {
					bound = remaining
				}
				data, readErr := io.ReadAll(io.LimitReader(child, bound+1))
				after, statErr := child.Stat()
				child.Close()
				if readErr != nil || statErr != nil {
					mark("unreadable_file", true)
					continue
				}
				if int64(len(data)) > bound {
					mark("file_changed_or_byte_limit", true)
					continue
				}
				if !info.ModTime().Equal(after.ModTime()) || info.Size() != after.Size() || after.Size() != int64(len(data)) || info.Mode() != after.Mode() {
					mark("changed_during_scan", true)
					continue
				}
				a.FilesScanned++
				a.BytesScanned += int64(len(data))
				hash := sha256.Sum256(data)
				manifest = append(manifest, manifestEntry{rel, int64(len(data)), info.Mode()&0111 != 0, hex.EncodeToString(hash[:])})
				if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
					mark("binary_content_unassessed", false)
					continue
				}
				findings, truncated := assessSkillText(ctx, rel, string(data), limits.MaxFindings-len(a.Findings))
				a.Findings = append(a.Findings, findings...)
				if truncated {
					mark("finding_limit", false)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				mark("unreadable_directory", true)
				break
			}
		}
		after, err := parent.Stat()
		if err != nil || !before.ModTime().Equal(after.ModTime()) {
			mark("changed_during_scan", true)
		}
	}
	walk(dir, "", 0)
	if ctx.Err() != nil {
		mark("scan_deadline", true)
	}
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].Path < manifest[j].Path })
	if len(manifest) == 0 {
		mark("no_readable_files", true)
	}
	if a.DigestStatus == "complete" {
		encoded, _ := json.Marshal(manifest)
		hash := sha256.Sum256(append([]byte(PackageDigestVersion+"\n"), encoded...))
		a.PackageDigest = hex.EncodeToString(hash[:])
	}
	if a.Status == "complete" {
		a.Risk = "low"
	}
	for _, finding := range a.Findings {
		if finding.Severity == "high" {
			a.Risk = "high"
			break
		}
		if finding.Severity == "medium" {
			a.Risk = "medium"
		}
	}
	sort.Strings(a.Reasons)
	sort.Slice(a.Findings, func(i, j int) bool {
		if a.Findings[i].Path != a.Findings[j].Path {
			return a.Findings[i].Path < a.Findings[j].Path
		}
		if a.Findings[i].Line != a.Findings[j].Line {
			return a.Findings[i].Line < a.Findings[j].Line
		}
		return a.Findings[i].RuleID < a.Findings[j].RuleID
	})
	return a
}

func validAssessmentRelativePath(path string) bool {
	if !utf8.ValidString(path) || len(path) > 512 || strings.Contains(path, "\\") {
		return false
	}
	if len(path) >= 2 && path[1] == ':' {
		return false
	}
	for _, char := range path {
		if char < 32 || char == 127 {
			return false
		}
	}
	return true
}
