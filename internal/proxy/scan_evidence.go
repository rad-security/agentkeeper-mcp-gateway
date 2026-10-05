package proxy

import (
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/detection"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/telemetry"
)

// scanEvidence carries the parts of a multi-finding scan that belong in the
// event beyond the primary finding: the other distinct findings, how the
// primary one was decoded, whether the message was truncated, and any session
// correlation lineage.
type scanEvidence struct {
	additional  []map[string]interface{}
	decodedFrom string
	truncated   bool
	correlation map[string]interface{}
}

// attach copies the evidence onto a terminal outcome before it is logged.
func (ev scanEvidence) attach(o logging.ToolCallOutcome) logging.ToolCallOutcome {
	o.AdditionalFindings = ev.additional
	o.DecodedFrom = ev.decodedFrom
	o.ScanTruncated = ev.truncated
	o.Correlation = ev.correlation
	return o
}

// applyScan turns a multi-finding scan into the decision the route applies: the
// primary finding (strictest post-mode verdict, ties broken by severity) and
// the evidence for the rest. decoded_from and additional_findings describe how
// each finding was reached. The caller merges the primary into its running
// verdict exactly as it did the single-finding result.
func (p *Proxy) applyScan(scan detection.ScanResult, synced telemetry.SyncPolicy) (detection.Result, scanEvidence) {
	ev := scanEvidence{truncated: scan.Truncated}
	if len(scan.Findings) == 0 {
		return detection.Result{Verdict: detection.VerdictPass}, ev
	}
	decided := make([]detection.Result, len(scan.Findings))
	primary := 0
	for i, f := range scan.Findings {
		decided[i] = applyDetectionPolicy(detection.Result{
			Verdict:     detection.VerdictWarn,
			PatternName: f.PatternName,
			Severity:    f.Severity,
			Description: f.Description,
			Category:    f.Category,
		}, synced, p.config.Detection)
		if i > 0 && moreDecisive(decided[i], scan.Findings[i], decided[primary], scan.Findings[primary]) {
			primary = i
		}
	}
	for i, f := range scan.Findings {
		if i == primary {
			continue
		}
		entry := map[string]interface{}{
			"pattern_name": f.PatternName,
			"category":     f.Category,
			"severity":     f.Severity,
		}
		if f.DecodedFrom != "" {
			entry["decoded_from"] = f.DecodedFrom
		}
		ev.additional = append(ev.additional, entry)
	}
	ev.decodedFrom = scan.Findings[primary].DecodedFrom
	return decided[primary], ev
}

// moreDecisive reports whether finding a should drive the decision over b:
// a stricter post-mode verdict wins, then a higher severity.
func moreDecisive(aRes detection.Result, aFind detection.Finding, bRes detection.Result, bFind detection.Finding) bool {
	if ar, br := verdictRank(string(aRes.Verdict)), verdictRank(string(bRes.Verdict)); ar != br {
		return ar > br
	}
	return findingSeverityRank(aFind.Severity) > findingSeverityRank(bFind.Severity)
}

func findingSeverityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}
