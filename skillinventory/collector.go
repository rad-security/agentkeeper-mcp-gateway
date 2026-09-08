// Package skillinventory exposes the canonical read-only collector to the
// native AgentKeeper runtime. It deliberately exposes no authentication,
// transport, configuration mutation, command registration or enforcement API.
package skillinventory

import (
	"context"
	internal "github.com/rad-security/agentkeeper-mcp-gateway/internal/skillinventory"
)

const CollectorVersion = internal.CollectorVersion

type ScanOptions = internal.ScanOptions
type Collection = internal.CollectionV2
type Source = internal.SourceV2
type Observation = internal.ObservationV2
type Envelope = internal.EnvelopeV2
type Assessment = internal.PackageAssessment
type Finding = internal.SkillFinding

// Collect reads only recognized skill sources under the requested user/project
// root. Call from a background collector, never from the tool evaluation path.
// Retain NextAssessmentOffset across calls to avoid bounded-pass starvation.
func Collect(ctx context.Context, opts ScanOptions, assessmentOffset int) (Collection, error) {
	return internal.CollectV2FromCursor(ctx, opts, assessmentOffset)
}

// CollectWithAssessmentHints prioritizes new/changed metadata on selected
// background passes. Alternate priority-applied passes with ordinary passes to
// preserve rotation fairness. Persist returned hints locally, never as approvals.
func CollectWithAssessmentHints(ctx context.Context, opts ScanOptions, assessmentOffset int, previous map[string]string, prioritize bool) (Collection, error) {
	return internal.CollectV2WithAssessmentHints(ctx, opts, assessmentOffset, previous, prioritize)
}

// Probe returns a bounded metadata change hint for install/SKILL.md changes.
// Resource-file content changes still require periodic full-package assessment.
// A probe fingerprint is never suitable for approval or enforcement decisions.
func Probe(ctx context.Context, opts ScanOptions) (Collection, error) {
	return internal.ProbeV2(ctx, opts)
}

// Chunk preserves all observations while respecting the server's byte/record
// limits. The caller owns durable epoch/sequence, replay and acknowledgements.
func Chunk(collection Collection, epoch string, sequence int64, scanID string) ([]Envelope, error) {
	return internal.ChunkCollection(collection, epoch, sequence, scanID)
}
