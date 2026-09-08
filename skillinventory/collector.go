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

// Chunk preserves all observations while respecting the server's byte/record
// limits. The caller owns durable epoch/sequence, replay and acknowledgements.
func Chunk(collection Collection, epoch string, sequence int64, scanID string) ([]Envelope, error) {
	return internal.ChunkCollection(collection, epoch, sequence, scanID)
}
