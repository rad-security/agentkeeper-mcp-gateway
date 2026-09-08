package skillinventory

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

const maxEnvelopeBytes = 1 << 20

type EnvelopeV2 struct {
	SchemaVersion    int             `json:"schema_version"`
	CollectorID      string          `json:"collector_id"`
	CollectorVersion string          `json:"collector_version"`
	Epoch            string          `json:"epoch"`
	Sequence         int64           `json:"sequence"`
	ScanID           string          `json:"scan_id"`
	StartedAt        string          `json:"started_at"`
	CompletedAt      string          `json:"completed_at"`
	ChunkIndex       int             `json:"chunk_index"`
	ChunkCount       int             `json:"chunk_count"`
	Sources          []SourceV2      `json:"sources"`
	Observations     []ObservationV2 `json:"observations"`
}

var inventoryUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// ChunkCollection keeps the complete source list in every chunk, caps both
// records and encoded bytes, and never drops observations to fit transport.
// Epoch/sequence are supplied by the durable coordinator, not wall clock time.
func ChunkCollection(collection CollectionV2, epoch string, sequence int64, scanID string) ([]EnvelopeV2, error) {
	if !inventoryUUID.MatchString(epoch) || !inventoryUUID.MatchString(scanID) || sequence < 1 || sequence > 9007199254740991 {
		return nil, fmt.Errorf("invalid scan identity")
	}
	start, startErr := time.Parse(time.RFC3339Nano, collection.StartedAt)
	end, endErr := time.Parse(time.RFC3339Nano, collection.CompletedAt)
	if startErr != nil || endErr != nil || end.Before(start) || len(collection.Sources) < 1 || len(collection.Sources) > 64 {
		return nil, fmt.Errorf("invalid scan metadata")
	}
	base := EnvelopeV2{2, "gateway-skillinventory", CollectorVersion, epoch, sequence, scanID, collection.StartedAt, collection.CompletedAt, 0, 50, collection.Sources, []ObservationV2{}}
	chunks := []EnvelopeV2{}
	current := base
	for _, item := range collection.Observations {
		candidate := current
		candidate.Observations = append(append([]ObservationV2{}, current.Observations...), item)
		encoded, err := json.Marshal(candidate)
		if err != nil {
			return nil, err
		}
		if len(candidate.Observations) > 200 || len(encoded) > maxEnvelopeBytes {
			if len(current.Observations) == 0 {
				return nil, fmt.Errorf("observation exceeds transport limit")
			}
			chunks = append(chunks, current)
			current = base
			current.ChunkIndex = len(chunks)
			current.Observations = []ObservationV2{item}
			encoded, err = json.Marshal(current)
			if err != nil || len(encoded) > maxEnvelopeBytes {
				return nil, fmt.Errorf("observation exceeds transport limit")
			}
		} else {
			current = candidate
		}
		if len(chunks) >= 50 {
			return nil, fmt.Errorf("scan exceeds chunk limit")
		}
	}
	chunks = append(chunks, current)
	for i := range chunks {
		chunks[i].ChunkCount = len(chunks)
		encoded, err := json.Marshal(chunks[i])
		if err != nil || len(encoded) > maxEnvelopeBytes {
			return nil, fmt.Errorf("scan metadata exceeds transport limit")
		}
	}
	return chunks, nil
}
