package config

import "encoding/json"

// Retain unknown client fields through structural rewrites.
// Entries needing unsupported native behavior stay with the original client.
func (s *ServerEntry) UnmarshalJSON(data []byte) error {
	type known ServerEntry
	var decoded known
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, key := range []string{"name", "command", "args", "env", "transport", "type", "url", "headers"} {
		delete(raw, key)
	}
	*s = ServerEntry(decoded)
	if len(raw) > 0 {
		s.Extra = raw
	}
	return nil
}
func (s ServerEntry) MarshalJSON() ([]byte, error) {
	type known ServerEntry
	base, err := json.Marshal(known(s))
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(base, &result); err != nil {
		return nil, err
	}
	for key, value := range s.Extra {
		if _, exists := result[key]; !exists {
			result[key] = value
		}
	}
	return json.Marshal(result)
}
