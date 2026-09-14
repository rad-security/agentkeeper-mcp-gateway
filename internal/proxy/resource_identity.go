package proxy

import (
	"encoding/base64"
	"encoding/json"
)

func namespacedResourceURI(serverName, uri string) string {
	return "agentkeeper://resource/" + base64.RawURLEncoding.EncodeToString([]byte(serverName)) + "/" + base64.RawURLEncoding.EncodeToString([]byte(uri))
}

// namespaceResourceContents changes only valid resource identity fields. A
// malformed backend result retains its existing handling; schema validation is
// a separate contract from this compatibility repair.
func namespaceResourceContents(response json.RawMessage, serverName string) (json.RawMessage, map[string]resourceRoute) {
	var result map[string]json.RawMessage
	if json.Unmarshal(response, &result) != nil || result == nil {
		return response, nil
	}
	var contents []map[string]json.RawMessage
	if json.Unmarshal(result["contents"], &contents) != nil || contents == nil {
		return response, nil
	}
	routes := make(map[string]resourceRoute, len(contents))
	for _, content := range contents {
		var originalURI string
		if content == nil || json.Unmarshal(content["uri"], &originalURI) != nil || originalURI == "" {
			return response, nil
		}
		uri := namespacedResourceURI(serverName, originalURI)
		content["uri"], _ = json.Marshal(uri)
		routes[uri] = resourceRoute{ServerName: serverName, OriginalURI: originalURI}
	}
	result["contents"], _ = json.Marshal(contents)
	encoded, err := json.Marshal(result)
	if err != nil {
		return response, nil
	}
	return encoded, routes
}

// resourceMetadata merges Gateway provenance without discarding vendor or
// client metadata. Clone both maps so cached upstream manifests stay untouched.
func resourceMetadata(original interface{}, provenance map[string]interface{}) interface{} {
	metadata := make(map[string]interface{})
	if original != nil {
		upstream, ok := original.(map[string]interface{})
		if !ok {
			return original
		}
		for key, value := range upstream {
			metadata[key] = value
		}
	}
	gateway := make(map[string]interface{})
	if upstream, ok := metadata["agentkeeper"].(map[string]interface{}); ok {
		for key, value := range upstream {
			gateway[key] = value
		}
	}
	for key, value := range provenance {
		gateway[key] = value
	}
	metadata["agentkeeper"] = gateway
	return metadata
}
