// Package nativeauth classifies MCP server entries that should remain owned by
// the native MCP client because authentication is negotiated there.
package nativeauth

import "strings"

// RequiresNativeClientAuth reports whether a remote HTTP-like MCP entry should
// stay in the client config instead of being proxied by the local gateway. Many
// hosted MCP providers rely on Claude/Cursor/Cowork to perform OAuth; if we move
// those entries behind the gateway without a bearer/header, the provider returns
// 401 and the user's tools disappear.
func RequiresNativeClientAuth(transport, url string, headers map[string]string) bool {
	if !isRemoteHTTP(transport, url) {
		return false
	}
	return !hasCredentialHeader(headers)
}

func isRemoteHTTP(transport, url string) bool {
	if strings.TrimSpace(url) == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "", "http", "sse", "streamable-http":
		return true
	default:
		return false
	}
}

func hasCredentialHeader(headers map[string]string) bool {
	for key, value := range headers {
		if strings.TrimSpace(value) == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token":
			return true
		}
	}
	return false
}
