package cmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readAddedServers(t *testing.T, home string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Servers []map[string]interface{} `json:"servers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg.Servers
}

func TestAddRemoteServerPersistsHeaders(t *testing.T) {
	home := t.TempDir()
	_, stderr, code := run(t, home, "add", "remote-api", "https://api.example.com/mcp",
		"--header", "Authorization:Bearer tok", "--header", "X-Org: acme:west")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	servers := readAddedServers(t, home)
	if len(servers) != 1 {
		t.Fatalf("servers = %v", servers)
	}
	server := servers[0]
	if server["url"] != "https://api.example.com/mcp" || server["transport"] != "http" {
		t.Fatalf("unexpected remote entry: %v", server)
	}
	headers, _ := server["headers"].(map[string]interface{})
	if headers["Authorization"] != "Bearer tok" || headers["X-Org"] != "acme:west" || len(headers) != 2 {
		t.Fatalf("headers were not persisted exactly: %v", server["headers"])
	}
}

func TestAddRejectsMalformedOrMisplacedHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"missing separator", []string{"add", "remote-api", "https://api.example.com/mcp", "--header", "Authorization"}, "key:value"},
		{"empty key", []string{"add", "remote-api", "https://api.example.com/mcp", "--header", ":value"}, "key:value"},
		{"stdio server", []string{"add", "local", "npx", "server", "--header", "Authorization:Bearer tok"}, "remote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			_, stderr, code := run(t, home, tc.args...)
			if code == 0 {
				t.Fatalf("expected failure for %v", tc.args)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr %q does not mention %q", stderr, tc.want)
			}
			if _, err := os.Stat(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")); err == nil {
				t.Fatalf("a rejected add must not write config")
			}
		})
	}
}
