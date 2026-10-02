package cmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
		{"stdio server", []string{"add", "--header", "Authorization:Bearer tok", "local", "npx", "server"}, "remote"},
		{"argument after url", []string{"add", "remote-api", "https://api.example.com/mcp", "extra"}, "unexpected argument"},
		{"no command", []string{"add", "local", "--env", `{"K":"V"}`}, "command or URL"},
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

// Everything after a stdio command is that command's own: add must not parse
// it or consume it as one of its own flags. After an explicit `--` that holds
// even for arguments spelled like add's flags.
func TestAddStdioCommandKeepsItsOwnFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want map[string]interface{}
	}{
		{"flags after command",
			[]string{"add", "fs", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
			map[string]interface{}{"name": "fs", "command": "npx -y @modelcontextprotocol/server-filesystem /tmp"}},
		{"explicit separator",
			[]string{"add", "fs", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
			map[string]interface{}{"name": "fs", "command": "npx -y @modelcontextprotocol/server-filesystem /tmp"}},
		{"quoted command string",
			[]string{"add", "fs", "npx -y @modelcontextprotocol/server-filesystem /tmp"},
			map[string]interface{}{"name": "fs", "command": "npx -y @modelcontextprotocol/server-filesystem /tmp"}},
		{"env before name",
			[]string{"add", "--env", `{"K":"V"}`, "fs", "python3", "server.py"},
			map[string]interface{}{"name": "fs", "command": "python3 server.py", "env": map[string]interface{}{"K": "V"}}},
		{"env between name and command",
			[]string{"add", "fs", "--env", `{"K":"V"}`, "python3", "server.py", "-v"},
			map[string]interface{}{"name": "fs", "command": "python3 server.py -v", "env": map[string]interface{}{"K": "V"}}},
		{"separator before a command with add's flag names",
			[]string{"add", "fs", "--", "python3", "server.py", "--header", "X-Upstream:1", "--env", "prod", "--config", "server.toml", "--help"},
			map[string]interface{}{"name": "fs", "command": "python3 server.py --header X-Upstream:1 --env prod --config server.toml --help"}},
		{"separator before the name",
			[]string{"add", "--", "fs", "python3", "server.py", "--config", "server.toml"},
			map[string]interface{}{"name": "fs", "command": "python3 server.py --config server.toml"}},
		{"separator inside the server arguments",
			[]string{"add", "fs", "python3", "server.py", "--", "--env=prod"},
			map[string]interface{}{"name": "fs", "command": "python3 server.py -- --env=prod"}},
		{"env before name with a server flag",
			[]string{"add", "--env", `{"API_TOKEN":"tok-123"}`, "local-api", "python3", "server.py", "--port", "8080"},
			map[string]interface{}{"name": "local-api", "command": "python3 server.py --port 8080", "env": map[string]interface{}{"API_TOKEN": "tok-123"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			_, stderr, code := run(t, home, tc.args...)
			if code != 0 {
				t.Fatalf("exit %d, stderr: %s", code, stderr)
			}
			servers := readAddedServers(t, home)
			if len(servers) != 1 || !reflect.DeepEqual(servers[0], tc.want) {
				t.Fatalf("servers = %v, want [%v]", servers, tc.want)
			}
		})
	}
}

// The previous release took add's flags after a stdio command, so people type
// them there. Recording them as server arguments would drop the env or config
// path and leave a token in the command string: refuse, and write nothing.
func TestAddRejectsOwnFlagsAfterStdioCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"env", []string{"add", "local-api", "python3", "server.py", "--env", `{"API_TOKEN":"tok-123"}`}, "--env"},
		{"env with equals", []string{"add", "local-api", "python3", "server.py", `--env={"API_TOKEN":"tok-123"}`}, "--env"},
		{"header", []string{"add", "local-api", "python3", "server.py", "--header", "Authorization:Bearer tok-123"}, "--header"},
		{"header with equals", []string{"add", "local-api", "python3", "server.py", "--header=Authorization:Bearer tok-123"}, "--header"},
		{"config", []string{"add", "local-api", "python3", "server.py", "--config", "alt.json"}, "--config"},
		{"config with equals", []string{"add", "local-api", "python3", "server.py", "--config=alt.json"}, "--config"},
		{"directly after the command", []string{"add", "local-api", "python3", "--env", `{"API_TOKEN":"tok-123"}`, "server.py"}, "--env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			configFile := filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")
			if _, stderr, code := run(t, home, "add", "existing", "python3", "x.py"); code != 0 {
				t.Fatalf("seed add: exit %d, stderr: %s", code, stderr)
			}
			before, err := os.ReadFile(configFile)
			if err != nil {
				t.Fatal(err)
			}

			_, stderr, code := runInDir(t, home, home, tc.args...)
			if code == 0 {
				t.Fatalf("expected failure for %v", tc.args)
			}
			for _, want := range []string{tc.want, "before the server command", `"--"`} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("stderr %q does not mention %q", stderr, want)
				}
			}
			if strings.Contains(stderr, "tok-123") {
				t.Fatalf("stderr repeats the flag value: %q", stderr)
			}
			after, err := os.ReadFile(configFile)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("a rejected add changed the config:\nbefore: %s\nafter:  %s", before, after)
			}
			if _, err := os.Stat(filepath.Join(home, "alt.json")); err == nil {
				t.Fatalf("a rejected add wrote the --config path")
			}
		})
	}
}

// A URL takes no arguments, so add's flags keep working after it.
func TestAddRemoteServerAcceptsFlagsAroundURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"header after url", []string{"add", "remote", "https://x.example.test/mcp", "--header", "A:B"}},
		{"header before name", []string{"add", "--header", "A:B", "remote", "https://x.example.test/mcp"}},
		{"header between name and url", []string{"add", "remote", "--header", "A:B", "https://x.example.test/mcp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			_, stderr, code := run(t, home, tc.args...)
			if code != 0 {
				t.Fatalf("exit %d, stderr: %s", code, stderr)
			}
			want := map[string]interface{}{
				"name": "remote", "transport": "http", "url": "https://x.example.test/mcp",
				"headers": map[string]interface{}{"A": "B"},
			}
			servers := readAddedServers(t, home)
			if len(servers) != 1 || !reflect.DeepEqual(servers[0], want) {
				t.Fatalf("servers = %v, want [%v]", servers, want)
			}
		})
	}
}

// --config is honoured wherever add still parses its own flags.
func TestAddHonoursConfigFlagAfterName(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(alt string) []string
	}{
		{"after url", func(alt string) []string {
			return []string{"add", "remote", "https://x.example.test/mcp", "--config", alt}
		}},
		{"between name and command", func(alt string) []string {
			return []string{"add", "fs", "--config", alt, "python3", "server.py"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			alt := filepath.Join(home, "alt.json")
			_, stderr, code := run(t, home, tc.args(alt)...)
			if code != 0 {
				t.Fatalf("exit %d, stderr: %s", code, stderr)
			}
			if _, err := os.Stat(alt); err != nil {
				t.Fatalf("--config path was not written: %v", err)
			}
			if _, err := os.Stat(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")); err == nil {
				t.Fatalf("add wrote the default config instead of the --config path")
			}
		})
	}
}

func TestAddHelpAfterNamePrintsHelpWithoutWriting(t *testing.T) {
	home := t.TempDir()
	stdout, stderr, code := run(t, home, "add", "fs", "--help", "python3", "server.py")
	if code != 0 || !strings.Contains(stdout, "Usage:") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "config.json")); err == nil {
		t.Fatalf("add --help must not write config")
	}
}
