package cmd_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A successful initialize with an empty default inventory is misleading when
// the configured upstreams were discarded because their config could not load.
func TestServerRejectsMalformedSelectedConfigurationBeforeMCPInitialize(t *testing.T) {
	cases := []struct {
		name, body         string
		missing, directory bool
	}{
		{name: "boolean_detection", body: `{"mode":"audit","detection":{"threat":true,"sensitive_data":false},"servers":[{"name":"fixture","command":"never-launch-invalid-config"}]}`},
		{name: "invalid_json", body: `{"mode":"audit",`},
		{name: "wrong_servers_shape", body: `{"mode":"audit","servers":{}}`},
		{name: "missing_explicit_path", missing: true},
		{name: "directory_instead_of_config", directory: true},
	}
	for _, tc := range cases {
		for _, source := range []string{"flag", "environment"} {
			t.Run(tc.name+"/"+source, func(t *testing.T) {
				home := t.TempDir()
				path := filepath.Join(home, "selected.json")
				if tc.directory {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				} else if !tc.missing {
					if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
						t.Fatal(err)
					}
				}
				before, _ := os.ReadFile(path)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				args := []string{"server"}
				env := []string{"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "xdg"), "TMPDIR=" + home, "PATH=" + os.Getenv("PATH"), "AGENTKEEPER_COWORK_GUARD=0"}
				if source == "flag" {
					args = []string{"--config", path, "server"}
				} else {
					env = append(env, "AGENTKEEPER_CONFIG="+path)
				}
				command := exec.CommandContext(ctx, binary, args...)
				command.Env = env
				command.Dir = home
				command.Stdin = strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n")
				var stdout, stderr bytes.Buffer
				command.Stdout = &stdout
				command.Stderr = &stderr
				err := command.Run()
				if ctx.Err() != nil {
					t.Fatal("invalid configuration did not exit promptly")
				}
				if err == nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "cannot start MCP Gateway") {
					t.Fatalf("invalid selected config appeared to start: err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
				}
				if strings.Contains(stderr.String(), "using defaults") || strings.Contains(stderr.String(), "servers configured") {
					t.Fatalf("startup silently discarded selected config: %s", stderr.String())
				}
				after, _ := os.ReadFile(path)
				if !bytes.Equal(before, after) {
					t.Fatal("invalid user configuration was overwritten")
				}
				if tc.missing {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("missing selected config was created: %v", err)
					}
				}
			})
		}
	}
}
