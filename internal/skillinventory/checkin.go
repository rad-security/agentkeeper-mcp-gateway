package skillinventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// CheckinPayload is the body shape the dashboard's /api/v1/claude-code/checkin
// route expects. Matches plugin/skills/connect/SKILL.md payload field-for-field
// so both ingest paths produce identical rows in host_skill_inventory /
// host_mcp_inventory.
type CheckinPayload struct {
	Hostname           string      `json:"hostname"`
	OS                 string      `json:"os"`
	ClaudeVersion      string      `json:"claude_version,omitempty"`
	CWD                string      `json:"cwd,omitempty"`
	MachineID          string      `json:"machine_id,omitempty"`
	InstalledSkills    []Skill     `json:"installed_skills"`
	InstalledMCPServer []MCPServer `json:"installed_mcp_servers"`
	Source             string      `json:"source,omitempty"` // "gateway-scan-inventory" for telemetry
}

// BuildPayload assembles the full checkin body from a scanned inventory +
// the environmental metadata a Claude Code SessionStart hook provides.
func BuildPayload(inv Inventory, cwd, claudeVersion, machineID string) CheckinPayload {
	hostname, _ := os.Hostname()
	return CheckinPayload{
		Hostname:           hostname,
		OS:                 Platform(),
		ClaudeVersion:      claudeVersion,
		CWD:                cwd,
		MachineID:          machineID,
		InstalledSkills:    inv.Skills,
		InstalledMCPServer: inv.MCPServers,
		Source:             "gateway-scan-inventory",
	}
}

// Send POSTs the payload to {apiURL}/api/v1/claude-code/checkin with the
// provided API key. Fail-open by design: returns the server's response body
// on 2xx; returns a non-fatal error on network/5xx failures so callers can
// decide whether to log or swallow.
//
// apiURL is the base URL (e.g. "https://www.agentkeeper.dev"). The path is appended.
func Send(apiURL, apiKey, machineID string, payload CheckinPayload) ([]byte, error) {
	if apiURL == "" {
		apiURL = "https://www.agentkeeper.dev"
	}
	endpoint := strings.TrimRight(apiURL, "/") + "/api/v1/claude-code/checkin"

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encoding payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if machineID != "" {
		req.Header.Set("X-Machine-Id", machineID)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST checkin: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return respBody, fmt.Errorf("checkin HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
	return respBody, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
