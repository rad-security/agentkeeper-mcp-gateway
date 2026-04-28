package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
)

const (
	defaultAPIURL = "https://www.agentkeeper.dev"
	pollInterval  = 3 * time.Second
	pollTimeout   = 100 * time.Second
)

// DeviceCodeResponse from the register endpoint.
type DeviceCodeResponse struct {
	Code      string `json:"code"`
	VerifyURL string `json:"verify_url"`
	PollURL   string `json:"poll_url"`
}

// PollResponse from the poll endpoint.
type PollResponse struct {
	Status  string `json:"status"` // "pending", "approved", "expired"
	APIKey  string `json:"api_key,omitempty"`
	OrgName string `json:"org_name,omitempty"`
	Plan    string `json:"plan,omitempty"`
}

// Login performs the device authorization flow.
func Login() error {
	cfg, _ := config.Load()
	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	// 1. Register device code
	resp, err := http.Post(apiURL+"/api/v1/device/register", "application/json", nil)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", apiURL, err)
	}
	defer resp.Body.Close()

	var device DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&device); err != nil {
		return fmt.Errorf("invalid response from register: %w", err)
	}

	// 2. Show code to user
	fmt.Printf("\nOpening browser to approve this device...\n\n")
	fmt.Printf("  Device code: %s\n\n", device.Code)
	fmt.Printf("  If the browser didn't open:\n")
	fmt.Printf("  %s\n\n", device.VerifyURL)
	fmt.Printf("Waiting for approval...\n")

	// Try to open browser
	openBrowser(device.VerifyURL)

	// 3. Poll for approval
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)

		pollResp, err := http.Get(apiURL + "/api/v1/device/poll?code=" + device.Code)
		if err != nil {
			continue
		}

		var poll PollResponse
		json.NewDecoder(pollResp.Body).Decode(&poll)
		pollResp.Body.Close()

		switch poll.Status {
		case "approved":
			// Save API key
			if err := config.SaveAPIKey(poll.APIKey); err != nil {
				return fmt.Errorf("saving API key: %w", err)
			}

			fmt.Printf("\nConnected!\n")
			fmt.Printf("  Organization: %s\n", poll.OrgName)
			fmt.Printf("  Plan: %s\n", poll.Plan)
			fmt.Printf("\nRestart the gateway to activate.\n")
			return nil

		case "expired":
			return fmt.Errorf("device code expired — run 'auth login' again")
		}
	}

	return fmt.Errorf("timed out waiting for approval — run 'auth login' again")
}

// Status checks the current auth status.
func Status() error {
	cfg, _ := config.Load()
	if cfg.APIKey == "" {
		fmt.Println("Not connected. Run 'agentkeeper-mcp-gateway auth login' to connect.")
		return nil
	}

	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	// Check key validity
	req, _ := http.NewRequest("GET", apiURL+"/api/v1/claude-code/health", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Connected but API unreachable: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)

	if health["ok"] == true {
		fmt.Printf("Connected\n")
		if name, ok := health["org_name"]; ok {
			fmt.Printf("  Organization: %v\n", name)
		}
		if plan, ok := health["plan"]; ok {
			fmt.Printf("  Plan: %v\n", plan)
		}
	} else {
		fmt.Println("API key may be invalid. Run 'agentkeeper-mcp-gateway auth login' to reconnect.")
	}

	return nil
}

// Logout removes the stored API key.
func Logout() error {
	cfg, _ := config.Load()
	cfg.APIKey = ""
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Println("Logged out. Gateway will run in local-only mode.")
	return nil
}

func openBrowser(url string) {
	// Best-effort browser open
	var cmd string
	var args []string
	switch {
	case isCommandAvailable("open"):
		cmd = "open"
		args = []string{url}
	case isCommandAvailable("xdg-open"):
		cmd = "xdg-open"
		args = []string{url}
	case isCommandAvailable("wslview"):
		cmd = "wslview"
		args = []string{url}
	default:
		return
	}
	exec.Command(cmd, args...).Start()
}

func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
