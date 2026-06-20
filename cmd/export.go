package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/logging"
	"github.com/spf13/cobra"
)

var (
	exportFormat string
	exportSince  string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export gateway event logs",
	Long:  `Export recorded MCP gateway events in JSON or CSV format.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load()
		events, err := readExportEvents(defaultExportLogPath(cfg), exportSince)
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(exportFormat)) {
		case "json":
			data, err := json.MarshalIndent(events, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		case "csv":
			return writeExportCSV(cmd.OutOrStdout(), events)
		default:
			return fmt.Errorf("unsupported format %q: use json or csv", exportFormat)
		}
		return nil
	},
}

func defaultExportLogPath(cfg config.Config) string {
	if strings.TrimSpace(cfg.LogPath) != "" {
		return cfg.LogPath
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "agentkeeper-mcp-gateway", "events.jsonl")
}

func readExportEvents(path, since string) ([]logging.Event, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("cannot determine gateway event log path")
	}
	var sinceTime *time.Time
	if strings.TrimSpace(since) != "" {
		parsed, err := time.Parse("2006-01-02", strings.TrimSpace(since))
		if err != nil {
			return nil, fmt.Errorf("invalid --since date %q: use YYYY-MM-DD", since)
		}
		sinceTime = &parsed
	}

	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return []logging.Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var events []logging.Event
	for {
		var event logging.Event
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("reading event log: %w", err)
		}
		if sinceTime != nil {
			eventTime, err := time.Parse(time.RFC3339Nano, event.Timestamp)
			if err != nil || eventTime.Before(*sinceTime) {
				continue
			}
		}
		events = append(events, event)
	}
	return events, nil
}

func writeExportCSV(out io.Writer, events []logging.Event) error {
	writer := csv.NewWriter(out)
	if err := writer.Write([]string{
		"timestamp",
		"event_type",
		"server_name",
		"tool_name",
		"verdict",
		"severity",
		"pattern_name",
		"category",
		"description",
	}); err != nil {
		return err
	}
	for _, event := range events {
		if err := writer.Write([]string{
			event.Timestamp,
			event.EventType,
			event.ServerName,
			event.ToolName,
			event.Verdict,
			event.Severity,
			event.PatternName,
			event.Category,
			event.Description,
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "json", "Output format (json or csv)")
	exportCmd.Flags().StringVar(&exportSince, "since", "", "Export events since date (YYYY-MM-DD)")
	rootCmd.AddCommand(exportCmd)
}
