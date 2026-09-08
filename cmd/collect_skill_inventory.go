package cmd

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/skillinventory"
	"github.com/spf13/cobra"
)

func newCollectSkillInventoryCommand() *cobra.Command {
	var cwd string
	var offset int
	var wirePreview bool
	var metadataOnly bool
	command := &cobra.Command{
		Use:   "collect-skill-inventory",
		Short: "Inspect versioned skill inventory locally without uploading content",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if offset < 0 {
				return fmt.Errorf("assessment offset must not be negative")
			}
			if metadataOnly && wirePreview {
				return fmt.Errorf("metadata probes are local scheduling hints, not wire reports")
			}
			var result skillinventory.CollectionV2
			var err error
			if metadataOnly {
				result, err = skillinventory.ProbeV2(cmd.Context(), skillinventory.ScanOptions{CWD: cwd})
			} else {
				result, err = skillinventory.CollectV2FromCursor(cmd.Context(), skillinventory.ScanOptions{CWD: cwd}, offset)
			}
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if wirePreview {
				identity := func() (string, error) {
					var bytes [16]byte
					if _, err := rand.Read(bytes[:]); err != nil {
						return "", err
					}
					bytes[6] = (bytes[6] & 15) | 64
					bytes[8] = (bytes[8] & 63) | 128
					return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:]), nil
				}
				epoch, err := identity()
				if err != nil {
					return err
				}
				scan, err := identity()
				if err != nil {
					return err
				}
				chunks, err := skillinventory.ChunkCollection(result, epoch, 1, scan)
				if err != nil {
					return err
				}
				return encoder.Encode(chunks)
			}
			return encoder.Encode(result)
		},
	}
	command.Flags().StringVar(&cwd, "cwd", "", "Explicit project directory to include alongside user and Cowork sources")
	command.Flags().IntVar(&offset, "assessment-offset", 0, "Resume bounded package assessment at this local cursor")
	command.Flags().BoolVar(&wirePreview, "wire-preview", false, "Emit metadata-only wire chunks with ephemeral scan IDs; never uploads or advances durable collector state")
	command.Flags().BoolVar(&metadataOnly, "metadata-only", false, "Probe source and SKILL.md metadata without reading skill bodies; local scheduling hint only")
	return command
}

func init() { rootCmd.AddCommand(newCollectSkillInventoryCommand()) }
