package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/rad-security/agentkeeper-mcp-gateway/internal/config"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/discovery"
	"github.com/rad-security/agentkeeper-mcp-gateway/internal/manualrouting"
)

// gatewayServerNameSet snapshots the Gateway config before a migration so the
// servers that migration introduces can be told apart from ones that were
// already there.
func gatewayServerNameSet() map[string]bool {
	names := map[string]bool{}
	cfg, err := config.Load()
	if err != nil {
		return names
	}
	for _, server := range cfg.Servers {
		names[server.Name] = true
	}
	return names
}

// recordMigrationOwnership makes a migration performed outside the adapter
// path reversible by `configure-ide --remove-routing`. It is a no-op when the
// migration changed nothing. created reports that the migration wrote a
// client config that did not exist before, which rollback then removes.
func recordMigrationOwnership(client string, plan discovery.MigrationPlan, gatewayBefore map[string]bool, created bool) error {
	if plan.ConfigPath == "" || plan.SkippedGitWorktree || (plan.BackupPath == "" && len(plan.Migrated) == 0 && !created) {
		return nil
	}
	opts := manualrouting.AdoptOptions{
		Client: client, Path: plan.ConfigPath,
		SourceHash: plan.SourceHash, RouteRevision: plan.RouteRevision,
	}
	for _, server := range plan.Servers {
		if server.SourceKind == "cowork_remote_mcp_config" {
			opts.Kind = manualrouting.KindCoworkRemote
			break
		}
	}
	switch {
	case plan.BackupPath != "":
		original, err := os.ReadFile(plan.BackupPath)
		if err != nil {
			return fmt.Errorf("reading pre-route backup for %s: %w", plan.ConfigPath, err)
		}
		opts.Original, opts.OriginalExists = original, true
	case created:
		// The Cowork entrypoint created the client config; rollback removes it.
	default:
		// Servers were imported without rewriting the source file.
		current, err := os.ReadFile(plan.ConfigPath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", plan.ConfigPath, err)
		}
		opts.Original, opts.OriginalExists = current, true
	}
	for _, server := range plan.Migrated {
		name := server.GatewayName
		if name == "" {
			name = server.Name
		}
		opts.ReferencedGatewayServers = append(opts.ReferencedGatewayServers, name)
		if !gatewayBefore[name] {
			opts.AddedGatewayServers = append(opts.AddedGatewayServers, name)
		}
	}
	if err := manualrouting.Adopt(opts); err != nil {
		return fmt.Errorf("routed %s, but could not record it for rollback: %w", plan.ConfigPath, err)
	}
	return nil
}

// ownershipRecordError reports that a migration succeeded but could not be
// recorded for rollback. Callers that must keep serving (the Cowork guard)
// treat it as a warning; the routes it names are live.
type ownershipRecordError struct{ err error }

func (e *ownershipRecordError) Error() string { return e.err.Error() }
func (e *ownershipRecordError) Unwrap() error { return e.err }

// migrateCoworkOwned routes Cowork MCP sources and records every file it
// rewrote, so the routes made by configure-ide, `cowork configure` and the
// Cowork guard are all reversible. Sources rewritten before a failure are
// recorded too: an unrecorded route can never be restored.
func migrateCoworkOwned(sourcePath string, dryRun bool) (discovery.CoworkMigrationResult, error) {
	gatewayBefore := gatewayServerNameSet()
	result, err := discovery.MigrateCoworkMCP(sourcePath, dryRun)
	if dryRun {
		return result, err
	}
	var recordErrs []error
	for _, plan := range result.Plans {
		if recordErr := recordMigrationOwnership(discovery.ClientCowork, plan, gatewayBefore, false); recordErr != nil {
			recordErrs = append(recordErrs, recordErr)
		}
	}
	if entrypoint := result.GatewayEntrypoint; entrypoint != nil && !entrypoint.AlreadyRouted {
		// The entrypoint step either rewrote an existing client config, leaving
		// a backup, or created the config.
		if recordErr := recordMigrationOwnership(discovery.ClientCowork, *entrypoint, gatewayBefore, entrypoint.BackupPath == ""); recordErr != nil {
			recordErrs = append(recordErrs, recordErr)
		}
	}
	if err != nil {
		return result, errors.Join(append([]error{err}, recordErrs...)...)
	}
	if len(recordErrs) > 0 {
		return result, &ownershipRecordError{err: errors.Join(recordErrs...)}
	}
	return result, nil
}
