package discovery

import (
	"os"
	"path/filepath"
)

// insideGitWorktree reports whether the file at path sits inside a git
// worktree, i.e. a .git entry (directory for a normal clone, file for a
// linked worktree or submodule) exists in its directory or any parent.
//
// Rewriting MCP config files that live inside a customer's repository puts
// AgentKeeper-authored changes into their commits and PRs, so migration
// callers use this to refuse those writes unless the user asked explicitly
// (configure-ide --cwd / --scope=project).
func insideGitWorktree(path string) bool {
	dir := filepath.Dir(path)
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
