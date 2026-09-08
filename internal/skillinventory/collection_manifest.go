package skillinventory

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// A manifest establishes install presence only. It does not attest publisher,
// enabled state, content safety, or invocation identity. Paths outside this
// source are reported as incomplete coverage and are never opened implicitly.
func readInstalledPluginPaths(root *os.File) (map[string]string, []string) {
	paths := map[string]string{}
	f, err := openAssessmentChild(root, "installed_plugins.json", false)
	if err != nil {
		return paths, []string{"install_manifest_unavailable"}
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || before.Size() > 1<<20 {
		return paths, []string{"install_manifest_limit"}
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || len(data) > 1<<20 || before.Size() != after.Size() || after.Size() != int64(len(data)) || !before.ModTime().Equal(after.ModTime()) {
		return paths, []string{"install_manifest_changed_or_unreadable"}
	}
	var manifest struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Plugins == nil {
		return paths, []string{"install_manifest_invalid"}
	}
	partial := false
	conflicts := map[string]bool{}
	count := 0
	for plugin, installs := range manifest.Plugins {
		validName := plugin != "" && len(plugin) <= 256 && utf8.ValidString(plugin)
		for _, char := range plugin {
			if char < 32 || char == 127 {
				validName = false
			}
		}
		if !validName {
			partial = true
			continue
		}
		for _, install := range installs {
			count++
			if count > 1000 {
				return paths, []string{"install_manifest_limit"}
			}
			if !filepath.IsAbs(install.InstallPath) {
				partial = true
				continue
			}
			// root.Name is the descriptor traversal path (canonical platform alias).
			// Normalize only /var vs /private/var aliases via the parent path used
			// to open the root; do not resolve untrusted install path symlinks.
			base := root.Name()
			path := install.InstallPath
			if strings.HasPrefix(base, "/private/var/") && strings.HasPrefix(path, "/var/") {
				path = "/private" + path
			}
			rel, err := filepath.Rel(base, path)
			if err != nil || rel == "." || !validAssessmentRelativePath(filepath.ToSlash(rel)) {
				partial = true
				continue
			}
			parts := strings.Split(filepath.ToSlash(rel), "/")
			valid := len(parts) <= 6
			for _, part := range parts {
				if part == ".." || part == "." || part == "" || len(part) > 256 {
					valid = false
				}
			}
			if !valid {
				partial = true
				continue
			}
			key := strings.Join(parts, "/")
			if old, exists := paths[key]; exists && old != plugin {
				conflicts[key] = true
				partial = true
			}
			paths[key] = plugin
		}
	}
	for key := range conflicts {
		delete(paths, key)
	}
	if partial {
		return paths, []string{"install_manifest_partial"}
	}
	return paths, []string{}
}
