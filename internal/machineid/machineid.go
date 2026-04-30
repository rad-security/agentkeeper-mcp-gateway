package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

type Runner func(name string, args ...string) ([]byte, error)

func Detect() string {
	return DetectWithRunner(runtime.GOOS, commandOutput)
}

func commandOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func DetectWithRunner(goos string, run Runner) string {
	if goos != "windows" || run == nil {
		return ""
	}

	if out, err := run("dsregcmd", "/status"); err == nil {
		if id := ParseEntraDeviceID(string(out)); id != "" {
			return "entra:" + id
		}
	}

	if out, err := run("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid"); err == nil {
		if guid := ParseMachineGuid(string(out)); guid != "" {
			sum := sha256.Sum256([]byte(strings.ToLower(guid)))
			return "winmg:" + hex.EncodeToString(sum[:])
		}
	}

	return ""
}

func ParseEntraDeviceID(output string) string {
	re := regexp.MustCompile(`(?im)^\s*(?:DeviceId|Device\s+Id)\s*:\s*([0-9a-fA-F-]{36})\s*$`)
	match := re.FindStringSubmatch(output)
	if len(match) != 2 {
		return ""
	}
	return strings.ToLower(match[1])
}

func ParseMachineGuid(output string) string {
	re := regexp.MustCompile(`(?im)\bMachineGuid\b\s+REG_SZ\s+([0-9a-fA-F-]{8,})\s*$`)
	match := re.FindStringSubmatch(output)
	if len(match) != 2 {
		return ""
	}
	return strings.ToLower(match[1])
}
