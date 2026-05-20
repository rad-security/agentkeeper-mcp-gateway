package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

type Runner func(name string, args ...string) ([]byte, error)
type FileReader func(name string) ([]byte, error)

func Detect() string {
	return DetectWithRunnerAndReader(runtime.GOOS, commandOutput, os.ReadFile)
}

func commandOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func DetectWithRunner(goos string, run Runner) string {
	return DetectWithRunnerAndReader(goos, run, nil)
}

func DetectWithRunnerAndReader(goos string, run Runner, readFile FileReader) string {
	if override := normalize(os.Getenv("AGENTKEEPER_MACHINE_ID")); override != "" {
		return override
	}

	switch goos {
	case "darwin":
		if run == nil {
			return ""
		}
		if out, err := run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
			return normalize(ParseIOPlatformUUID(string(out)))
		}
		return ""
	case "windows":
		if run == nil {
			return ""
		}
	default:
		if readFile == nil {
			return ""
		}
		for _, path := range []string{"/etc/machine-id", "/sys/class/dmi/id/product_uuid"} {
			if out, err := readFile(path); err == nil {
				if id := normalize(string(out)); id != "" {
					return id
				}
			}
		}
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
			return "winmg:" + hex.EncodeToString(sum[:])[:32]
		}
	}

	if out, err := run("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", `try { $v = (Get-CimInstance Win32_ComputerSystemProduct).UUID; if ($v) { [Console]::Write($v) } } catch {}`); err == nil {
		if uuid := ParseSMBIOSUUID(string(out)); uuid != "" {
			return "smbios:" + uuid
		}
	}

	if out, err := run("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", `try { $v = (Get-CimInstance Win32_BIOS | Select-Object -First 1).SerialNumber; if ($v) { [Console]::Write($v) } } catch {}`); err == nil {
		if serial := ParseBIOSSerial(string(out)); serial != "" {
			return "serial:" + serial
		}
	}

	return ""
}

func normalize(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), ""))
}

func ParseIOPlatformUUID(output string) string {
	re := regexp.MustCompile(`(?m)"IOPlatformUUID"\s*=\s*"([^"]+)"`)
	match := re.FindStringSubmatch(output)
	if len(match) != 2 {
		return ""
	}
	return normalize(match[1])
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

func ParseSMBIOSUUID(output string) string {
	id := normalize(output)
	if id == "" ||
		id == "00000000-0000-0000-0000-000000000000" ||
		id == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		return ""
	}
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !re.MatchString(id) {
		return ""
	}
	return id
}

func ParseBIOSSerial(output string) string {
	serial := normalize(output)
	switch serial {
	case "", "tobefilledbyo.e.m.", "defaultstring", "systemserialnumber", "none", "unknown", "notspecified":
		return ""
	}
	if regexp.MustCompile(`^0+$`).MatchString(serial) {
		return ""
	}
	return serial
}
