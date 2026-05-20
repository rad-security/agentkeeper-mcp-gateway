package machineid

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestParseEntraDeviceID(t *testing.T) {
	out := `
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
                  DeviceId : AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
`
	got := ParseEntraDeviceID(out)
	want := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if got != want {
		t.Fatalf("DeviceId = %q, want %q", got, want)
	}
}

func TestParseMachineGuid(t *testing.T) {
	out := `
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
    MachineGuid    REG_SZ    00112233-4455-6677-8899-aabbccddeeff
`
	got := ParseMachineGuid(out)
	want := "00112233-4455-6677-8899-aabbccddeeff"
	if got != want {
		t.Fatalf("MachineGuid = %q, want %q", got, want)
	}
}

func TestDetectWithRunner_PrefersEntraDeviceID(t *testing.T) {
	got := DetectWithRunner("windows", func(name string, args ...string) ([]byte, error) {
		if name != "dsregcmd" {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return []byte("DeviceId : AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"), nil
	})
	want := "entra:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if got != want {
		t.Fatalf("DetectWithRunner = %q, want %q", got, want)
	}
}

func TestDetectWithRunner_FallsBackToHashedMachineGuid(t *testing.T) {
	got := DetectWithRunner("windows", func(name string, args ...string) ([]byte, error) {
		switch name {
		case "dsregcmd":
			return nil, errors.New("not joined")
		case "reg":
			return []byte(`MachineGuid    REG_SZ    00112233-4455-6677-8899-aabbccddeeff`), nil
		default:
			t.Fatalf("unexpected command %s %v", name, args)
			return nil, nil
		}
	})
	if !strings.HasPrefix(got, "winmg:") {
		t.Fatalf("DetectWithRunner = %q, want winmg prefix", got)
	}
	if len(strings.TrimPrefix(got, "winmg:")) != 32 {
		t.Fatalf("hashed MachineGuid length = %d, want 32", len(strings.TrimPrefix(got, "winmg:")))
	}
	if strings.Contains(got, "00112233") {
		t.Fatalf("MachineGuid must be hashed before upload, got %q", got)
	}
}

func TestDetectWithRunner_FallsBackToSMBIOSBeforeSerial(t *testing.T) {
	got := DetectWithRunner("windows", func(name string, args ...string) ([]byte, error) {
		switch name {
		case "dsregcmd", "reg":
			return nil, errors.New("not available")
		case "powershell":
			cmd := strings.Join(args, " ")
			if strings.Contains(cmd, "Win32_ComputerSystemProduct") {
				return []byte("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"), nil
			}
			if strings.Contains(cmd, "Win32_BIOS") {
				return []byte("SERIAL-1"), nil
			}
			t.Fatalf("unexpected powershell args %v", args)
			return nil, nil
		default:
			t.Fatalf("unexpected command %s %v", name, args)
			return nil, nil
		}
	})
	want := "smbios:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if got != want {
		t.Fatalf("DetectWithRunner = %q, want %q", got, want)
	}
}

func TestDetectWithRunner_FallsBackToSerialLast(t *testing.T) {
	got := DetectWithRunner("windows", func(name string, args ...string) ([]byte, error) {
		switch name {
		case "dsregcmd", "reg":
			return nil, errors.New("not available")
		case "powershell":
			cmd := strings.Join(args, " ")
			if strings.Contains(cmd, "Win32_ComputerSystemProduct") {
				return []byte("00000000-0000-0000-0000-000000000000"), nil
			}
			if strings.Contains(cmd, "Win32_BIOS") {
				return []byte("SERIAL-1"), nil
			}
			t.Fatalf("unexpected powershell args %v", args)
			return nil, nil
		default:
			t.Fatalf("unexpected command %s %v", name, args)
			return nil, nil
		}
	})
	want := "serial:serial-1"
	if got != want {
		t.Fatalf("DetectWithRunner = %q, want %q", got, want)
	}
}

func TestDetectWithRunner_DarwinUsesIOPlatformUUID(t *testing.T) {
	got := DetectWithRunner("darwin", func(name string, args ...string) ([]byte, error) {
		if name != "ioreg" {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return []byte(`"IOPlatformUUID" = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"`), nil
	})
	want := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if got != want {
		t.Fatalf("DetectWithRunner darwin = %q, want %q", got, want)
	}
}

func TestDetectWithRunnerAndReader_LinuxUsesMachineID(t *testing.T) {
	got := DetectWithRunnerAndReader("linux", func(name string, args ...string) ([]byte, error) {
		t.Fatalf("runner should not be called for linux")
		return nil, nil
	}, func(name string) ([]byte, error) {
		if name == "/etc/machine-id" {
			return []byte("ABCDEF123456\n"), nil
		}
		return nil, errors.New("missing")
	})
	want := "abcdef123456"
	if got != want {
		t.Fatalf("DetectWithRunnerAndReader linux = %q, want %q", got, want)
	}
}

func TestDetectWithRunner_OverrideWins(t *testing.T) {
	t.Setenv("AGENTKEEPER_MACHINE_ID", "  ENTRA:OVERRIDE  ")
	got := DetectWithRunner("windows", func(name string, args ...string) ([]byte, error) {
		t.Fatalf("runner should not be called when override is set")
		return nil, nil
	})
	if got != "entra:override" {
		t.Fatalf("DetectWithRunner override = %q, want entra:override", got)
	}
}

func TestDetectWithRunner_NonWindowsWithoutReaderReturnsBlank(t *testing.T) {
	os.Unsetenv("AGENTKEEPER_MACHINE_ID")
	got := DetectWithRunner("darwin", func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("missing")
	})
	if got != "" {
		t.Fatalf("DetectWithRunner missing darwin = %q, want blank", got)
	}
}
