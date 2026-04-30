package machineid

import (
	"errors"
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
	if strings.Contains(got, "00112233") {
		t.Fatalf("MachineGuid must be hashed before upload, got %q", got)
	}
}

func TestDetectWithRunner_NonWindowsReturnsBlank(t *testing.T) {
	got := DetectWithRunner("darwin", func(name string, args ...string) ([]byte, error) {
		t.Fatalf("runner should not be called for non-Windows")
		return nil, nil
	})
	if got != "" {
		t.Fatalf("DetectWithRunner non-Windows = %q, want blank", got)
	}
}
