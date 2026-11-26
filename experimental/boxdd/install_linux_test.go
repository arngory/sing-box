//go:build linux && !android

package boxdd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testNikoLinuxNames() Names {
	return Names{
		Service:            "niko-daemon",
		DisplayName:        "Niko",
		Description:        "Niko's privileged service",
		Product:            "Niko",
		UpdateProductName:  "Niko",
		PipePath:           `\\.\pipe\ProtectedPrefix\Administrators\niko`,
		WorkerPipePrefix:   `\\.\pipe\niko-worker.`,
		WindowsWorkingDir:  `C:\ProgramData\Niko`,
		LinuxWorkingDir:    "/var/lib/niko-daemon",
		ApplicationExe:     "niko.exe",
		DaemonExe:          "niko-daemon.exe",
		PolkitActionPrefix: "io.niko.daemon",
	}
}

func makeFakeLinuxDaemonSource(t *testing.T, daemonBytes, cronetBytes []byte) (string, string) {
	t.Helper()
	src := t.TempDir()
	daemonPath := filepath.Join(src, "niko-daemon")
	if err := os.WriteFile(daemonPath, daemonBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	cronetPath := filepath.Join(src, "libcronet.so")
	if err := os.WriteFile(cronetPath, cronetBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	cronetSum := sha256.Sum256(cronetBytes)
	manifest := hex.EncodeToString(cronetSum[:]) + "  libcronet.so\n"
	if err := os.WriteFile(filepath.Join(src, "files.sha256"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256([]byte(manifest))
	return daemonPath, hex.EncodeToString(manifestSum[:])
}

func TestLinuxInstallGoldenUnitUpgradeRollbackAndUninstall(t *testing.T) {
	origNames := activeNames
	origOpts := activeOptions
	t.Cleanup(func() {
		activeNames = origNames
		activeOptions = origOpts
	})

	daemonV1, manifestV1 := makeFakeLinuxDaemonSource(t, []byte("niko-daemon-v1"), []byte("cronet-v1"))
	activeNames = testNikoLinuxNames()
	activeOptions = Options{InstallManifestSHA256: manifestV1}

	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/local/libexec"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}

	var systemctlCalls []string
	env := linuxInstallEnv{
		rootPrefix:     root,
		selfExePath:    daemonV1,
		requireRoot:    false,
		pkexecUID:      "1000",
		workingDir:     "/var/lib/niko-daemon",
		primaryParent:  "/usr/local/libexec",
		fallbackParent: "/opt",
		runSystemctl: func(args ...string) error {
			systemctlCalls = append(systemctlCalls, strings.Join(args, " "))
			return nil
		},
		queryUnitProp: func(prop string) (string, error) {
			if prop == "ActiveState" {
				return "inactive", nil
			}
			return "", nil
		},
		runRestorecon: func(string) error { return nil },
		checkHealth:   func(string) error { return nil },
		isReadOnlyFS:  func(string) (bool, error) { return false, nil },
	}

	if err := serviceInstallLinux(env); err != nil {
		t.Fatalf("fresh install failed: %v", err)
	}

	// Verify golden systemd unit file
	unitBytes, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/niko-daemon.service"))
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	wantUnit := `# managed-by=niko
[Unit]
Description=Niko's privileged service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/niko/niko-daemon run --working-directory /var/lib/niko-daemon --socket /run/niko-daemon/niko-daemon.sock
StateDirectory=niko-daemon
StateDirectoryMode=0700
RuntimeDirectory=niko-daemon
RuntimeDirectoryMode=0755
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`
	if string(unitBytes) != wantUnit {
		t.Fatalf("systemd unit mismatch:\ngot:\n%s\nwant:\n%s", string(unitBytes), wantUnit)
	}
	if strings.Contains(string(unitBytes), "ProtectHome") {
		t.Fatalf("unit must not set ProtectHome=read-only")
	}

	// Verify staged files, permissions, marker, and PKEXEC_UID owner pre-seeding
	gotDaemon, err := os.ReadFile(filepath.Join(root, "usr/local/libexec/niko/niko-daemon"))
	if err != nil || string(gotDaemon) != "niko-daemon-v1" {
		t.Fatalf("installed daemon mismatch: %q %v", string(gotDaemon), err)
	}
	gotCronet, err := os.ReadFile(filepath.Join(root, "usr/local/libexec/niko/libcronet.so"))
	if err != nil || string(gotCronet) != "cronet-v1" {
		t.Fatalf("installed libcronet.so mismatch: %q %v", string(gotCronet), err)
	}
	ownerBytes, err := os.ReadFile(filepath.Join(root, "var/lib/niko-daemon/owner.json"))
	if err != nil || !strings.Contains(string(ownerBytes), `"user_id":"1000"`) {
		t.Fatalf("owner.json not pre-seeded from PKEXEC_UID: %q %v", string(ownerBytes), err)
	}

	// Upgrade to v2 with simulated health failure -> must roll back cleanly to v1 AND preserve enabled state (B1)!
	daemonV2, manifestV2 := makeFakeLinuxDaemonSource(t, []byte("niko-daemon-v2"), []byte("cronet-v2"))
	activeOptions.InstallManifestSHA256 = manifestV2
	systemctlCalls = nil
	envFail := env
	envFail.selfExePath = daemonV2
	envFail.queryUnitProp = func(prop string) (string, error) {
		switch prop {
		case "ActiveState":
			return "active", nil
		case "UnitFileState":
			return "enabled", nil
		default:
			return "", nil
		}
	}
	envFail.checkHealth = func(string) error { return errors.New("health check boom") }

	if err := serviceInstallLinux(envFail); err == nil {
		t.Fatalf("expected upgrade with failing health check to fail")
	}
	afterRollback, err := os.ReadFile(filepath.Join(root, "usr/local/libexec/niko/niko-daemon"))
	if err != nil || string(afterRollback) != "niko-daemon-v1" {
		t.Fatalf("rollback did not restore v1 daemon: %q %v", string(afterRollback), err)
	}
	joinedCalls := strings.Join(systemctlCalls, " | ")
	if strings.Contains(joinedCalls, "disable --now") {
		t.Fatalf("upgrade rollback must NOT run disable --now: %s", joinedCalls)
	}
	if !strings.Contains(joinedCalls, "enable niko-daemon.service") || !strings.Contains(joinedCalls, "start niko-daemon.service") {
		t.Fatalf("upgrade rollback must re-enable and start previous service: %s", joinedCalls)
	}

	// Upgrade to v2 cleanly -> succeeds
	envOk := envFail
	envOk.checkHealth = func(string) error { return nil }
	if err := serviceInstallLinux(envOk); err != nil {
		t.Fatalf("clean upgrade to v2 failed: %v", err)
	}
	gotV2, _ := os.ReadFile(filepath.Join(root, "usr/local/libexec/niko/niko-daemon"))
	if string(gotV2) != "niko-daemon-v2" {
		t.Fatalf("expected v2 daemon after upgrade, got %q", string(gotV2))
	}

	// Root CLI take-over transfers owner to UID 1001
	if err := serviceTakeOverLinux(envOk, "1001"); err != nil {
		t.Fatalf("serviceTakeOverLinux failed: %v", err)
	}
	ownerBytes, _ = os.ReadFile(filepath.Join(root, "var/lib/niko-daemon/owner.json"))
	if !strings.Contains(string(ownerBytes), `"user_id":"1001"`) {
		t.Fatalf("owner.json not updated by take-over: %q", string(ownerBytes))
	}

	// Uninstall removes unit and marker-managed install dir
	if err := serviceUninstallLinux(envOk); err != nil {
		t.Fatalf("serviceUninstallLinux failed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/systemd/system/niko-daemon.service")); !os.IsNotExist(err) {
		t.Fatalf("unit file still exists after uninstall")
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/local/libexec/niko")); !os.IsNotExist(err) {
		t.Fatalf("install dir still exists after uninstall")
	}
}

func TestLinuxInstallFallbackOptAndConflictChecks(t *testing.T) {
	origNames := activeNames
	origOpts := activeOptions
	t.Cleanup(func() {
		activeNames = origNames
		activeOptions = origOpts
	})

	daemonBin, manifest := makeFakeLinuxDaemonSource(t, []byte("niko-daemon"), []byte("cronet"))
	activeNames = testNikoLinuxNames()
	activeOptions = Options{InstallManifestSHA256: manifest}

	root := t.TempDir()
	_ = os.Chmod(root, 0o755)
	_ = os.MkdirAll(filepath.Join(root, "opt"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0o755)

	env := linuxInstallEnv{
		rootPrefix:     root,
		selfExePath:    daemonBin,
		requireRoot:    false,
		workingDir:     "/var/lib/niko-daemon",
		primaryParent:  "/usr/local/libexec",
		fallbackParent: "/opt",
		runSystemctl:   func(...string) error { return nil },
		queryUnitProp:  func(prop string) (string, error) {
			if prop == "ActiveState" {
				return "inactive", nil
			}
			return "", nil
		},
		runRestorecon:  func(string) error { return nil },
		checkHealth:    func(string) error { return nil },
		isReadOnlyFS: func(p string) (bool, error) {
			return strings.Contains(p, "usr/local"), nil
		},
	}

	// 1. Read-only /usr/local falls back to /opt/niko
	if err := serviceInstallLinux(env); err != nil {
		t.Fatalf("fallback to /opt failed: %v", err)
	}
	unitBytes, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/niko-daemon.service"))
	if !strings.Contains(string(unitBytes), "ExecStart=/opt/niko/niko-daemon ") {
		t.Fatalf("expected /opt/niko ExecStart, got:\n%s", string(unitBytes))
	}

	// 2. Tampered libcronet.so -> exit code 13 (InstallExitManifestFailed)
	_ = os.WriteFile(filepath.Join(filepath.Dir(daemonBin), "libcronet.so"), []byte("tampered!"), 0o644)
	err := serviceInstallLinux(env)
	var exitErr *installExitError
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitManifestFailed {
		t.Fatalf("expected exit %d on tampered libcronet.so, got %v", InstallExitManifestFailed, err)
	}
	_ = os.WriteFile(filepath.Join(filepath.Dir(daemonBin), "libcronet.so"), []byte("cronet"), 0o644)

	// 3. Unmanaged non-empty target directory without .niko-install -> refused (exit 15)
	_ = os.Remove(filepath.Join(root, "opt/niko", linuxInstallMarkerName))
	err = serviceInstallLinux(env)
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitInvalidSource {
		t.Fatalf("expected exit %d on unmanaged target dir, got %v", InstallExitInvalidSource, err)
	}

	// 4. Packaged unit in /usr/lib/systemd/system -> refused (exit 15)
	_ = os.MkdirAll(filepath.Join(root, "usr/lib/systemd/system"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/lib/systemd/system/niko-daemon.service"), []byte("[Unit]\n"), 0o644)
	err = serviceInstallLinux(env)
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitInvalidSource {
		t.Fatalf("expected exit %d when packaged unit exists, got %v", InstallExitInvalidSource, err)
	}
	_ = os.Remove(filepath.Join(root, "usr/lib/systemd/system/niko-daemon.service"))

	// 5. Release build without embedded manifestSHA256 must fail closed (I7)
	activeOptions.InstallManifestSHA256 = ""
	activeOptions.DevelopmentListen = false
	err = serviceInstallLinux(env)
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitManifestFailed {
		t.Fatalf("expected fail-closed exit %d when manifestSHA256 is empty, got %v", InstallExitManifestFailed, err)
	}
	activeOptions.InstallManifestSHA256 = manifest

	// 6. Masked unit (/etc/systemd/system/niko-daemon.service -> /dev/null) must be refused (I10)
	_ = os.Remove(filepath.Join(root, "etc/systemd/system/niko-daemon.service"))
	_ = os.Symlink("/dev/null", filepath.Join(root, "etc/systemd/system/niko-daemon.service"))
	err = serviceInstallLinux(env)
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitInvalidSource {
		t.Fatalf("expected exit %d on masked unit symlink, got %v", InstallExitInvalidSource, err)
	}
	_ = os.Remove(filepath.Join(root, "etc/systemd/system/niko-daemon.service"))

	// 7. Unmanaged /etc unit without # managed-by=niko header must NOT be deleted by uninstall (I14)
	_ = os.WriteFile(filepath.Join(root, "etc/systemd/system/niko-daemon.service"), []byte("[Unit]\nDescription=Custom\n"), 0o644)
	err = serviceUninstallLinux(env)
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitInvalidSource {
		t.Fatalf("expected exit %d uninstalling unmanaged /etc unit, got %v", InstallExitInvalidSource, err)
	}
}

func TestValidateProtectedLinuxDirectoryOstreeSymlink(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0o755)
	_ = os.MkdirAll(filepath.Join(root, "var/usrlocal/libexec"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "usr"), 0o755)
	if err := os.Symlink("/var/usrlocal", filepath.Join(root, "usr/local")); err != nil {
		t.Fatal(err)
	}

	if err := validateProtectedLinuxDirectoryAt("/usr/local/libexec", root, false); err != nil {
		t.Fatalf("ostree-style symlink should be accepted: %v", err)
	}

	// World-writable target directory must be rejected
	if err := os.Chmod(filepath.Join(root, "var/usrlocal/libexec"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateProtectedLinuxDirectoryAt("/usr/local/libexec", root, false); err == nil {
		t.Fatalf("world-writable resolved target must be rejected")
	}
}

func TestParseSystemdExecStartPath(t *testing.T) {
	raw := "{ path=/usr/local/libexec/niko/niko-daemon ; argv[]=/usr/local/libexec/niko/niko-daemon run --working-directory /var/lib/niko-daemon ; ignore_errors=no }"
	if got := parseSystemdExecStartPath(raw); got != "/usr/local/libexec/niko/niko-daemon" {
		t.Fatalf("got %q", got)
	}
}
