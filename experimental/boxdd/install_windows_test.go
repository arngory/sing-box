//go:build windows

package boxdd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNekoStageAndInstallToProgramFiles(t *testing.T) {
	origNames := activeNames
	origOpts := activeOptions
	t.Cleanup(func() {
		activeNames = origNames
		activeOptions = origOpts
	})
	activeNames = nikoTestNames()
	activeOptions.InstallRoot = InstallProgramFiles

	if !windows.GetCurrentProcessToken().IsElevated() {
		_, err := stageAndInstallIntoRoot(os.Args[0], t.TempDir(), true)
		var exitErr *installExitError
		if !errors.As(err, &exitErr) || exitErr.code != InstallExitNotElevated {
			t.Fatalf("non-elevated install err = %v, want exit code %d", err, InstallExitNotElevated)
		}
		t.Skip("skipping elevated Program Files staging test without administrator privileges")
	}

	// Build a self-signed code-signing certificate in CurrentUser\My for this test, sign fake niko.exe
	// and niko-daemon.exe (copies of a valid PE binary, os.Args[0]), and verify staging, tamper rejection,
	// hardlink rejection, junction rejection, and clean update.
	certThumbprint := createTestCodeSigningCert(t)
	t.Cleanup(func() { removeTestCodeSigningCert(certThumbprint) })

	buildPortable := func(t *testing.T) (srcRoot, daemonPath, manifestHash string) {
		t.Helper()
		srcRoot = filepath.Join(t.TempDir(), "portable")
		daemonDir := filepath.Join(srcRoot, "resources", "daemon")
		dataDir := filepath.Join(srcRoot, "data")
		if err := os.MkdirAll(daemonDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dataDir, 0o755); err != nil {
			t.Fatal(err)
		}
		exeBytes, err := os.ReadFile(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		appPath := filepath.Join(srcRoot, activeNames.ApplicationExe)
		daemonPath = filepath.Join(daemonDir, activeNames.DaemonExe)
		if err := os.WriteFile(appPath, exeBytes, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(daemonPath, exeBytes, 0o755); err != nil {
			t.Fatal(err)
		}
		signTestExecutable(t, certThumbprint, appPath)
		signTestExecutable(t, certThumbprint, daemonPath)

		dllPath := filepath.Join(srcRoot, "flutter_windows.dll")
		appSoPath := filepath.Join(dataDir, "app.so")
		if err := os.WriteFile(dllPath, []byte("flutter-dll-v1"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(appSoPath, []byte("app-so-v1"), 0o644); err != nil {
			t.Fatal(err)
		}

		var manifest strings.Builder
		for _, rel := range []string{activeNames.ApplicationExe, "flutter_windows.dll", "data/app.so"} {
			sum, err := sha256File(filepath.Join(srcRoot, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatal(err)
			}
			manifest.WriteString(hex.EncodeToString(sum[:]) + "  " + rel + "\n")
		}
		manifestBytes := []byte(manifest.String())
		if err := os.WriteFile(filepath.Join(srcRoot, "resources", "files.sha256"), manifestBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		mSum := sha256.Sum256(manifestBytes)
		manifestHash = hex.EncodeToString(mSum[:])
		return srcRoot, daemonPath, manifestHash
	}

	installParent := t.TempDir()

	// 1. Happy path: portable -> <installParent>\Niko (even with stray file in portable dir, which is ignored!).
	srcRoot1, daemonPath, manifestHash := buildPortable(t)
	if err := os.WriteFile(filepath.Join(srcRoot1, "stray-user-log.txt"), []byte("ignore-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	activeOptions.InstallManifestSHA256 = manifestHash
	staged, err := stageAndInstallIntoRoot(daemonPath, installParent, true)
	if err != nil {
		t.Fatalf("stageAndInstallIntoRoot: %v", err)
	}
	staged.Commit()
	wantDaemon := filepath.Join(installParent, activeNames.Product, "resources", "daemon", activeNames.DaemonExe)
	if !strings.EqualFold(staged.daemonPath, wantDaemon) {
		t.Fatalf("installedDaemon = %q, want %q", staged.daemonPath, wantDaemon)
	}
	if _, err := os.Stat(filepath.Join(installParent, activeNames.Product, activeNames.ApplicationExe)); err != nil {
		t.Fatalf("installed app missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installParent, activeNames.Product, "stray-user-log.txt")); !os.IsNotExist(err) {
		t.Fatalf("stray file outside manifest was copied into Program Files")
	}

	// 2. Re-install / update over existing target succeeds.
	_, daemonPath2, manifestHash2 := buildPortable(t)
	activeOptions.InstallManifestSHA256 = manifestHash2
	staged2, err := stageAndInstallIntoRoot(daemonPath2, installParent, true)
	if err != nil {
		t.Fatalf("update stageAndInstallIntoRoot: %v", err)
	}
	staged2.Commit()

	// 3. Missing embedded manifest SHA-256 fails closed even when allowUnsafe=true.
	activeOptions.InstallManifestSHA256 = ""
	_, err = stageAndInstallIntoRoot(daemonPath2, t.TempDir(), true)
	var exitErr *installExitError
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitManifestFailed {
		t.Fatalf("missing manifest hash err = %v, want exit %d", err, InstallExitManifestFailed)
	}

	// 4. User-writable installParent fails ancestor check when allowUnsafe=false.
	activeOptions.InstallManifestSHA256 = manifestHash2
	if _, err := stageAndInstallIntoRoot(daemonPath2, t.TempDir(), false); err == nil {
		t.Fatal("expected ancestor permission error on user-writable temp dir with allowUnsafe=false")
	}

	// 5. Tampered DLL fails with InstallExitManifestFailed and cleans up staging.
	tamperParent := t.TempDir()
	tamperRoot, tamperDaemon, tamperHash := buildPortable(t)
	if err := os.WriteFile(filepath.Join(tamperRoot, "flutter_windows.dll"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	activeOptions.InstallManifestSHA256 = tamperHash
	_, err = stageAndInstallIntoRoot(tamperDaemon, tamperParent, true)
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitManifestFailed {
		t.Fatalf("tampered DLL err = %v, want exit %d", err, InstallExitManifestFailed)
	}
	entries, _ := os.ReadDir(tamperParent)
	if len(entries) != 0 {
		t.Fatalf("staging directory leaked after tamper failure: %v", entries)
	}

	// 6. Hard-linked manifest file in source fails with InstallExitInvalidSource.
	hardlinkParent := t.TempDir()
	hardlinkRoot, hardlinkDaemon, hardlinkHash := buildPortable(t)
	if err := os.Link(filepath.Join(hardlinkRoot, "flutter_windows.dll"), filepath.Join(hardlinkRoot, "second-link.dll")); err != nil {
		t.Fatal(err)
	}
	activeOptions.InstallManifestSHA256 = hardlinkHash
	_, err = stageAndInstallIntoRoot(hardlinkDaemon, hardlinkParent, true)
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitInvalidSource {
		t.Fatalf("hardlink err = %v, want exit %d", err, InstallExitInvalidSource)
	}

	// 7. Junction replacing a manifest subdirectory (data/) fails with InstallExitInvalidSource.
	juncParent := t.TempDir()
	juncRoot, juncDaemon, juncHash := buildPortable(t)
	juncTarget := t.TempDir()
	if err := os.WriteFile(filepath.Join(juncTarget, "app.so"), []byte("app-so-v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(juncRoot, "data")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cmd.exe", "/c", "mklink", "/J", filepath.Join(juncRoot, "data"), juncTarget)
	if out, cerr := cmd.CombinedOutput(); cerr != nil {
		t.Fatalf("mklink /J: %v (%s)", cerr, string(out))
	}
	activeOptions.InstallManifestSHA256 = juncHash
	_, err = stageAndInstallIntoRoot(juncDaemon, juncParent, true)
	if !errors.As(err, &exitErr) || exitErr.code != InstallExitInvalidSource {
		t.Fatalf("junction err = %v, want exit %d", err, InstallExitInvalidSource)
	}
}

func createTestCodeSigningCert(t *testing.T) string {
	t.Helper()
	script := `$ErrorActionPreference = 'Stop'; $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Niko Boxdd Test" -CertStoreLocation Cert:\LocalMachine\My; Write-Output $c.Thumbprint`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		t.Fatalf("create test cert: %v (%s)", err, string(out))
	}
	thumb := strings.TrimSpace(string(out))
	if len(thumb) != 40 {
		t.Fatalf("unexpected cert thumbprint %q", thumb)
	}
	return thumb
}

func removeTestCodeSigningCert(thumbprint string) {
	script := `Remove-Item -Path "Cert:\LocalMachine\My\` + thumbprint + `" -Force -ErrorAction SilentlyContinue`
	_ = exec.Command("powershell.exe", "-NoProfile", "-Command", script).Run()
}

func signTestExecutable(t *testing.T, thumbprint, filePath string) {
	t.Helper()
	script := `$ErrorActionPreference = 'Stop'; $c = Get-Item "Cert:\LocalMachine\My\` + thumbprint + `"; $r = Set-AuthenticodeSignature -FilePath "` + filePath + `" -Certificate $c; if ($r.Status -ne 'Valid' -and $r.Status -ne 'UnknownError') { throw "sign failed: $($r.Status) $($r.StatusMessage)" }`
	if out, err := exec.Command("powershell.exe", "-NoProfile", "-Command", script).CombinedOutput(); err != nil {
		t.Fatalf("sign %s: %v (%s)", filePath, err, string(out))
	}
}
