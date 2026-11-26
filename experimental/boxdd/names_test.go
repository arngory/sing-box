package boxdd

import (
	"runtime"
	"strings"
	"testing"
)

func nikoTestNames() Names {
	return Names{
		Service:            "niko-daemon",
		DisplayName:        "Niko",
		Description:        "Niko's privileged service",
		Product:            "Niko",
		UpdateProductName:  "Niko",
		PipePath:           `\\.\pipe\ProtectedPrefix\Administrators\niko`,
		WorkerPipePrefix:   `\\.\pipe\niko-worker.`,
		WindowsWorkingDir:  ProgramDataDir("Niko"),
		LinuxWorkingDir:    "/var/lib/niko-daemon",
		ApplicationExe:     "niko.exe",
		DaemonExe:          "niko-daemon.exe",
		PolkitActionPrefix: "io.niko.daemon",
	}
}

func TestNekoDefaultNames(t *testing.T) {
	n := DefaultNames()
	if n.Service != "sing-box-daemon" {
		t.Fatalf("Service = %q", n.Service)
	}
	if n.DisplayName != "sing-box Service" {
		t.Fatalf("DisplayName = %q", n.DisplayName)
	}
	if n.Description != "Privileged service for sing-box" {
		t.Fatalf("Description = %q", n.Description)
	}
	if n.Product != "sing-box" || n.UpdateProductName != "sing-box" {
		t.Fatalf("Product = %q / %q", n.Product, n.UpdateProductName)
	}
	if n.PipePath != `\\.\pipe\ProtectedPrefix\Administrators\sing-box` {
		t.Fatalf("PipePath = %q", n.PipePath)
	}
	if n.WorkerPipePrefix != `\\.\pipe\sing-box-worker.` {
		t.Fatalf("WorkerPipePrefix = %q", n.WorkerPipePrefix)
	}
	if !strings.HasSuffix(strings.ToLower(n.WindowsWorkingDir), `\programdata\sing-box-daemon`) {
		t.Fatalf("WindowsWorkingDir = %q", n.WindowsWorkingDir)
	}
	if n.LinuxWorkingDir != "/var/lib/sing-box-daemon" {
		t.Fatalf("LinuxWorkingDir = %q", n.LinuxWorkingDir)
	}
	if n.ApplicationExe != "sing-box.exe" || n.DaemonExe != "sing-box-daemon.exe" {
		t.Fatalf("Exes = %q / %q", n.ApplicationExe, n.DaemonExe)
	}
	if n.PolkitActionPrefix != "io.nekohasekai.sfl" {
		t.Fatalf("PolkitActionPrefix = %q", n.PolkitActionPrefix)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("DefaultNames().Validate(): %v", err)
	}
	if err := nikoTestNames().Validate(); err != nil {
		t.Fatalf("nikoTestNames().Validate(): %v", err)
	}
}

func TestNekoNamesValidate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Names)
	}{
		{"empty service", func(n *Names) { n.Service = "" }},
		{"uppercase service", func(n *Names) { n.Service = "Niko" }},
		{"service with space", func(n *Names) { n.Service = "niko daemon" }},
		{"empty display", func(n *Names) { n.DisplayName = "  " }},
		{"product with slash", func(n *Names) { n.Product = `Niko\Sub` }},
		{"product dot", func(n *Names) { n.Product = "." }},
		{"product dotdot", func(n *Names) { n.Product = ".." }},
		{"product trailing dot", func(n *Names) { n.Product = "Niko." }},
		{"product reserved", func(n *Names) { n.Product = "CON" }},
		{"unprotected pipe", func(n *Names) { n.PipePath = `\\.\pipe\niko` }},
		{"pipe traversal", func(n *Names) { n.PipePath = `\\.\pipe\ProtectedPrefix\Administrators\a\b` }},
		{"bad worker pipe prefix", func(n *Names) { n.WorkerPipePrefix = `C:\tmp\pipe.` }},
		{"relative windows dir", func(n *Names) { n.WindowsWorkingDir = `ProgramData\Niko` }},
		{"windows dir traversal", func(n *Names) { n.WindowsWorkingDir = `C:\ProgramData\..\Niko` }},
		{"windows dir forward slash", func(n *Names) { n.WindowsWorkingDir = `C:\a/../..` }},
		{"windows dir extra colon", func(n *Names) { n.WindowsWorkingDir = `C:\ProgramData\Niko:ads` }},
		{"relative linux dir", func(n *Names) { n.LinuxWorkingDir = "var/lib/niko" }},
		{"linux dir traversal", func(n *Names) { n.LinuxWorkingDir = "/var/lib/../niko" }},
		{"app exe without .exe", func(n *Names) { n.ApplicationExe = "niko" }},
		{"daemon exe with path", func(n *Names) { n.DaemonExe = `daemon\niko-daemon.exe` }},
		{"same exe names", func(n *Names) { n.DaemonExe = n.ApplicationExe }},
		{"single-label polkit", func(n *Names) { n.PolkitActionPrefix = "niko" }},
		{"uppercase polkit", func(n *Names) { n.PolkitActionPrefix = "io.Niko.daemon" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := nikoTestNames()
			tc.mutate(&n)
			if err := n.Validate(); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestNekoApplyOptions(t *testing.T) {
	origNames := activeNames
	origOpts := activeOptions
	origServices := addedServices
	t.Cleanup(func() {
		activeNames = origNames
		activeOptions = origOpts
		addedServices = origServices
		applyNamesToCommands(origNames)
	})

	niko := nikoTestNames()
	manifestHash := strings.Repeat("AB", 32)
	if err := applyOptions(Options{
		Names:                 niko,
		WorkerTransport:       WorkerTransportUnix,
		InstallRoot:           InstallProgramFiles,
		InstallManifestSHA256: manifestHash,
		DevelopmentListen:     false,
	}); err != nil {
		t.Fatalf("applyOptions: %v", err)
	}
	if mainCommand.Use != "niko-daemon" {
		t.Fatalf("mainCommand.Use = %q, want niko-daemon", mainCommand.Use)
	}
	if activeOptions.InstallManifestSHA256 != strings.ToLower(manifestHash) {
		t.Fatalf("manifest hash not normalized: %q", activeOptions.InstallManifestSHA256)
	}
	flag := commandService.PersistentFlags().Lookup("working-directory")
	if flag == nil {
		t.Fatal("missing working-directory flag")
	}
	wantDir := niko.defaultWorkingDirectory()
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		if flag.DefValue != wantDir || flag.Value.String() != wantDir {
			t.Fatalf("working-directory default = (%q, %q), want %q", flag.DefValue, flag.Value.String(), wantDir)
		}
	}

	// Empty manifest hash is accepted by applyOptions so non-install subcommands (version,
	// service status, dev run) work; stageAndInstallIntoRoot fails closed with InstallExitManifestFailed.
	if err := applyOptions(Options{InstallRoot: InstallProgramFiles}); err != nil {
		t.Fatalf("InstallProgramFiles without manifest hash should be deferred to service install: %v", err)
	}
	if err := applyOptions(Options{InstallManifestSHA256: "not-hex"}); err == nil {
		t.Fatal("expected error for invalid manifest hash")
	}
	if err := applyOptions(Options{WorkerTransport: WorkerTransport(99)}); err == nil {
		t.Fatal("expected error for invalid worker transport")
	}
	if err := applyOptions(Options{InstallRoot: InstallRoot(99)}); err == nil {
		t.Fatal("expected error for invalid install root")
	}
}
