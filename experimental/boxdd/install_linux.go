//go:build linux && !android

package boxdd

// niko: safe Linux systemd service install, uninstall, and root take-over (Phase P3: C1 + C2).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/tailscale/atomicfile"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

const (
	linuxInstallMarkerName  = ".niko-install"
	linuxDaemonManifestName = "files.sha256"
	linuxUnitManagedHeader  = "# managed-by=niko\n"
	maxLinuxSymlinkDepth    = 16
	linuxHealthWaitTimeout  = 10 * time.Second
)

var safeSystemdPathRegexp = regexp.MustCompile(`^/[A-Za-z0-9/._-]+$`)

type linuxInstallEnv struct {
	rootPrefix     string
	selfExePath    string
	requireRoot    bool
	pkexecUID      string
	workingDir     string
	primaryParent  string
	fallbackParent string
	runSystemctl   func(args ...string) error
	queryUnitProp  func(property string) (string, error)
	runRestorecon  func(path string) error
	checkHealth    func(socketPath string) error
	isReadOnlyFS   func(path string) (bool, error)
}

func defaultLinuxInstallEnv() linuxInstallEnv {
	uid := strings.TrimSpace(os.Getenv("PKEXEC_UID"))
	if uid == "" {
		uid = strings.TrimSpace(os.Getenv("SUDO_UID"))
	}
	return linuxInstallEnv{
		rootPrefix:     "",
		selfExePath:    "/proc/self/exe",
		requireRoot:    true,
		pkexecUID:      uid,
		workingDir:     commandServiceFlagWorkingDirectory,
		primaryParent:  "/usr/local/libexec",
		fallbackParent: "/opt",
		runSystemctl:   runSystemctl,
		queryUnitProp:  systemctlProperty,
		runRestorecon:  defaultRunRestorecon,
		checkHealth:    defaultLinuxHealthCheck,
		isReadOnlyFS:   defaultLinuxIsReadOnlyFS,
	}
}

func linuxDaemonBinaryName(names Names) string {
	return names.Service
}

func linuxDefaultSocketPath(names Names) string {
	return "/run/" + names.Service + "/" + names.Service + ".sock"
}

func linuxInstallDirName(names Names) string {
	return strings.ToLower(names.Product)
}

func (e linuxInstallEnv) hostPath(absPath string) string {
	if e.rootPrefix == "" {
		return absPath
	}
	return filepath.Join(e.rootPrefix, strings.TrimPrefix(filepath.Clean(absPath), "/"))
}

func defaultRunRestorecon(path string) error {
	bin, err := exec.LookPath("restorecon")
	if err != nil {
		return nil
	}
	output, err := exec.Command(bin, "-RF", path).CombinedOutput()
	if err != nil {
		log.Warn("restorecon ", path, ": ", strings.TrimSpace(string(output)), " (", err, ")")
	}
	return nil
}

func defaultLinuxIsReadOnlyFS(path string) (bool, error) {
	probe := path
	for {
		var st unix.Statfs_t
		err := unix.Statfs(probe, &st)
		if err == nil {
			return st.Flags&unix.ST_RDONLY != 0, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return false, err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return false, err
		}
		probe = parent
	}
}

func defaultLinuxHealthCheck(socketPath string) error {
	deadline := time.Now().Add(linuxHealthWaitTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := probeUnixHealth(ctx, socketPath)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	return E.Cause(lastErr, "daemon did not become healthy at ", socketPath)
}

func probeUnixHealth(ctx context.Context, socketPath string) error {
	cc, err := grpc.NewClient(
		"passthrough:///unix-health",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(dialCtx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dialCtx, "unix", socketPath)
		}),
	)
	if err != nil {
		return err
	}
	defer cc.Close()
	client := grpc_health_v1.NewHealthClient(cc)
	resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{
		Service: DesktopService_ServiceDesc.ServiceName,
	})
	if err != nil {
		return err
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		return E.New("unexpected health status: ", resp.Status.String())
	}
	return nil
}

// validateProtectedLinuxDirectory verifies that every path component leading to directory
// is owned by root and not writable by group or others. Root-owned symlinks (e.g. ostree's
// /usr/local -> /var/usrlocal or /opt -> /var/opt) are resolved and validated safely.
func validateProtectedLinuxDirectory(directory string) error {
	return validateProtectedLinuxDirectoryAt(directory, "", true)
}

func validateProtectedLinuxDirectoryAt(directory string, rootPrefix string, requireRoot bool) error {
	if !filepath.IsAbs(directory) {
		return E.New("protected path must be absolute: ", directory)
	}
	cleanTarget := filepath.Clean(directory)
	return validateLinuxPathChain(cleanTarget, rootPrefix, requireRoot, 0)
}

func validateLinuxPathChain(absTarget string, rootPrefix string, requireRoot bool, depth int) error {
	if depth > maxLinuxSymlinkDepth {
		return E.New("too many symlinks resolving protected path: ", absTarget)
	}
	rootDir := "/"
	if rootPrefix != "" {
		rootDir = filepath.Clean(rootPrefix)
	}
	if err := checkProtectedDirNode(rootDir, requireRoot); err != nil {
		return err
	}
	trimmed := strings.TrimPrefix(filepath.Clean(absTarget), "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	curAbs := "/"
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return E.New("invalid parent traversal in protected path: ", absTarget)
		}
		nextAbs := filepath.Join(curAbs, part)
		hostNode := nextAbs
		if rootPrefix != "" {
			hostNode = filepath.Join(rootPrefix, strings.TrimPrefix(nextAbs, "/"))
		}
		info, err := os.Lstat(hostNode)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if requireRoot {
				st, ok := info.Sys().(*syscall.Stat_t)
				if !ok || st.Uid != 0 {
					return E.New("protected symlink is not owned by root: ", nextAbs)
				}
			}
			linkTarget, err := os.Readlink(hostNode)
			if err != nil {
				return err
			}
			var resolved string
			if filepath.IsAbs(linkTarget) {
				resolved = filepath.Clean(linkTarget)
			} else {
				resolved = filepath.Clean(filepath.Join(curAbs, linkTarget))
			}
			if i+1 < len(parts) {
				resolved = filepath.Join(append([]string{resolved}, parts[i+1:]...)...)
			}
			return validateLinuxPathChain(resolved, rootPrefix, requireRoot, depth+1)
		}
		if err := checkProtectedDirInfo(nextAbs, info, requireRoot); err != nil {
			return err
		}
		curAbs = nextAbs
	}
	return nil
}

func checkProtectedDirNode(hostPath string, requireRoot bool) error {
	info, err := os.Lstat(hostPath)
	if err != nil {
		return err
	}
	return checkProtectedDirInfo(hostPath, info, requireRoot)
}

func checkProtectedDirInfo(displayPath string, info os.FileInfo, requireRoot bool) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return E.New("protected path is not a directory: ", displayPath)
	}
	if requireRoot {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return E.New("protected path is not owned by root: ", displayPath)
		}
	}
	if info.Mode().Perm()&0o022 != 0 {
		return E.New("protected path is writable by non-root users: ", displayPath)
	}
	return nil
}

func validateSafeSystemdPath(label, p string) error {
	clean := filepath.Clean(p)
	if clean != p || !safeSystemdPathRegexp.MatchString(clean) || strings.Contains(clean, "..") {
		return &installExitError{
			code: InstallExitInvalidSource,
			err:  E.New("unsafe ", label, " path for systemd unit: ", p),
		}
	}
	return nil
}

func renderLinuxSystemdUnit(names Names, installDir string, workingDir string, socketPath string) string {
	daemonPath := filepath.Join(installDir, linuxDaemonBinaryName(names))
	return fmt.Sprintf(`%s[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run --working-directory %s --socket %s
StateDirectory=%s
StateDirectoryMode=0700
RuntimeDirectory=%s
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
`,
		linuxUnitManagedHeader,
		names.Description,
		daemonPath,
		workingDir,
		socketPath,
		names.Service,
		names.Service,
	)
}

func acquireLinuxInstallLock(env linuxInstallEnv) (func(), error) {
	runDir := env.hostPath("/run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(runDir, activeNames.Service+".install.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, &installExitError{
			code: InstallExitTargetBusy,
			err:  E.Cause(err, "another service install/uninstall is already running"),
		}
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

func cleanupStaleLinuxTempDirs(parentHost string, dirName string) {
	entries, err := os.ReadDir(parentHost)
	if err != nil {
		return
	}
	prefixes := []string{
		"." + dirName + ".staging-",
		"." + dirName + ".old-",
		"." + dirName + ".failed-",
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		matched := false
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		full := filepath.Join(parentHost, name)
		if info, err := os.Lstat(filepath.Join(full, linuxInstallMarkerName)); err == nil && info.Mode().IsRegular() {
			_ = os.RemoveAll(full)
		}
	}
}

func checkNoConflictingLinuxUnit(env linuxInstallEnv, unitName string, etcUnitPath string) error {
	for _, pkgDir := range []string{
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
		"/usr/local/lib/systemd/system",
		"/run/systemd/system",
	} {
		pkgUnit := env.hostPath(filepath.Join(pkgDir, unitName))
		if _, err := os.Lstat(pkgUnit); err == nil {
			return &installExitError{
				code: InstallExitInvalidSource,
				err:  E.New("an external systemd unit already exists at ", filepath.Join(pkgDir, unitName), "; update or remove it with your package manager"),
			}
		}
	}
	dropInDir := env.hostPath(filepath.Join("/etc/systemd/system", unitName+".d"))
	if entries, err := os.ReadDir(dropInDir); err == nil && len(entries) > 0 {
		return &installExitError{
			code: InstallExitInvalidSource,
			err:  E.New("systemd drop-in overrides exist in /etc/systemd/system/", unitName, ".d; refusing to overwrite"),
		}
	}
	if env.queryUnitProp != nil {
		if frag, err := env.queryUnitProp("FragmentPath"); err == nil && frag != "" {
			expected := filepath.Join("/etc/systemd/system", unitName)
			if filepath.Clean(frag) != expected {
				return &installExitError{
					code: InstallExitInvalidSource,
					err:  E.New("service unit is managed externally at ", frag),
				}
			}
		}
		if dropIns, err := env.queryUnitProp("DropInPaths"); err == nil && strings.TrimSpace(dropIns) != "" {
			return &installExitError{
				code: InstallExitInvalidSource,
				err:  E.New("systemd drop-in overrides exist: ", strings.TrimSpace(dropIns)),
			}
		}
	}
	if info, err := os.Lstat(etcUnitPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return &installExitError{
				code: InstallExitInvalidSource,
				err:  E.New("refusing to overwrite symlinked or masked unit at /etc/systemd/system/", unitName),
			}
		}
	}
	return nil
}

func serviceInstallLinux(env linuxInstallEnv) error {
	if env.requireRoot && os.Geteuid() != 0 {
		return &installExitError{
			code: InstallExitNotElevated,
			err:  E.New("installing the service requires root privileges"),
		}
	}

	unlock, err := acquireLinuxInstallLock(env)
	if err != nil {
		return err
	}
	defer unlock()

	// Release builds must always carry an embedded manifest SHA-256 (fail closed).
	if activeOptions.InstallManifestSHA256 == "" && !activeOptions.DevelopmentListen {
		return &installExitError{
			code: InstallExitManifestFailed,
			err:  E.New("install manifest SHA-256 is required for Linux service installation"),
		}
	}

	workLogical := env.workingDir
	if workLogical == "" {
		workLogical = activeNames.LinuxWorkingDir
	}
	workLogical = filepath.Clean(workLogical)
	if workLogical != filepath.Clean(activeNames.LinuxWorkingDir) {
		return &installExitError{
			code: InstallExitInvalidSource,
			err:  E.New("working directory must match default service state directory ", activeNames.LinuxWorkingDir),
		}
	}
	if err := validateSafeSystemdPath("working directory", workLogical); err != nil {
		return err
	}
	socketLogical := linuxDefaultSocketPath(activeNames)
	if err := validateSafeSystemdPath("socket", socketLogical); err != nil {
		return err
	}

	unitName := activeNames.serviceUnitName()
	etcUnitDir := env.hostPath("/etc/systemd/system")
	unitHostPath := filepath.Join(etcUnitDir, unitName)
	if err := checkNoConflictingLinuxUnit(env, unitName, unitHostPath); err != nil {
		return err
	}

	// Open the running daemon executable directly via /proc/self/exe (never argv[0]).
	selfFD, err := unix.Open(env.selfExePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return &installExitError{
			code: InstallExitInvalidLayout,
			err:  E.Cause(err, "open running daemon binary"),
		}
	}
	defer unix.Close(selfFD)

	var selfStat unix.Stat_t
	if err := unix.Fstat(selfFD, &selfStat); err != nil {
		return &installExitError{
			code: InstallExitInvalidLayout,
			err:  E.Cause(err, "stat running daemon binary"),
		}
	}
	if selfStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return &installExitError{
			code: InstallExitInvalidLayout,
			err:  E.New("running daemon executable is not a regular file"),
		}
	}

	resolvedSelf, err := os.Readlink(env.selfExePath)
	if err != nil {
		resolvedSelf = env.selfExePath
	}
	srcDir := filepath.Dir(resolvedSelf)
	srcDirFD, err := unix.Open(srcDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &installExitError{
			code: InstallExitInvalidSource,
			err:  E.Cause(err, "open daemon source directory"),
		}
	}
	defer unix.Close(srcDirFD)

	installParent, err := chooseLinuxInstallParent(env)
	if err != nil {
		return err
	}
	hostParent := env.hostPath(installParent)
	if err := ensureLinuxProtectedParent(installParent, env.rootPrefix, env.requireRoot); err != nil {
		return &installExitError{
			code: InstallExitInvalidSource,
			err:  E.Cause(err, "prepare install parent ", installParent),
		}
	}
	dirName := linuxInstallDirName(activeNames)
	cleanupStaleLinuxTempDirs(hostParent, dirName)

	targetLogical := filepath.Join(installParent, dirName)
	if err := validateSafeSystemdPath("install directory", targetLogical); err != nil {
		return err
	}
	targetHost := env.hostPath(targetLogical)
	targetExists, err := checkLinuxTargetDir(targetHost)
	if err != nil {
		return err
	}

	var nonce [8]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return E.Cause(err, "generate staging nonce")
	}
	suffix := hex.EncodeToString(nonce[:])
	stagingHost := filepath.Join(hostParent, fmt.Sprintf(".%s.staging-%s", dirName, suffix))
	if err := os.Mkdir(stagingHost, 0o700); err != nil {
		return E.Cause(err, "create protected staging directory")
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = os.RemoveAll(stagingHost)
		}
	}()

	daemonBin := linuxDaemonBinaryName(activeNames)
	var totalCopied int64

	if activeOptions.InstallManifestSHA256 != "" {
		expectedManifestSum, err := hex.DecodeString(activeOptions.InstallManifestSHA256)
		if err != nil || len(expectedManifestSum) != sha256.Size {
			return &installExitError{
				code: InstallExitManifestFailed,
				err:  E.New("invalid embedded install manifest SHA-256"),
			}
		}
		manifestFD, err := openRelativeLinuxNoFollow(srcDirFD, linuxDaemonManifestName, false)
		if err != nil {
			return &installExitError{
				code: InstallExitManifestFailed,
				err:  E.Cause(err, "open daemon manifest ", linuxDaemonManifestName),
			}
		}
		manifestData, readErr := readLinuxFDBounded(manifestFD, maxInstallManifestSize)
		_ = unix.Close(manifestFD)
		if readErr != nil {
			return &installExitError{
				code: InstallExitManifestFailed,
				err:  E.Cause(readErr, "read daemon manifest"),
			}
		}
		actualSum := sha256.Sum256(manifestData)
		if subtle.ConstantTimeCompare(actualSum[:], expectedManifestSum) != 1 {
			return &installExitError{
				code: InstallExitManifestFailed,
				err:  E.New("daemon manifest SHA-256 mismatch"),
			}
		}
		entries, err := parseLinuxDaemonManifest(manifestData, daemonBin)
		if err != nil {
			return &installExitError{
				code: InstallExitManifestFailed,
				err:  err,
			}
		}
		if err := writeLinuxFileSynced(filepath.Join(stagingHost, linuxDaemonManifestName), manifestData, 0o644); err != nil {
			return E.Cause(err, "stage daemon manifest")
		}
		totalCopied += int64(len(manifestData))

		for _, entry := range entries {
			// Manifest-verified files allow Nlink > 1 (ostree deduplication); content is read from fd and hashed.
			fd, openErr := openRelativeLinuxNoFollow(srcDirFD, entry.relSlash, false)
			if openErr != nil {
				code := InstallExitInvalidSource
				if errors.Is(openErr, unix.ENOENT) {
					code = InstallExitManifestFailed
				}
				return &installExitError{
					code: code,
					err:  E.Cause(openErr, "open sibling file ", entry.relSlash),
				}
			}
			dstPath := filepath.Join(stagingHost, filepath.FromSlash(entry.relSlash))
			fileMode := os.FileMode(0o644)
			if entry.relSlash == "slipstream-client" || strings.HasSuffix(entry.relSlash, "/slipstream-client") {
				fileMode = 0o755
			}
			copied, sum, copyErr := copyLinuxFDWithSHA256(fd, dstPath, fileMode, maxInstallTotalBytes-totalCopied)
			_ = unix.Close(fd)
			if copyErr != nil {
				return &installExitError{
					code: InstallExitInvalidSource,
					err:  E.Cause(copyErr, "stage sibling file ", entry.relSlash),
				}
			}
			totalCopied += copied
			if subtle.ConstantTimeCompare(sum[:], entry.sum) != 1 {
				return &installExitError{
					code: InstallExitManifestFailed,
					err:  E.New("SHA-256 mismatch for staged file: ", entry.relSlash),
				}
			}
		}
	} else {
		// Dev-only fallback: copy libcronet.so if present as a regular single-link file.
		if fd, openErr := openRelativeLinuxNoFollow(srcDirFD, "libcronet.so", true); openErr == nil {
			copied, _, copyErr := copyLinuxFDWithSHA256(fd, filepath.Join(stagingHost, "libcronet.so"), 0o644, maxInstallTotalBytes-totalCopied)
			_ = unix.Close(fd)
			if copyErr != nil {
				return E.Cause(copyErr, "stage libcronet.so")
			}
			totalCopied += copied
		}
	}

	// Copy the daemon executable directly from the already-opened selfFD.
	if _, err := unix.Seek(selfFD, 0, io.SeekStart); err != nil {
		return E.Cause(err, "seek running daemon executable")
	}
	if _, _, err := copyLinuxFDWithSHA256(selfFD, filepath.Join(stagingHost, daemonBin), 0o755, maxInstallTotalBytes-totalCopied); err != nil {
		return E.Cause(err, "stage daemon executable")
	}

	markerContent := fmt.Sprintf("product=%s\nservice=%s\n", activeNames.Product, activeNames.Service)
	if err := writeLinuxFileSynced(filepath.Join(stagingHost, linuxInstallMarkerName), []byte(markerContent), 0o644); err != nil {
		return E.Cause(err, "write install marker")
	}
	if err := os.Chmod(stagingHost, 0o755); err != nil {
		return E.Cause(err, "set staging directory permissions")
	}

	// Validate working directory parent chain before creating/securing workingDir and owner.json (I5).
	if err := ensureLinuxProtectedParent(filepath.Dir(workLogical), env.rootPrefix, env.requireRoot); err != nil {
		return &installExitError{
			code: InstallExitInvalidSource,
			err:  E.Cause(err, "validate working directory parent"),
		}
	}
	workHost := env.hostPath(workLogical)
	if info, statErr := os.Lstat(workHost); statErr == nil {
		if err := checkProtectedDirInfo(workLogical, info, env.requireRoot); err != nil {
			return &installExitError{
				code: InstallExitInvalidSource,
				err:  err,
			}
		}
	} else if os.IsNotExist(statErr) {
		if err := os.Mkdir(workHost, 0o700); err != nil {
			return E.Cause(err, "create daemon working directory")
		}
	} else {
		return E.Cause(statErr, "stat daemon working directory")
	}
	if err := os.Chmod(workHost, 0o700); err != nil {
		return E.Cause(err, "secure daemon working directory")
	}
	if env.pkexecUID == "" {
		if _, err := os.Lstat(filepath.Join(workHost, ownerFileName)); os.IsNotExist(err) {
			log.Warn("installing without PKEXEC_UID/SUDO_UID: first local user to connect will claim ownership (or run 'service take-over --uid <uid>')")
		}
	}
	if err := maybePreseedLinuxOwner(workHost, env.pkexecUID); err != nil {
		return E.Cause(err, "pre-seed service owner")
	}

	if err := os.MkdirAll(etcUnitDir, 0o755); err != nil {
		return E.Cause(err, "create systemd unit directory")
	}
	prevUnitData, prevUnitErr := os.ReadFile(unitHostPath)
	hadPrevUnit := prevUnitErr == nil

	wasRunning := false
	wasEnabled := false
	if env.queryUnitProp != nil {
		if activeState, err := env.queryUnitProp("ActiveState"); err == nil {
			wasRunning = activeState == "active" || activeState == "activating" || activeState == "reloading"
		}
		if unitFileState, err := env.queryUnitProp("UnitFileState"); err == nil {
			wasEnabled = unitFileState == "enabled" || unitFileState == "enabled-runtime"
		}
	}

	// Atomically promote stagingHost -> targetHost (B2: on RENAME_EXCHANGE, stagingHost IS the backup; no second rename!).
	var backupHost string
	if targetExists {
		if wasRunning && env.runSystemctl != nil {
			_ = env.runSystemctl("stop", unitName)
		}
		var swappedBackup string
		swappedBackup, err = promoteLinuxDirectory(stagingHost, targetHost, filepath.Join(hostParent, fmt.Sprintf(".%s.old-%s", dirName, suffix)))
		if err != nil {
			if wasRunning && env.runSystemctl != nil {
				_ = env.runSystemctl("start", unitName)
			}
			return E.Cause(err, "promote staged installation")
		}
		backupHost = swappedBackup
	} else {
		if err := os.Rename(stagingHost, targetHost); err != nil {
			return E.Cause(err, "promote staged installation")
		}
	}
	keepStaging = true

	// Apply SELinux labels on the final promoted path (I11).
	if env.runRestorecon != nil {
		_ = env.runRestorecon(targetHost)
	}

	rollback := func() {
		if env.runSystemctl != nil {
			if hadPrevUnit {
				_ = env.runSystemctl("stop", unitName)
			} else {
				_ = env.runSystemctl("disable", "--now", unitName)
			}
		}
		if hadPrevUnit {
			_ = atomicfile.WriteFile(unitHostPath, prevUnitData, 0o644)
		} else {
			_ = os.Remove(unitHostPath)
		}
		if backupHost != "" {
			failedFallback := filepath.Join(hostParent, fmt.Sprintf(".%s.failed-%s", dirName, suffix))
			if failedPath, swapErr := promoteLinuxDirectory(backupHost, targetHost, failedFallback); swapErr == nil {
				_ = os.RemoveAll(failedPath)
			}
		} else {
			_ = os.RemoveAll(targetHost)
		}
		if env.runRestorecon != nil {
			if hadPrevUnit {
				_ = env.runRestorecon(unitHostPath)
			}
			if backupHost != "" {
				_ = env.runRestorecon(targetHost)
			}
		}
		if env.runSystemctl != nil {
			_ = env.runSystemctl("daemon-reload")
			if wasEnabled {
				_ = env.runSystemctl("enable", unitName)
			}
			if wasRunning {
				_ = env.runSystemctl("start", unitName)
			}
		}
	}

	unitContent := renderLinuxSystemdUnit(activeNames, targetLogical, workLogical, socketLogical)
	if err := atomicfile.WriteFile(unitHostPath, []byte(unitContent), 0o644); err != nil {
		rollback()
		return E.Cause(err, "write systemd unit")
	}
	if env.runRestorecon != nil {
		_ = env.runRestorecon(unitHostPath)
	}

	if env.runSystemctl != nil {
		if err := env.runSystemctl("daemon-reload"); err != nil {
			rollback()
			return err
		}
		// Separate enable + restart so a daemon already running from another path is always restarted (I12).
		if err := env.runSystemctl("enable", unitName); err != nil {
			rollback()
			return err
		}
		if err := env.runSystemctl("restart", unitName); err != nil {
			rollback()
			return err
		}
	}

	if env.checkHealth != nil {
		if err := env.checkHealth(env.hostPath(socketLogical)); err != nil {
			rollback()
			return err
		}
	}

	if backupHost != "" {
		_ = os.RemoveAll(backupHost)
	}
	// Clean up any previous marked install in the alternate parent (e.g. /opt -> /usr/local/libexec migration) (I12).
	for _, altParent := range []string{env.primaryParent, env.fallbackParent} {
		if altParent == "" || altParent == installParent {
			continue
		}
		altHost := env.hostPath(filepath.Join(altParent, dirName))
		if info, err := os.Lstat(filepath.Join(altHost, linuxInstallMarkerName)); err == nil && info.Mode().IsRegular() {
			_ = os.RemoveAll(altHost)
		}
	}
	return nil
}

func serviceUninstallLinux(env linuxInstallEnv) error {
	if env.requireRoot && os.Geteuid() != 0 {
		return &installExitError{
			code: InstallExitNotElevated,
			err:  E.New("uninstalling the service requires root privileges"),
		}
	}
	unlock, err := acquireLinuxInstallLock(env)
	if err != nil {
		return err
	}
	defer unlock()

	unitName := activeNames.serviceUnitName()
	etcUnitPath := env.hostPath(filepath.Join("/etc/systemd/system", unitName))
	etcInfo, etcErr := os.Lstat(etcUnitPath)
	for _, pkgDir := range []string{"/usr/lib/systemd/system", "/lib/systemd/system", "/usr/local/lib/systemd/system"} {
		pkgUnit := env.hostPath(filepath.Join(pkgDir, unitName))
		if _, err := os.Lstat(pkgUnit); err == nil && os.IsNotExist(etcErr) {
			return &installExitError{
				code: InstallExitInvalidSource,
				err:  E.New("service is managed by a system package (", filepath.Join(pkgDir, unitName), "); remove it with your package manager"),
			}
		}
	}

	if etcErr == nil {
		if etcInfo.Mode()&os.ModeSymlink != 0 {
			return &installExitError{
				code: InstallExitInvalidSource,
				err:  E.New("refusing to remove symlinked or masked systemd unit at /etc/systemd/system/", unitName),
			}
		}
		unitBytes, readErr := os.ReadFile(etcUnitPath)
		if readErr != nil {
			return E.Cause(readErr, "read systemd unit")
		}
		if !strings.HasPrefix(string(unitBytes), linuxUnitManagedHeader) {
			return &installExitError{
				code: InstallExitInvalidSource,
				err:  E.New("systemd unit /etc/systemd/system/", unitName, " is not managed by ", activeNames.Product),
			}
		}
	}

	if env.runSystemctl != nil {
		_ = env.runSystemctl("disable", "--now", unitName)
	}
	if err := os.Remove(etcUnitPath); err != nil && !os.IsNotExist(err) {
		return E.Cause(err, "remove systemd unit")
	}
	if env.runSystemctl != nil {
		if err := env.runSystemctl("daemon-reload"); err != nil {
			return err
		}
	}

	dirName := linuxInstallDirName(activeNames)
	for _, parent := range []string{env.primaryParent, env.fallbackParent} {
		if parent == "" {
			continue
		}
		parentHost := env.hostPath(parent)
		cleanupStaleLinuxTempDirs(parentHost, dirName)
		dirHost := filepath.Join(parentHost, dirName)
		markerHost := filepath.Join(dirHost, linuxInstallMarkerName)
		if info, err := os.Lstat(markerHost); err == nil && info.Mode().IsRegular() {
			if err := os.RemoveAll(dirHost); err != nil {
				return E.Cause(err, "remove installation directory ", dirHost)
			}
		}
	}
	return nil
}

func serviceTakeOverLinux(env linuxInstallEnv, targetUID string) error {
	if env.requireRoot && os.Geteuid() != 0 {
		return &installExitError{
			code: InstallExitNotElevated,
			err:  E.New("taking over the service requires root privileges"),
		}
	}
	uidStr := strings.TrimSpace(targetUID)
	if uidStr == "" {
		uidStr = env.pkexecUID
	}
	if uidStr == "" {
		return E.New("target user ID is required (--uid or PKEXEC_UID/SUDO_UID)")
	}
	uidNum, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil || uidNum == 0 {
		return E.New("target user ID must be a non-root numeric UID: ", uidStr)
	}
	if env.requireRoot {
		if _, err := user.LookupId(uidStr); err != nil {
			return E.Cause(err, "lookup target user ", uidStr)
		}
	}

	workLogical := env.workingDir
	if workLogical == "" {
		workLogical = activeNames.LinuxWorkingDir
	}
	workHost := env.hostPath(workLogical)
	if err := validateProtectedLinuxDirectoryAt(workLogical, env.rootPrefix, env.requireRoot); err != nil {
		return E.Cause(err, "validate working directory")
	}
	content, err := json.Marshal(ownerState{UserID: uidStr})
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(filepath.Join(workHost, ownerFileName), content, 0o600); err != nil {
		return E.Cause(err, "write service owner")
	}
	if env.runSystemctl != nil && env.queryUnitProp != nil {
		if activeState, err := env.queryUnitProp("ActiveState"); err == nil && (activeState == "active" || activeState == "activating" || activeState == "reloading") {
			return env.runSystemctl("restart", activeNames.serviceUnitName())
		}
	}
	return nil
}

func chooseLinuxInstallParent(env linuxInstallEnv) (string, error) {
	candidates := []string{env.primaryParent, env.fallbackParent}
	var lastErr error
	for _, parent := range candidates {
		if parent == "" {
			continue
		}
		ro, err := env.isReadOnlyFS(env.hostPath(parent))
		if err != nil {
			lastErr = err
			continue
		}
		if ro {
			lastErr = E.New(parent, " is on a read-only filesystem")
			continue
		}
		return parent, nil
	}
	return "", &installExitError{
		code: InstallExitInvalidSource,
		err:  E.Cause(lastErr, "no writable Linux installation parent available"),
	}
}

func ensureLinuxProtectedParent(logicalParent string, rootPrefix string, requireRoot bool) error {
	hostParent := logicalParent
	if rootPrefix != "" {
		hostParent = filepath.Join(rootPrefix, strings.TrimPrefix(filepath.Clean(logicalParent), "/"))
	}
	probeLogical := filepath.Clean(logicalParent)
	for {
		probeHost := probeLogical
		if rootPrefix != "" {
			probeHost = filepath.Join(rootPrefix, strings.TrimPrefix(probeLogical, "/"))
		}
		if _, err := os.Lstat(probeHost); err == nil {
			if err := validateProtectedLinuxDirectoryAt(probeLogical, rootPrefix, requireRoot); err != nil {
				return err
			}
			break
		}
		parent := filepath.Dir(probeLogical)
		if parent == probeLogical {
			return E.New("cannot find existing ancestor for ", logicalParent)
		}
		probeLogical = parent
	}
	if err := os.MkdirAll(hostParent, 0o755); err != nil {
		return err
	}
	return validateProtectedLinuxDirectoryAt(logicalParent, rootPrefix, requireRoot)
}

func checkLinuxTargetDir(targetHost string) (bool, error) {
	info, err := os.Lstat(targetHost)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, &installExitError{
			code: InstallExitInvalidSource,
			err:  E.Cause(err, "stat target directory ", targetHost),
		}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, &installExitError{
			code: InstallExitInvalidSource,
			err:  E.New("target installation path is not a regular directory: ", targetHost),
		}
	}
	entries, err := os.ReadDir(targetHost)
	if err != nil {
		return false, E.Cause(err, "read target directory ", targetHost)
	}
	if len(entries) == 0 {
		return true, nil
	}
	markerInfo, markerErr := os.Lstat(filepath.Join(targetHost, linuxInstallMarkerName))
	if markerErr != nil || !markerInfo.Mode().IsRegular() {
		return false, &installExitError{
			code: InstallExitInvalidSource,
			err:  E.New("target directory already exists and is not managed by ", activeNames.Product, ": ", targetHost),
		}
	}
	return true, nil
}

// openRelativeLinuxNoFollow opens relSlash beneath dirFD without following symlinks and using
// O_NONBLOCK so a FIFO planted in the source directory cannot hang the root installer (I3).
// Falls back to step-by-step openat(O_NOFOLLOW) when openat2 returns ENOSYS or EPERM (seccomp, I4).
func openRelativeLinuxNoFollow(dirFD int, relSlash string, rejectHardLinks bool) (int, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	}
	fd, err := unix.Openat2(dirFD, relSlash, how)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		fd, err = openRelativeLinuxFallback(dirFD, relSlash)
	}
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return -1, E.New("source path is not a regular file: ", relSlash)
	}
	if rejectHardLinks && st.Nlink > 1 {
		_ = unix.Close(fd)
		return -1, E.New("source file has multiple hard links: ", relSlash)
	}
	// Clear O_NONBLOCK now that we proved it is a regular file.
	_ = unix.SetNonblock(fd, false)
	return fd, nil
}

func openRelativeLinuxFallback(dirFD int, relSlash string) (int, error) {
	parts := strings.Split(relSlash, "/")
	curFD := dirFD
	var opened []int
	defer func() {
		for i := len(opened) - 1; i >= 0; i-- {
			_ = unix.Close(opened[i])
		}
	}()
	for i := 0; i < len(parts)-1; i++ {
		nextFD, err := unix.Openat(curFD, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return -1, err
		}
		opened = append(opened, nextFD)
		curFD = nextFD
	}
	return unix.Openat(curFD, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}

func readLinuxFDBounded(fd int, limit int64) ([]byte, error) {
	dupFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dupFD), "manifest")
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, E.New("file exceeds maximum allowed size")
	}
	return data, nil
}

func copyLinuxFDWithSHA256(srcFD int, dstPath string, mode os.FileMode, maxBytes int64) (int64, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if maxBytes <= 0 {
		return 0, zero, E.New("installation exceeds total size limit")
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return 0, zero, err
	}
	dupFD, err := unix.FcntlInt(uintptr(srcFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return 0, zero, err
	}
	src := os.NewFile(uintptr(dupFD), "src")
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return 0, zero, err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(dst, hasher), io.LimitReader(src, maxBytes+1))
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(dstPath)
		return 0, zero, copyErr
	}
	if written > maxBytes {
		_ = os.Remove(dstPath)
		return 0, zero, E.New("installation exceeds total size limit")
	}
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(dstPath)
		return 0, zero, E.Errors(syncErr, closeErr)
	}
	if err := os.Chmod(dstPath, mode); err != nil {
		_ = os.Remove(dstPath)
		return 0, zero, err
	}
	var sum [sha256.Size]byte
	hasher.Sum(sum[:0])
	return written, sum, nil
}

func writeLinuxFileSynced(dstPath string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, wErr := f.Write(data)
	sErr := f.Sync()
	cErr := f.Close()
	if wErr != nil || sErr != nil || cErr != nil {
		_ = os.Remove(dstPath)
		return E.Errors(wErr, sErr, cErr)
	}
	return os.Chmod(dstPath, mode)
}

// promoteLinuxDirectory atomically swaps stagingHost into targetHost and returns the backup path
// holding the previous targetHost contents. When RENAME_EXCHANGE succeeds, stagingHost itself holds
// the old contents with zero follow-up rename failure window (B2).
func promoteLinuxDirectory(stagingHost, targetHost, fallbackBackupHost string) (string, error) {
	err := unix.Renameat2(unix.AT_FDCWD, stagingHost, unix.AT_FDCWD, targetHost, unix.RENAME_EXCHANGE)
	if err == nil {
		return stagingHost, nil
	}
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) {
		return "", err
	}
	if err := os.Rename(targetHost, fallbackBackupHost); err != nil {
		return "", err
	}
	if err := os.Rename(stagingHost, targetHost); err != nil {
		_ = os.Rename(fallbackBackupHost, targetHost)
		return "", err
	}
	return fallbackBackupHost, nil
}

func maybePreseedLinuxOwner(workHost string, pkexecUID string) error {
	if pkexecUID == "" {
		return nil
	}
	ownerPath := filepath.Join(workHost, ownerFileName)
	if _, err := os.Lstat(ownerPath); err == nil {
		return nil
	}
	uidNum, err := strconv.ParseUint(pkexecUID, 10, 32)
	if err != nil || uidNum == 0 {
		return nil
	}
	content, err := json.Marshal(ownerState{UserID: pkexecUID})
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(ownerPath, content, 0o600)
}
