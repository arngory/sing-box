package boxdd

// niko: parameterized daemon naming and build/runtime options (docs/design/desktop-stage3.md, slice 14).

import (
	"encoding/hex"
	"regexp"
	"runtime"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Names configures the platform-visible identifiers of a daemon built from boxdd.
// The zero value selects DefaultNames() (upstream sing-box identifiers).
type Names struct {
	Service            string
	DisplayName        string
	Description        string
	Product            string
	UpdateProductName  string
	PipePath           string
	WorkerPipePrefix   string
	WindowsWorkingDir  string
	LinuxWorkingDir    string
	ApplicationExe     string
	DaemonExe          string
	PolkitActionPrefix string
}

// WorkerTransport selects the local IPC between the desktop window and its worker on Windows.
type WorkerTransport int

const (
	// WorkerTransportPipe uses Windows named pipes (upstream default).
	WorkerTransportPipe WorkerTransport = iota
	// WorkerTransportUnix uses an AF_UNIX socket in the user's private directory with peer PID
	// verification and a mutual HMAC-SHA256 handshake (Niko release transport).
	WorkerTransportUnix
)

// InstallRoot selects where "service install" installs the daemon on Windows.
type InstallRoot int

const (
	// InstallInPlace secures and registers the currently running installation directory (upstream default).
	InstallInPlace InstallRoot = iota
	// InstallProgramFiles copies and verifies a portable layout into <ProgramFiles>\<Product> before
	// registering the service there, preventing EoP from user-writable directories.
	InstallProgramFiles
)

const (
	protectedPipePrefix = `\\.\pipe\ProtectedPrefix\Administrators\`
	namedPipePrefix     = `\\.\pipe\`
)

var (
	serviceNameRegexp  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	polkitPrefixRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`)

	activeNames   = DefaultNames()
	activeOptions = Options{}
)

// ProgramDataDir returns <ProgramData>\<name> on Windows (resolved via FOLDERID_ProgramData,
// falling back to C:\ProgramData) and C:\ProgramData\<name> on other platforms.
func ProgramDataDir(name string) string {
	return knownProgramDataDir(name)
}

// DefaultNames returns upstream sing-box's daemon identifiers.
func DefaultNames() Names {
	return Names{
		Service:            "sing-box-daemon",
		DisplayName:        "sing-box Service",
		Description:        "Privileged service for sing-box",
		Product:            "sing-box",
		UpdateProductName:  "sing-box",
		PipePath:           `\\.\pipe\ProtectedPrefix\Administrators\sing-box`,
		WorkerPipePrefix:   `\\.\pipe\sing-box-worker.`,
		WindowsWorkingDir:  ProgramDataDir("sing-box-daemon"),
		LinuxWorkingDir:    "/var/lib/sing-box-daemon",
		ApplicationExe:     "sing-box.exe",
		DaemonExe:          "sing-box-daemon.exe",
		PolkitActionPrefix: "io.nekohasekai.sfl",
	}
}

// Validate checks that every identifier in Names is well-formed and safe for OS APIs.
func (n Names) Validate() error {
	if !serviceNameRegexp.MatchString(n.Service) {
		return E.New("invalid service name: ", n.Service)
	}
	if strings.TrimSpace(n.DisplayName) == "" || hasControlChar(n.DisplayName) {
		return E.New("invalid service display name")
	}
	if strings.TrimSpace(n.Description) == "" || hasControlChar(n.Description) {
		return E.New("invalid service description")
	}
	if err := validateProductName(n.Product); err != nil {
		return E.Cause(err, "invalid product name")
	}
	if strings.TrimSpace(n.UpdateProductName) == "" || hasControlChar(n.UpdateProductName) {
		return E.New("invalid update product name")
	}
	if !strings.HasPrefix(n.PipePath, protectedPipePrefix) {
		return E.New("pipe path must be under ", protectedPipePrefix)
	}
	pipeSuffix := n.PipePath[len(protectedPipePrefix):]
	if pipeSuffix == "" || strings.ContainsAny(pipeSuffix, `\/`) || hasControlChar(pipeSuffix) {
		return E.New("invalid pipe path suffix: ", n.PipePath)
	}
	if !strings.HasPrefix(n.WorkerPipePrefix, namedPipePrefix) {
		return E.New("worker pipe prefix must be under ", namedPipePrefix)
	}
	workerSuffix := n.WorkerPipePrefix[len(namedPipePrefix):]
	if workerSuffix == "" || strings.ContainsAny(workerSuffix, `\/`) || hasControlChar(workerSuffix) {
		return E.New("invalid worker pipe prefix: ", n.WorkerPipePrefix)
	}
	if err := validateWindowsAbsoluteDir(n.WindowsWorkingDir); err != nil {
		return E.Cause(err, "invalid Windows working directory")
	}
	if err := validateLinuxAbsoluteDir(n.LinuxWorkingDir); err != nil {
		return E.Cause(err, "invalid Linux working directory")
	}
	if err := validateExeName(n.ApplicationExe); err != nil {
		return E.Cause(err, "invalid application executable name")
	}
	if err := validateExeName(n.DaemonExe); err != nil {
		return E.Cause(err, "invalid daemon executable name")
	}
	if strings.EqualFold(n.ApplicationExe, n.DaemonExe) {
		return E.New("application and daemon executable names must differ")
	}
	if !polkitPrefixRegexp.MatchString(n.PolkitActionPrefix) {
		return E.New("invalid PolicyKit action prefix: ", n.PolkitActionPrefix)
	}
	return nil
}

func (n Names) defaultWorkingDirectory() string {
	switch runtime.GOOS {
	case "windows":
		return n.WindowsWorkingDir
	case "linux":
		return n.LinuxWorkingDir
	default:
		return ""
	}
}

func (n Names) serviceUnitName() string {
	return n.Service + ".service"
}

func (n Names) polkitTakeOverAction() string {
	return n.PolkitActionPrefix + ".take-over-service"
}

func (n Names) polkitSetInsecureModeAction() string {
	return n.PolkitActionPrefix + ".set-insecure-mode"
}

func applyOptions(options Options) error {
	names := options.Names
	if names == (Names{}) {
		names = DefaultNames()
	}
	if err := names.Validate(); err != nil {
		return err
	}
	if options.WorkerTransport != WorkerTransportPipe && options.WorkerTransport != WorkerTransportUnix {
		return E.New("invalid worker transport: ", int(options.WorkerTransport))
	}
	if options.InstallRoot != InstallInPlace && options.InstallRoot != InstallProgramFiles {
		return E.New("invalid install root: ", int(options.InstallRoot))
	}
	if options.InstallManifestSHA256 != "" {
		raw, err := hex.DecodeString(options.InstallManifestSHA256)
		if err != nil || len(raw) != 32 {
			return E.New("invalid install manifest SHA-256")
		}
		options.InstallManifestSHA256 = strings.ToLower(options.InstallManifestSHA256)
	}
	options.Names = names
	activeNames = names
	activeOptions = options
	addedServices = options.Services
	applyNamesToCommands(names)
	if flag := commandRun.Flags().Lookup("listen"); flag != nil {
		flag.Hidden = !options.DevelopmentListen
	}
	return nil
}

func applyNamesToCommands(n Names) {
	mainCommand.Use = n.Service
	if flag := commandService.PersistentFlags().Lookup("working-directory"); flag != nil {
		defaultDir := n.defaultWorkingDirectory()
		flag.DefValue = defaultDir
		if !flag.Changed {
			_ = flag.Value.Set(defaultDir)
		}
	}
}

func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

const windowsIllegalNameChars = `\/:*?"<>|`

var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func isWindowsReservedName(name string) bool {
	stem := name
	if dot := strings.IndexByte(stem, '.'); dot >= 0 {
		stem = stem[:dot]
	}
	return windowsReservedNames[strings.ToUpper(stem)]
}

func validateProductName(name string) error {
	if name == "" || strings.TrimSpace(name) != name || hasControlChar(name) {
		return E.New("empty or malformed: ", name)
	}
	if name == "." || name == ".." || strings.HasSuffix(name, ".") || strings.ContainsAny(name, windowsIllegalNameChars) {
		return E.New("illegal Windows directory name: ", name)
	}
	if isWindowsReservedName(name) {
		return E.New("reserved Windows device name: ", name)
	}
	return nil
}

func validateExeName(name string) error {
	if name == "" || hasControlChar(name) || strings.ContainsAny(name, windowsIllegalNameChars) {
		return E.New("must be a base filename: ", name)
	}
	if strings.HasSuffix(name, " ") || isWindowsReservedName(name) {
		return E.New("invalid Windows filename: ", name)
	}
	if len(name) <= 4 || !strings.EqualFold(name[len(name)-4:], ".exe") {
		return E.New("must end with .exe: ", name)
	}
	return nil
}

func validateWindowsAbsoluteDir(path string) error {
	if len(path) < 4 || hasControlChar(path) || strings.Contains(path, "/") {
		return E.New("must be an absolute Windows directory path: ", path)
	}
	drive := path[0]
	if !((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) || path[1] != ':' || path[2] != '\\' {
		return E.New("must start with a Windows drive root: ", path)
	}
	rest := path[3:]
	if strings.ContainsAny(rest, `:*?"<>|`) {
		return E.New("must not contain illegal Windows path characters: ", path)
	}
	for _, part := range strings.Split(rest, `\`) {
		if part == "" || part == "." || part == ".." {
			return E.New("must not contain empty or relative components: ", path)
		}
	}
	return nil
}

func validateLinuxAbsoluteDir(path string) error {
	if len(path) < 2 || path[0] != '/' || hasControlChar(path) {
		return E.New("must be an absolute Linux directory path: ", path)
	}
	for _, part := range strings.Split(path[1:], "/") {
		if part == ".." {
			return E.New("must not contain parent traversal: ", path)
		}
	}
	return nil
}
