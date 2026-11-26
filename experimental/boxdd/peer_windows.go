//go:build windows

package boxdd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	winioProcess "github.com/tailscale/go-winio/pkg/process"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type windowsTransportCredentials struct {
	daemon                  *Daemon
	daemonSigner            []byte
	daemonExecutable        windows.Handle
	expectedWorkerPath      string
	expectedApplicationPath string
}

type windowsAuthenticatedConnection struct {
	net.Conn
	daemon             *Daemon
	identity           peerIdentity
	process            windows.Handle
	processImage       windows.Handle
	parentProcess      windows.Handle
	parentProcessImage windows.Handle
	close              sync.Once
	closeError         error
}

type fileDescriptorConnection interface {
	Fd() uintptr
}

func platformServerOptions(daemon *Daemon) ([]grpc.ServerOption, error) {
	if listenAddress != "" || userMode {
		return nil, nil
	}
	transportCredentials := &windowsTransportCredentials{daemon: daemon}
	err := transportCredentials.initializeServerIdentity()
	if err != nil {
		return nil, err
	}
	daemon.platform.(*windowsPlatformInterface).daemonSigner = transportCredentials.daemonSigner
	return []grpc.ServerOption{grpc.Creds(transportCredentials)}, nil
}

func platformFallbackPeerIdentity(ctx context.Context) (peerIdentity, error) {
	if userMode {
		return currentWindowsUserIdentity()
	}
	// niko: --listen (development only, TCP without credentials) has no peer to authenticate, as on Linux
	// (peer_linux.go). Without this DesktopService refuses every call there and the mode cannot start a service
	if listenAddress != "" {
		return peerIdentity{UserID: "local"}, nil
	}
	return peerIdentity{}, E.New("missing Windows peer authentication")
}

func (c *windowsTransportCredentials) ClientHandshake(ctx context.Context, authority string, rawConnection net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, E.New("Windows local process credentials do not support client handshakes")
}

// niko: rate-limit event log writes for rejected pipe handshakes so an unprivileged local user
// cannot flood the Windows Event Log by repeatedly connecting to the daemon pipe.
var lastHandshakeRejectLogUnixNano atomic.Int64

func (c *windowsTransportCredentials) ServerHandshake(rawConnection net.Conn) (net.Conn, credentials.AuthInfo, error) {
	connection, authenticationInformation, err := c.serverHandshake(rawConnection)
	if err != nil {
		now := time.Now().UnixNano()
		prev := lastHandshakeRejectLogUnixNano.Load()
		if now-prev >= int64(time.Second) && lastHandshakeRejectLogUnixNano.CompareAndSwap(prev, now) {
			serviceLogError(E.Cause(err, "reject Windows daemon connection"))
		}
	}
	return connection, authenticationInformation, err
}

func (c *windowsTransportCredentials) serverHandshake(rawConnection net.Conn) (net.Conn, credentials.AuthInfo, error) {
	descriptorConnection, loaded := rawConnection.(fileDescriptorConnection)
	if !loaded {
		return nil, nil, E.New("daemon endpoint is not a Windows named pipe")
	}
	var processID uint32
	err := windows.GetNamedPipeClientProcessId(windows.Handle(descriptorConnection.Fd()), &processID)
	if err != nil {
		return nil, nil, E.Cause(err, "identify named pipe client")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, processID)
	if err != nil {
		return nil, nil, E.Cause(err, "open named pipe client process")
	}
	keepProcess := false
	defer func() {
		if !keepProcess {
			windows.CloseHandle(process)
		}
	}()
	identity, err := processIdentity(process, processID)
	if err != nil {
		return nil, nil, err
	}
	workerImagePath, err := winioProcess.QueryFullProcessImageName(process, winioProcess.ImageNameFormatWin32Path)
	if err != nil {
		return nil, nil, E.Cause(err, "query named pipe client executable")
	}
	processImage, err := openLockedExecutable(workerImagePath)
	if err != nil {
		return nil, nil, E.Cause(err, "open named pipe client executable")
	}
	keepProcessImage := false
	defer func() {
		if !keepProcessImage {
			windows.CloseHandle(processImage)
		}
	}()
	processImageFinalPath, err := finalWindowsPath(processImage)
	if err != nil {
		return nil, nil, E.Cause(err, "resolve named pipe client executable")
	}
	if !strings.EqualFold(processImageFinalPath, c.expectedWorkerPath) {
		return nil, nil, E.New("named pipe client is not the installed ", activeNames.Product, " worker")
	}
	sameExecutable, err := sameWindowsFile(processImage, c.daemonExecutable)
	if err != nil {
		return nil, nil, err
	}
	if !sameExecutable {
		return nil, nil, E.New("named pipe client worker executable was replaced")
	}
	// niko: processImage is the exact same NTFS file as c.daemonExecutable (held open by the daemon
	// with FILE_SHARE_READ and already Authenticode-verified in initializeServerIdentity), so its
	// signer is identical to c.daemonSigner; skipping a redundant WinVerifyTrust saves one check per reconnect.
	parentProcessID, err := processParentID(process)
	if err != nil {
		return nil, nil, err
	}
	err = validateWorkerProcessRole(process, parentProcessID)
	if err != nil {
		return nil, nil, err
	}
	parentProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, parentProcessID)
	if err != nil {
		return nil, nil, E.Cause(err, "open ", activeNames.Product, " worker parent process")
	}
	keepParentProcess := false
	defer func() {
		if !keepParentProcess {
			windows.CloseHandle(parentProcess)
		}
	}()
	parentIdentity, err := processIdentity(parentProcess, parentProcessID)
	if err != nil {
		return nil, nil, err
	}
	if parentIdentity.UserID != identity.UserID || parentIdentity.SessionID != identity.SessionID {
		return nil, nil, E.New(activeNames.Product, " worker and application have different process identities")
	}
	parentCreationTime, err := processCreationTime(parentProcess)
	if err != nil {
		return nil, nil, err
	}
	workerCreationTime, err := processCreationTime(process)
	if err != nil {
		return nil, nil, err
	}
	if parentCreationTime >= workerCreationTime {
		return nil, nil, E.New(activeNames.Product, " worker parent was created after the worker")
	}
	parentImagePath, err := winioProcess.QueryFullProcessImageName(parentProcess, winioProcess.ImageNameFormatWin32Path)
	if err != nil {
		return nil, nil, E.Cause(err, "query ", activeNames.Product, " worker parent executable")
	}
	parentProcessImage, err := openLockedExecutable(parentImagePath)
	if err != nil {
		return nil, nil, E.Cause(err, "open ", activeNames.Product, " worker parent executable")
	}
	keepParentProcessImage := false
	defer func() {
		if !keepParentProcessImage {
			windows.CloseHandle(parentProcessImage)
		}
	}()
	expectedApplication, err := openLockedExecutable(c.expectedApplicationPath)
	if err != nil {
		return nil, nil, E.Cause(err, "open installed application executable")
	}
	defer windows.CloseHandle(expectedApplication)
	parentImageFinalPath, err := finalWindowsPath(parentProcessImage)
	if err != nil {
		return nil, nil, E.Cause(err, "resolve ", activeNames.Product, " worker parent executable")
	}
	expectedApplicationFinalPath, err := finalWindowsPath(expectedApplication)
	if err != nil {
		return nil, nil, E.Cause(err, "resolve installed application executable")
	}
	if !strings.EqualFold(parentImageFinalPath, expectedApplicationFinalPath) {
		return nil, nil, E.New(activeNames.Product, " worker parent is not the installed application")
	}
	sameApplication, err := sameWindowsFile(parentProcessImage, expectedApplication)
	if err != nil {
		return nil, nil, err
	}
	if !sameApplication {
		return nil, nil, E.New(activeNames.Product, " worker parent executable was replaced")
	}
	err = validateApplicationProcessRole(parentProcess, expectedApplication)
	if err != nil {
		return nil, nil, err
	}
	applicationSigner, err := authenticodeSigner(parentImageFinalPath, parentProcessImage)
	if err != nil {
		return nil, nil, E.Cause(err, "authenticate ", activeNames.Product, " application")
	}
	if !bytes.Equal(applicationSigner, c.daemonSigner) {
		return nil, nil, E.New(activeNames.Product, " application and daemon have different signing certificates")
	}
	workerWaitResult, err := windows.WaitForSingleObject(process, 0)
	if err != nil {
		return nil, nil, err
	}
	parentWaitResult, err := windows.WaitForSingleObject(parentProcess, 0)
	if err != nil {
		return nil, nil, err
	}
	if workerWaitResult != uint32(windows.WAIT_TIMEOUT) || parentWaitResult != uint32(windows.WAIT_TIMEOUT) {
		return nil, nil, E.New(activeNames.Product, " worker or application exited during authentication")
	}
	parentIdentity.ProcessID = parentProcessID
	connection := &windowsAuthenticatedConnection{
		Conn:               rawConnection,
		daemon:             c.daemon,
		identity:           parentIdentity,
		process:            process,
		processImage:       processImage,
		parentProcess:      parentProcess,
		parentProcessImage: parentProcessImage,
	}
	keepProcess = true
	keepProcessImage = true
	keepParentProcess = true
	keepParentProcessImage = true
	c.daemon.registerPeerConnection(connection)
	authenticationInformation := &peerAuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		identity:       parentIdentity,
	}
	return connection, authenticationInformation, nil
}

func (c *windowsTransportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "windows-local-process",
	}
}

func (c *windowsTransportCredentials) Clone() credentials.TransportCredentials {
	return &windowsTransportCredentials{
		daemon:                  c.daemon,
		daemonSigner:            c.daemonSigner,
		daemonExecutable:        c.daemonExecutable,
		expectedWorkerPath:      c.expectedWorkerPath,
		expectedApplicationPath: c.expectedApplicationPath,
	}
}

func (c *windowsTransportCredentials) OverrideServerName(serverNameOverride string) error {
	return nil
}

func (c *windowsTransportCredentials) initializeServerIdentity() error {
	executablePath, err := os.Executable()
	if err != nil {
		return E.Cause(err, "locate daemon executable")
	}
	executable, err := openLockedExecutable(executablePath)
	if err != nil {
		return E.Cause(err, "open daemon executable")
	}
	keepExecutable := false
	defer func() {
		if !keepExecutable {
			windows.CloseHandle(executable)
		}
	}()
	finalPath, err := finalWindowsPath(executable)
	if err != nil {
		return E.Cause(err, "resolve daemon executable")
	}
	_, applicationPath, err := installedApplicationPath(finalPath)
	if err != nil {
		return err
	}
	c.daemonExecutable = executable
	c.expectedWorkerPath = finalPath
	c.expectedApplicationPath = applicationPath
	c.daemonSigner, err = authenticodeSigner(finalPath, executable)
	if err != nil {
		return E.Cause(err, "authenticate daemon executable")
	}
	keepExecutable = true
	return nil
}

func processIdentity(process windows.Handle, processID uint32) (peerIdentity, error) {
	var token windows.Token
	err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token)
	if err != nil {
		return peerIdentity{}, E.Cause(err, "open named pipe client token")
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return peerIdentity{}, E.Cause(err, "query named pipe client user")
	}
	userID := user.User.Sid.String()
	if userID == "" {
		return peerIdentity{}, E.New("named pipe client has an invalid user SID")
	}
	var sessionID uint32
	err = windows.ProcessIdToSessionId(processID, &sessionID)
	if err != nil {
		return peerIdentity{}, E.Cause(err, "query named pipe client session")
	}
	if sessionID == 0 {
		return peerIdentity{}, E.New("named pipe client is not in an interactive session")
	}
	return peerIdentity{UserID: userID, ProcessID: processID, SessionID: sessionID}, nil
}

func validateApplicationProcessRole(process windows.Handle, expectedApplication windows.Handle) error {
	arguments, err := processCommandLine(process)
	if err != nil {
		return E.Cause(err, "query named pipe client command line")
	}
	for _, argument := range arguments[1:] {
		normalizedArgument := strings.ToLower(argument)
		if normalizedArgument == "--type" || strings.HasPrefix(normalizedArgument, "--type=") {
			return E.New("named pipe client is an Electron child process")
		}
	}
	applicationParent, err := processParentIsApplication(process, expectedApplication)
	if err != nil {
		return err
	}
	if applicationParent {
		return E.New("named pipe client is a child of the ", activeNames.Product, " application")
	}
	return nil
}

func validateWorkerProcessRole(process windows.Handle, parentProcessID uint32) error {
	arguments, err := processCommandLine(process)
	if err != nil {
		return E.Cause(err, "query ", activeNames.Product, " worker command line")
	}
	return validateWorkerCommandLine(arguments, parentProcessID, activeOptions.WorkerTransport, activeNames)
}

func validateWorkerCommandLine(arguments []string, parentProcessID uint32, transport WorkerTransport, names Names) error {
	switch transport {
	case WorkerTransportPipe:
		if len(arguments) != 8 ||
			arguments[1] != "worker" ||
			arguments[2] != "--socket" ||
			arguments[4] != "--parent-pid" ||
			arguments[6] != "--daemon-relay-socket" {
			return E.New("named pipe client is not a ", names.Product, " worker process")
		}
		if !strings.HasPrefix(strings.ToLower(arguments[3]), strings.ToLower(names.WorkerPipePrefix)) ||
			!strings.HasPrefix(strings.ToLower(arguments[7]), strings.ToLower(names.WorkerPipePrefix)) ||
			strings.EqualFold(arguments[3], arguments[7]) {
			return E.New(names.Product, " worker has invalid private pipe paths")
		}
		commandParentProcessID, err := strconv.ParseUint(arguments[5], 10, 32)
		if err != nil || uint32(commandParentProcessID) != parentProcessID {
			return E.New(names.Product, " worker has an invalid parent process ID")
		}
		return nil
	case WorkerTransportUnix:
		if len(arguments) != 6 ||
			arguments[1] != "worker" ||
			arguments[2] != "--parent-pid" ||
			arguments[4] != "--daemon-relay-unix" {
			return E.New("named pipe client is not a ", names.Product, " AF_UNIX worker process")
		}
		commandParentProcessID, err := strconv.ParseUint(arguments[3], 10, 32)
		if err != nil || uint32(commandParentProcessID) != parentProcessID {
			return E.New(names.Product, " worker has an invalid parent process ID")
		}
		if err := validateWorkerUnixSocketPath(arguments[5]); err != nil {
			return E.Cause(err, names.Product, " worker has an invalid AF_UNIX relay socket path")
		}
		return nil
	default:
		return E.New("unsupported worker transport")
	}
}

func processCommandLine(process windows.Handle) ([]string, error) {
	var bufferLength uint32
	queryError := windows.NtQueryInformationProcess(
		process,
		windows.ProcessCommandLineInformation,
		nil,
		0,
		&bufferLength,
	)
	if bufferLength == 0 {
		if queryError != nil {
			return nil, queryError
		}
		return nil, E.New("named pipe client has an empty command line buffer")
	}
	buffer := make([]byte, bufferLength)
	queryError = windows.NtQueryInformationProcess(
		process,
		windows.ProcessCommandLineInformation,
		unsafe.Pointer(&buffer[0]),
		uint32(len(buffer)),
		&bufferLength,
	)
	if queryError != nil {
		return nil, queryError
	}
	commandLine := (*windows.NTUnicodeString)(unsafe.Pointer(&buffer[0]))
	if commandLine.Buffer == nil || commandLine.Length == 0 || commandLine.Length%2 != 0 {
		return nil, E.New("named pipe client has an invalid command line")
	}
	commandLineString := windows.UTF16ToString(unsafe.Slice(commandLine.Buffer, int(commandLine.Length/2)))
	return windows.DecomposeCommandLine(commandLineString)
}

func processParentIsApplication(process windows.Handle, expectedApplication windows.Handle) (bool, error) {
	parentProcessID, err := processParentID(process)
	if err != nil {
		return false, err
	}
	if parentProcessID == 0 {
		return false, nil
	}
	parentProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, parentProcessID)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return false, nil
		}
		return false, E.Cause(err, "open named pipe client parent")
	}
	defer windows.CloseHandle(parentProcess)
	parentImagePath, err := winioProcess.QueryFullProcessImageName(parentProcess, winioProcess.ImageNameFormatWin32Path)
	if err != nil {
		return false, E.Cause(err, "query named pipe client parent executable")
	}
	parentImage, err := openLockedExecutable(parentImagePath)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(parentImage)
	return sameWindowsFile(parentImage, expectedApplication)
}

func processParentID(process windows.Handle) (uint32, error) {
	var processInformation windows.PROCESS_BASIC_INFORMATION
	processInformationLength := uint32(unsafe.Sizeof(processInformation))
	err := windows.NtQueryInformationProcess(
		process,
		windows.ProcessBasicInformation,
		unsafe.Pointer(&processInformation),
		processInformationLength,
		&processInformationLength,
	)
	if err != nil {
		return 0, E.Cause(err, "query named pipe client parent")
	}
	parentProcessID := uint32(processInformation.InheritedFromUniqueProcessId)
	if parentProcessID == 0 || uintptr(parentProcessID) != processInformation.InheritedFromUniqueProcessId {
		return 0, nil
	}
	return parentProcessID, nil
}

func openLockedExecutable(path string) (windows.Handle, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
}

func finalWindowsPath(file windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	for {
		length, err := windows.GetFinalPathNameByHandle(file, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if length < uint32(len(buffer)) {
			return normalizeWindowsPath(windows.UTF16ToString(buffer[:length])), nil
		}
		buffer = make([]uint16, length+1)
	}
}

func normalizeWindowsPath(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + path[len(`\\?\UNC\`):]
	}
	return strings.TrimPrefix(path, `\\?\`)
}

func sameWindowsFile(first windows.Handle, second windows.Handle) (bool, error) {
	var firstInformation windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(first, &firstInformation)
	if err != nil {
		return false, E.Cause(err, "query named pipe client executable identity")
	}
	var secondInformation windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(second, &secondInformation)
	if err != nil {
		return false, E.Cause(err, "query installed application executable identity")
	}
	return firstInformation.VolumeSerialNumber == secondInformation.VolumeSerialNumber &&
		firstInformation.FileIndexHigh == secondInformation.FileIndexHigh &&
		firstInformation.FileIndexLow == secondInformation.FileIndexLow, nil
}

func (c *windowsAuthenticatedConnection) peerConnectionIdentity() peerIdentity {
	return c.identity
}

func (c *windowsAuthenticatedConnection) duplicateImpersonationToken() (windows.Token, error) {
	var processToken windows.Token
	err := windows.OpenProcessToken(c.parentProcess, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if err != nil {
		return 0, E.Cause(err, "open application token")
	}
	defer processToken.Close()
	return duplicateImpersonationToken(processToken)
}

func (d *Daemon) duplicatePeerImpersonationToken(identity peerIdentity) (windows.Token, error) {
	d.peerAccess.Lock()
	defer d.peerAccess.Unlock()
	for connection, connectionIdentity := range d.peerConnections {
		if connectionIdentity != identity {
			continue
		}
		windowsConnection, loaded := connection.(*windowsAuthenticatedConnection)
		if !loaded {
			continue
		}
		return windowsConnection.duplicateImpersonationToken()
	}
	return 0, E.New("authenticated application connection is no longer available")
}

func (c *windowsAuthenticatedConnection) Close() error {
	c.close.Do(func() {
		c.daemon.unregisterPeerConnection(c)
		c.closeError = E.Errors(
			c.Conn.Close(),
			windows.CloseHandle(c.parentProcessImage),
			windows.CloseHandle(c.parentProcess),
			windows.CloseHandle(c.processImage),
			windows.CloseHandle(c.process),
		)
	})
	return c.closeError
}

var (
	_ credentials.TransportCredentials = (*windowsTransportCredentials)(nil)
	_ peerConnection                   = (*windowsAuthenticatedConnection)(nil)
)
