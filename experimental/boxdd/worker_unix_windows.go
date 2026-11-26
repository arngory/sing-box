//go:build windows

package boxdd

// niko: Windows AF_UNIX worker listener with user-only DACL, 8.3 short-path fallback,
// SIO_AF_UNIX_GETPEERPID verification, and stale socket hygiene (slice 14).

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const (
	// _WSAIOR(IOC_VENDOR, 256) from <afunix.h>
	sioAFUnixGetPeerPID = 0x58000100
	ioReparseTagAFUnix  = 0x80000023
)

type authenticatedUnixWorkerListener struct {
	net.Listener
	parent   *windowsWorkerParent
	bindPath string
	close    sync.Once
	closeErr error
}

func listenWorkerUnixEndpoint(socketPath string, parent *windowsWorkerParent) (net.Listener, string, error) {
	bindPath, err := prepareWorkerSocketPath(socketPath)
	if err != nil {
		return nil, "", err
	}
	listener, err := net.Listen("unix", bindPath)
	if err != nil {
		return nil, "", E.Cause(err, "listen worker AF_UNIX socket")
	}
	if err = verifyUnixSocketOwner(bindPath); err != nil {
		_ = listener.Close()
		_ = os.Remove(bindPath)
		return nil, "", E.Cause(err, "verify worker AF_UNIX socket owner")
	}
	authenticated := &authenticatedUnixWorkerListener{
		Listener: listener,
		parent:   parent,
		bindPath: bindPath,
	}
	go func() {
		<-parent.exited
		_ = authenticated.Close()
	}()
	return authenticated, bindPath, nil
}

var errWorkerParentExited = errors.New("worker application parent exited")

func (l *authenticatedUnixWorkerListener) Accept() (net.Conn, error) {
	for {
		waitResult, err := windows.WaitForSingleObject(l.parent.process, 0)
		if err != nil {
			return nil, err
		}
		if waitResult != uint32(windows.WAIT_TIMEOUT) {
			return nil, errWorkerParentExited
		}
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		unixConnection, loaded := connection.(*net.UnixConn)
		if !loaded {
			_ = connection.Close()
			continue
		}
		peerPID, err := unixPeerProcessID(unixConnection)
		if err != nil || peerPID != l.parent.pid {
			_ = connection.Close()
			continue
		}
		waitResult, err = windows.WaitForSingleObject(l.parent.process, 0)
		if err != nil || waitResult != uint32(windows.WAIT_TIMEOUT) {
			_ = connection.Close()
			return nil, errWorkerParentExited
		}
		return connection, nil
	}
}

func (l *authenticatedUnixWorkerListener) Close() error {
	l.close.Do(func() {
		l.closeErr = l.Listener.Close()
		_ = os.Remove(l.bindPath)
	})
	return l.closeErr
}

func unixPeerProcessID(connection *net.UnixConn) (uint32, error) {
	rawConn, err := connection.SyscallConn()
	if err != nil {
		return 0, E.Cause(err, "open AF_UNIX raw socket")
	}
	var (
		pid           uint32
		bytesReturned uint32
		ioctlErr      error
	)
	ctrlErr := rawConn.Control(func(fd uintptr) {
		// Known Windows AF_UNIX quirk (microsoft/WSL issue 4676):
		// SIO_AF_UNIX_GETPEERPID writes the ULONG PID into the output buffer
		// while setting bytesReturned = 0. Trust pid when WSAIoctl succeeds
		// and pid != 0, regardless of bytesReturned.
		ioctlErr = windows.WSAIoctl(
			windows.Handle(fd),
			sioAFUnixGetPeerPID,
			nil,
			0,
			(*byte)(unsafe.Pointer(&pid)),
			uint32(unsafe.Sizeof(pid)),
			&bytesReturned,
			nil,
			0,
		)
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	if ioctlErr != nil {
		return 0, ioctlErr
	}
	if pid == 0 {
		return 0, E.New("SIO_AF_UNIX_GETPEERPID returned pid 0")
	}
	return pid, nil
}

func prepareWorkerSocketPath(socketPath string) (string, error) {
	if err := validateWorkerUnixSocketPath(socketPath); err != nil {
		return "", err
	}
	dir := filepath.Dir(socketPath)
	if err := ensureUserOnlySocketDir(dir); err != nil {
		return "", err
	}
	bindPath, err := resolveUnixSocketBindPath(socketPath)
	if err != nil {
		return "", err
	}
	if err := removeStaleUnixSocket(bindPath); err != nil {
		return "", err
	}
	return bindPath, nil
}

func currentWindowsTokenSIDs() (userSID *windows.SID, ownerSID *windows.SID, err error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, nil, E.Cause(err, "open current process token")
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, nil, E.Cause(err, "query current token user")
	}
	userCopy, err := tokenUser.User.Sid.Copy()
	if err != nil {
		return nil, nil, E.Cause(err, "copy current token user SID")
	}
	var needed uint32
	gerr := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &needed)
	if gerr != nil && !errors.Is(gerr, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, nil, E.Cause(gerr, "query current token owner size")
	}
	if needed == 0 {
		return userCopy, nil, nil
	}
	buf := make([]byte, needed)
	if gerr := windows.GetTokenInformation(token, windows.TokenOwner, &buf[0], needed, &needed); gerr != nil {
		return nil, nil, E.Cause(gerr, "query current token owner")
	}
	rawOwner := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	if rawOwner != nil {
		ownerCopy, cerr := rawOwner.Copy()
		if cerr != nil {
			return nil, nil, E.Cause(cerr, "copy current token owner SID")
		}
		ownerSID = ownerCopy
	}
	return userCopy, ownerSID, nil
}

func userOnlySocketSDDL(userSID, tokenOwnerSID *windows.SID) string {
	userStr := userSID.String()
	if tokenOwnerSID != nil && !windows.EqualSid(userSID, tokenOwnerSID) {
		return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)", userStr, tokenOwnerSID.String())
	}
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)", userStr)
}

func openNoFollowWindows(path string, desiredAccess uint32) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		pathPtr,
		desiredAccess,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func verifyHandleOwnedByCurrentUser(handle windows.Handle, label string) error {
	userSID, tokenOwnerSID, err := currentWindowsTokenSIDs()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return E.Cause(err, "query owner security info for ", label)
	}
	ownerSID, _, err := sd.Owner()
	if err != nil {
		return E.Cause(err, "read owner SID for ", label)
	}
	if windows.EqualSid(ownerSID, userSID) {
		return nil
	}
	if tokenOwnerSID != nil && windows.EqualSid(ownerSID, tokenOwnerSID) {
		return nil
	}
	return E.New("owner of ", label, " (", ownerSID.String(), ") does not match current user")
}

func ensureUserOnlySocketDir(dir string) error {
	userSID, tokenOwnerSID, err := currentWindowsTokenSIDs()
	if err != nil {
		return err
	}
	sddl := userOnlySocketSDDL(userSID, tokenOwnerSID)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return E.Cause(err, "parse socket directory security descriptor")
	}

	// Ensure parent directories exist, creating the leaf directory with a protected user-only DACL when new.
	if _, statErr := os.Lstat(dir); os.IsNotExist(statErr) {
		parent := filepath.Dir(dir)
		if parent != dir {
			if err := os.MkdirAll(parent, 0o700); err != nil {
				return E.Cause(err, "create socket directory parent")
			}
		}
		dirPtr, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return err
		}
		sa := &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: sd,
		}
		if err := windows.CreateDirectory(dirPtr, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return E.Cause(err, "create protected socket directory")
		}
	}

	// Open by handle without following reparse points so owner verification and DACL update have no TOCTOU.
	handle, err := openNoFollowWindows(dir, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return E.Cause(err, "open socket directory")
	}
	defer windows.CloseHandle(handle)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return E.Cause(err, "query socket directory attributes")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return E.New("socket directory is a reparse point: ", dir)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return E.New("socket directory is not a directory: ", dir)
	}
	if err := verifyHandleOwnedByCurrentUser(handle, dir); err != nil {
		return err
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return E.Cause(err, "extract socket directory DACL")
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return E.Cause(err, "apply user-only DACL to socket directory")
	}
	return nil
}

func verifyUnixSocketOwner(path string) error {
	handle, err := openNoFollowWindows(path, windows.READ_CONTROL)
	if err != nil {
		return E.Cause(err, "open AF_UNIX socket for owner check")
	}
	defer windows.CloseHandle(handle)
	return verifyHandleOwnedByCurrentUser(handle, path)
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return true
		}
	}
	return false
}

func resolveUnixSocketBindPath(socketPath string) (string, error) {
	tooLong := len([]byte(socketPath)) > maxUnixSocketPathBytes
	nonASCII := hasNonASCII(socketPath)
	if !tooLong && !nonASCII {
		return socketPath, nil
	}
	shortened, err := shortenWindowsSocketPath(socketPath)
	if err != nil {
		if !tooLong {
			return socketPath, nil
		}
		return "", E.New(
			"AF_UNIX socket path is ", len([]byte(socketPath)),
			" UTF-8 bytes (limit ", maxUnixSocketPathBytes, ") and 8.3 shortening failed: ", err,
		)
	}
	if len([]byte(shortened)) > maxUnixSocketPathBytes {
		if !tooLong {
			return socketPath, nil
		}
		return "", E.New(
			"AF_UNIX socket path is ", len([]byte(shortened)),
			" UTF-8 bytes after 8.3 shortening (limit ", maxUnixSocketPathBytes, ")",
		)
	}
	return shortened, nil
}

func shortenWindowsSocketPath(socketPath string) (string, error) {
	dir := filepath.Dir(socketPath)
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetShortPathName(dirPtr, &buf[0], uint32(len(buf)))
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", E.New("GetShortPathName returned 0")
		}
		if int(n) < len(buf) {
			return filepath.Join(windows.UTF16ToString(buf[:n]), filepath.Base(socketPath)), nil
		}
		if int(n) > 32768 {
			return "", E.New("GetShortPathName buffer too large")
		}
		buf = make([]uint16, n)
	}
}

func removeStaleUnixSocket(path string) error {
	isSocket, exists, err := isWindowsAFUnixSocket(path)
	if err != nil {
		return E.Cause(err, "inspect existing socket path")
	}
	if !exists {
		return nil
	}
	if !isSocket {
		return E.New("refusing to remove non-socket file at ", path)
	}
	return os.Remove(path)
}

func isWindowsAFUnixSocket(path string) (isSocket bool, exists bool, err error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, false, err
	}
	var data windows.Win32finddata
	handle, err := windows.FindFirstFile(pathPtr, &data)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return false, false, nil
		}
		return false, false, err
	}
	_ = windows.FindClose(handle)
	isAFUnix := data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && data.Reserved0 == ioReparseTagAFUnix
	return isAFUnix, true, nil
}

func isNormalRelayCloseError(err error) bool {
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.Errno(10053)) || // WSAECONNABORTED
		errors.Is(err, syscall.Errno(10054)) || // WSAECONNRESET
		errors.Is(err, windows.ERROR_NETNAME_DELETED) ||
		errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_CONNECTION_ABORTED)
}
