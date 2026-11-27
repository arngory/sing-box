//go:build windows

package boxdd

// niko: unprivileged Windows user-mode daemon hosted inside the AF_UNIX + HMAC worker (Phase P4 / C7).

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	winioProcess "github.com/tailscale/go-winio/pkg/process"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc"
)

func runSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func currentWindowsUserIdentity() (peerIdentity, error) {
	pid := uint32(os.Getpid())
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return peerIdentity{}, E.Cause(err, "open current process")
	}
	defer windows.CloseHandle(proc)
	return processIdentity(proc, pid)
}

func defaultWindowsUserWorkingDir() (string, error) {
	localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if localAppData == "" {
		cfgDir, err := os.UserConfigDir()
		if err != nil || cfgDir == "" {
			return "", E.New("cannot resolve LOCALAPPDATA for user-mode working directory")
		}
		localAppData = cfgDir
	}
	return filepath.Join(localAppData, activeNames.Product, "user-daemon"), nil
}

// prepareUserModeRun refuses `run --user-mode` on Windows so an unprivileged user never serves
// an open named pipe readable by other authenticated users; Windows user-mode runs exclusively
// inside `worker --user-mode` behind AF_UNIX + peer PID + mutual HMAC-SHA256.
func prepareUserModeRun() (func(), error) {
	return nil, E.New("on Windows use 'worker --user-mode' instead of 'run --user-mode'")
}

func ensureUserModeOwner() error {
	return nil
}

// prepareUserModeWorkerParent verifies that the worker's parent is the expected application
// executable in the same user session and was created before this worker (defending against PID reuse).
func prepareUserModeWorkerParent(parentProcessID uint32) (*windowsWorkerParent, error) {
	if os.Getppid() != int(parentProcessID) {
		return nil, E.New("user-mode worker was not started by the expected application process")
	}
	selfProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if err != nil {
		return nil, E.Cause(err, "open current process")
	}
	defer windows.CloseHandle(selfProc)
	selfIdentity, err := processIdentity(selfProc, uint32(os.Getpid()))
	if err != nil {
		return nil, err
	}
	selfCreationTime, err := processCreationTime(selfProc)
	if err != nil {
		return nil, err
	}

	parentProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, parentProcessID)
	if err != nil {
		return nil, err
	}
	keepProcess := false
	defer func() {
		if !keepProcess {
			windows.CloseHandle(parentProcess)
		}
	}()
	parentID, err := processIdentity(parentProcess, parentProcessID)
	if err != nil {
		return nil, err
	}
	if parentID.UserID != selfIdentity.UserID || parentID.SessionID != selfIdentity.SessionID {
		return nil, E.New("user-mode worker parent belongs to another user or session")
	}
	parentCreationTime, err := processCreationTime(parentProcess)
	if err != nil {
		return nil, err
	}
	if parentCreationTime >= selfCreationTime {
		return nil, E.New("user-mode worker parent was created after the worker")
	}
	parentImagePath, err := winioProcess.QueryFullProcessImageName(parentProcess, winioProcess.ImageNameFormatWin32Path)
	if err != nil {
		return nil, E.Cause(err, "query worker parent executable")
	}
	if !strings.EqualFold(filepath.Base(parentImagePath), activeNames.ApplicationExe) {
		return nil, E.New("user-mode worker parent executable mismatch: ", filepath.Base(parentImagePath))
	}

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		_, _ = windows.WaitForSingleObject(parentProcess, windows.INFINITE)
	}()
	keepProcess = true
	return &windowsWorkerParent{
		process:        parentProcess,
		executablePath: parentImagePath,
		userID:         parentID.UserID,
		sessionID:      parentID.SessionID,
		pid:            parentProcessID,
		exited:         exited,
	}, nil
}

type hmacAcceptResult struct {
	conn net.Conn
	err  error
}

type hmacUnixWorkerListener struct {
	net.Listener
	key            *[workerKeySize]byte
	windowPID      uint32
	workerPID      uint32
	handshakeSlots chan struct{}
	ready          chan hmacAcceptResult
	closed         chan struct{}
	closeOnce      sync.Once
}

func newHMACUnixWorkerListener(base net.Listener, key *[workerKeySize]byte, windowPID, workerPID uint32) *hmacUnixWorkerListener {
	l := &hmacUnixWorkerListener{
		Listener:       base,
		key:            key,
		windowPID:      windowPID,
		workerPID:      workerPID,
		handshakeSlots: make(chan struct{}, maxPendingWorkerHandshakes),
		ready:          make(chan hmacAcceptResult, maxPendingWorkerHandshakes),
		closed:         make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *hmacUnixWorkerListener) acceptLoop() {
	defer close(l.ready)
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case <-l.closed:
			case l.ready <- hmacAcceptResult{err: err}:
			}
			return
		}
		select {
		case l.handshakeSlots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func(c net.Conn) {
			defer func() { <-l.handshakeSlots }()
			if err := workerServerHandshake(c, l.key, l.windowPID, l.workerPID); err != nil {
				_ = c.Close()
				return
			}
			_ = c.SetDeadline(time.Time{})
			select {
			case l.ready <- hmacAcceptResult{conn: c}:
			case <-l.closed:
				_ = c.Close()
			}
		}(conn)
	}
}

func (l *hmacUnixWorkerListener) Accept() (net.Conn, error) {
	res, ok := <-l.ready
	if !ok {
		return nil, net.ErrClosed
	}
	return res.conn, res.err
}

func (l *hmacUnixWorkerListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.Listener.Close()
	})
	return err
}

func runUserModeWorker() error {
	key, err := readWorkerKey(os.Stdin, workerHandshakeTimeout)
	if err != nil {
		return err
	}
	defer zeroBytes(key[:])

	parent, err := prepareUserModeWorkerParent(workerParentProcessID)
	if err != nil {
		return err
	}
	defer parent.Close()

	userMode = true
	if workerWorkingDirectory != "" {
		workingDirectory = workerWorkingDirectory
	} else {
		dir, err := defaultWindowsUserWorkingDir()
		if err != nil {
			return err
		}
		workingDirectory = dir
	}
	if err := prepareWorkingDirectory(); err != nil {
		return E.Cause(err, "prepare user-mode working directory")
	}
	if err := saveOwner(parent.userID, parent.sessionID); err != nil {
		return E.Cause(err, "save user-mode owner")
	}

	listener, bindPath, err := listenWorkerUnixEndpoint(workerDaemonRelayUnixPath, parent)
	if err != nil {
		return err
	}
	hmacListener := newHMACUnixWorkerListener(listener, key, parent.pid, uint32(os.Getpid()))
	defer hmacListener.Close()

	d, err := newDaemon()
	if err != nil {
		return err
	}
	// Set owner immediately and repair any WinINet proxy settings left behind by a previous crash.
	if wp, ok := d.platform.(*windowsPlatformInterface); ok {
		wp.access.Lock()
		wp.ownerUserID = parent.userID
		wp.sessionID = parent.sessionID
		wp.recoverKeptProxyLocked()
		wp.access.Unlock()
	}
	defer d.Close()

	serveErrCh := make(chan error, 1)
	go func() {
		err := d.server.Serve(hmacListener)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
			serveErrCh <- err
		}
		close(serveErrCh)
	}()

	stdinEOF := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdinEOF)
	}()

	fmt.Printf("READY %s\n", bindPath)
	_ = os.Stdout.Sync()

	select {
	case err := <-serveErrCh:
		// If the parent already exited, closing the listener is expected shutdown, not a fatal error.
		select {
		case <-parent.Exited():
			return nil
		default:
		}
		return err
	case <-stdinEOF:
		return nil
	case <-parent.Exited():
		return nil
	}
}
