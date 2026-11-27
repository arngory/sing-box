//go:build darwin

package boxdd

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type darwinTransportCredentials struct {
	daemon *Daemon
}

type darwinAuthenticatedConnection struct {
	net.Conn
	daemon     *Daemon
	identity   peerIdentity
	close      sync.Once
	closeError error
}

func platformServerOptions(daemon *Daemon) ([]grpc.ServerOption, error) {
	if listenAddress != "" {
		return nil, nil
	}
	return []grpc.ServerOption{grpc.Creds(&darwinTransportCredentials{daemon: daemon})}, nil
}

func platformFallbackPeerIdentity(ctx context.Context) (peerIdentity, error) {
	if listenAddress != "" {
		return peerIdentity{UserID: "local"}, nil
	}
	return peerIdentity{}, E.New("missing macOS peer authentication")
}

func (c *darwinTransportCredentials) ClientHandshake(ctx context.Context, authority string, rawConnection net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, E.New("macOS local process credentials do not support client handshakes")
}

func (c *darwinTransportCredentials) ServerHandshake(rawConnection net.Conn) (net.Conn, credentials.AuthInfo, error) {
	identity, err := darwinPeerIdentity(rawConnection)
	if err != nil {
		return nil, nil, err
	}
	connection := &darwinAuthenticatedConnection{
		Conn:     rawConnection,
		daemon:   c.daemon,
		identity: identity,
	}
	c.daemon.registerPeerConnection(connection)
	authenticationInformation := &peerAuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		identity:       identity,
	}
	return connection, authenticationInformation, nil
}

func (c *darwinTransportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "darwin-local-process",
	}
}

func (c *darwinTransportCredentials) Clone() credentials.TransportCredentials {
	return &darwinTransportCredentials{daemon: c.daemon}
}

func (c *darwinTransportCredentials) OverrideServerName(serverNameOverride string) error {
	return nil
}

func darwinPeerIdentity(connection net.Conn) (peerIdentity, error) {
	syscallConnection, loaded := connection.(syscall.Conn)
	if !loaded {
		return peerIdentity{}, E.New("daemon endpoint does not expose a syscall connection")
	}
	rawConnection, err := syscallConnection.SyscallConn()
	if err != nil {
		return peerIdentity{}, E.Cause(err, "access daemon endpoint")
	}
	var xucred *unix.Xucred
	var credErr error
	var peerPID int
	var pidErr error
	err = rawConnection.Control(func(fileDescriptor uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fileDescriptor), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		peerPID, pidErr = unix.GetsockoptInt(int(fileDescriptor), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return peerIdentity{}, E.Cause(err, "inspect daemon endpoint")
	}
	if credErr != nil {
		return peerIdentity{}, E.Cause(credErr, "identify daemon peer")
	}
	if xucred == nil {
		return peerIdentity{}, E.New("daemon peer has invalid credentials")
	}
	if userMode && xucred.Uid != uint32(os.Geteuid()) {
		return peerIdentity{}, E.New("user-mode daemon accepts connections only from its own UID")
	}
	var processID uint32
	if pidErr == nil && peerPID > 0 {
		processID = uint32(peerPID)
	}
	return peerIdentity{
		UserID:    strconv.FormatUint(uint64(xucred.Uid), 10),
		ProcessID: processID,
	}, nil
}

func (c *darwinAuthenticatedConnection) peerConnectionIdentity() peerIdentity {
	return c.identity
}

func (c *darwinAuthenticatedConnection) Close() error {
	c.close.Do(func() {
		c.daemon.unregisterPeerConnection(c)
		c.closeError = c.Conn.Close()
	})
	return c.closeError
}

var (
	_ credentials.TransportCredentials = (*darwinTransportCredentials)(nil)
	_ peerConnection                   = (*darwinAuthenticatedConnection)(nil)
)
