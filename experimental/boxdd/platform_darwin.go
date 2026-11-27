//go:build darwin

package boxdd

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// darwinPlatformInterface configures the macOS user-session system HTTP/HTTPS proxy via `networksetup`
// for unprivileged user-mode proxy connections (M1).
type darwinPlatformInterface struct {
	daemon             *Daemon
	access             sync.Mutex
	proxyServer        string
	proxyPort          uint16
	configuredServices []string
	systemProxyActive  bool
	systemProxyEnabled bool
}

func newPlatformInterface(daemonInstance *Daemon) (daemonPlatform, error) {
	return &darwinPlatformInterface{
		daemon:             daemonInstance,
		systemProxyEnabled: true,
	}, nil
}

func (p *darwinPlatformInterface) Initialize(networkManager adapter.NetworkManager) error { return nil }
func (p *darwinPlatformInterface) UsePlatformAutoDetectInterfaceControl() bool            { return false }
func (p *darwinPlatformInterface) AutoDetectInterfaceControl(fd int) error                { return os.ErrInvalid }
func (p *darwinPlatformInterface) UsePlatformInterface() bool                             { return false }
func (p *darwinPlatformInterface) OpenInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	return nil, os.ErrInvalid
}

func (p *darwinPlatformInterface) ProcessPlatformOptions(options option.TunPlatformOptions) error {
	if options.HTTPProxy == nil || !options.HTTPProxy.Enabled {
		return nil
	}
	p.access.Lock()
	defer p.access.Unlock()
	if p.proxyPort != 0 {
		return E.New("only one enabled `tun.platform.http_proxy` is supported")
	}
	p.proxyServer = options.HTTPProxy.Server
	p.proxyPort = options.HTTPProxy.ServerPort
	if err := p.applySystemProxyLocked(); err != nil {
		rollbackErr := p.disableSystemProxyLocked()
		p.proxyServer = ""
		p.proxyPort = 0
		return E.Errors(E.Cause(err, "set macOS system proxy"), rollbackErr)
	}
	return nil
}

func (p *darwinPlatformInterface) UsePlatformDefaultInterfaceMonitor() bool { return false }
func (p *darwinPlatformInterface) CreateDefaultInterfaceMonitor(logger logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}
func (p *darwinPlatformInterface) UsePlatformNetworkInterfaces() bool                     { return false }
func (p *darwinPlatformInterface) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, os.ErrInvalid }
func (p *darwinPlatformInterface) UnderNetworkExtension() bool                            { return false }
func (p *darwinPlatformInterface) NetworkExtensionIncludeAllNetworks() bool               { return false }
func (p *darwinPlatformInterface) ClearDNSCache()                                         {}
func (p *darwinPlatformInterface) RequestPermissionForWIFIState() error                   { return nil }
func (p *darwinPlatformInterface) ReadWIFIState(ctx context.Context) adapter.WIFIState    { return adapter.WIFIState{} }
func (p *darwinPlatformInterface) UsePlatformConnectionOwnerFinder() bool                 { return false }
func (p *darwinPlatformInterface) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, os.ErrInvalid
}
func (p *darwinPlatformInterface) UsePlatformWIFIMonitor() bool { return false }
func (p *darwinPlatformInterface) UsePlatformNotification() bool { return true }
func (p *darwinPlatformInterface) SendNotification(notification *adapter.Notification) error {
	return p.daemon.startedService.SendNotification(notification)
}
func (p *darwinPlatformInterface) CancelNotification(identifier string, typeID int32) error {
	return p.daemon.startedService.CancelNotification(identifier, typeID)
}
func (p *darwinPlatformInterface) MyInterfaceAddress() []netip.Addr { return nil }
func (p *darwinPlatformInterface) UsePlatformNeighborResolver() bool { return false }
func (p *darwinPlatformInterface) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return os.ErrInvalid
}
func (p *darwinPlatformInterface) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return nil
}
func (p *darwinPlatformInterface) UsePlatformShell() bool   { return false }
func (p *darwinPlatformInterface) CheckPlatformShell() error { return nil }
func (p *darwinPlatformInterface) OpenShellSession(user *adapter.PlatformUser, command string, environ []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}
func (p *darwinPlatformInterface) LookupUser(username string) (*adapter.PlatformUser, error) {
	return nil, os.ErrInvalid
}
func (p *darwinPlatformInterface) LookupSFTPServer() (string, error)    { return "", os.ErrInvalid }
func (p *darwinPlatformInterface) ReadSystemSSHHostKey() ([]byte, error) { return nil, os.ErrInvalid }
func (p *darwinPlatformInterface) TailscaleHostname() string            { return "" }
func (p *darwinPlatformInterface) UsePlatformBridge() bool              { return false }
func (p *darwinPlatformInterface) CreateBridge(options adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, os.ErrInvalid
}

func (p *darwinPlatformInterface) PrepareOwner(identity peerIdentity) error {
	p.access.Lock()
	defer p.access.Unlock()
	return p.applySystemProxyLocked()
}

func (p *darwinPlatformInterface) RestoreOwner(state ownerState) error { return nil }

func (p *darwinPlatformInterface) ReleaseOwner() error {
	p.access.Lock()
	defer p.access.Unlock()
	return p.disableSystemProxyLocked()
}

func (p *darwinPlatformInterface) ResetPlatformOptions() error {
	p.access.Lock()
	defer p.access.Unlock()
	err := p.disableSystemProxyLocked()
	if err == nil {
		p.proxyServer = ""
		p.proxyPort = 0
	}
	return err
}

func (p *darwinPlatformInterface) SetSystemProxyPreference(enabled bool) {
	p.access.Lock()
	p.systemProxyEnabled = enabled
	p.access.Unlock()
}

func (p *darwinPlatformInterface) SystemProxyStatus() (*daemon.SystemProxyStatus, error) {
	p.access.Lock()
	defer p.access.Unlock()
	available := p.proxyPort != 0
	return &daemon.SystemProxyStatus{
		Available: available,
		Enabled:   available && p.systemProxyActive,
	}, nil
}

func (p *darwinPlatformInterface) SetSystemProxyEnabled(enabled bool) error {
	p.access.Lock()
	defer p.access.Unlock()
	if p.proxyPort == 0 {
		if !enabled {
			p.systemProxyEnabled = false
			return nil
		}
		return E.New("the system proxy is not available")
	}
	previous := p.systemProxyEnabled
	p.systemProxyEnabled = enabled
	if err := p.applySystemProxyLocked(); err != nil {
		p.systemProxyEnabled = previous
		rollback := p.applySystemProxyLocked()
		return E.Errors(err, rollback)
	}
	return nil
}

func (p *darwinPlatformInterface) HandleSessionChange(eventType uint32, sessionID uint32, state ownerState) (uint32, bool, error) {
	return 0, false, nil
}

func (p *darwinPlatformInterface) Close() error {
	p.access.Lock()
	defer p.access.Unlock()
	err := p.disableSystemProxyLocked()
	p.proxyServer = ""
	p.proxyPort = 0
	return err
}

func (p *darwinPlatformInterface) applySystemProxyLocked() error {
	if p.proxyPort == 0 {
		return nil
	}
	if !p.systemProxyEnabled {
		return p.disableSystemProxyLocked()
	}
	if p.systemProxyActive {
		return nil
	}
	services, err := darwinNetworkServices()
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return E.New("no active macOS network services found")
	}
	portStr := strconv.Itoa(int(p.proxyPort))
	var applied []string
	for _, svc := range services {
		if err := runNetworkSetup("-setwebproxy", svc, p.proxyServer, portStr); err != nil {
			continue
		}
		if err := runNetworkSetup("-setsecurewebproxy", svc, p.proxyServer, portStr); err != nil {
			_ = runNetworkSetup("-setwebproxystate", svc, "off")
			continue
		}
		applied = append(applied, svc)
	}
	if len(applied) == 0 {
		return E.New("networksetup failed on all macOS network services")
	}
	p.configuredServices = applied
	p.systemProxyActive = true
	return nil
}

func (p *darwinPlatformInterface) disableSystemProxyLocked() error {
	if !p.systemProxyActive {
		return nil
	}
	var errs []error
	for _, svc := range p.configuredServices {
		if err := runNetworkSetup("-setwebproxystate", svc, "off"); err != nil {
			errs = append(errs, err)
		}
		if err := runNetworkSetup("-setsecurewebproxystate", svc, "off"); err != nil {
			errs = append(errs, err)
		}
	}
	p.configuredServices = nil
	p.systemProxyActive = false
	return E.Errors(errs...)
}

func darwinNetworkServices() ([]string, error) {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

func runNetworkSetup(args ...string) error {
	out, err := exec.Command("/usr/sbin/networksetup", args...).CombinedOutput()
	if err != nil {
		return E.Cause(err, "networksetup ", strings.Join(args, " "), ": ", strings.TrimSpace(string(out)))
	}
	return nil
}

var _ daemonPlatform = (*darwinPlatformInterface)(nil)
