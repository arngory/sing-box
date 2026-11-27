//go:build darwin

package boxdd

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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

const darwinProxySnapshotName = "darwin_proxy_snapshot.json"

type darwinServiceProxyState struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    string `json:"port"`
}

type darwinServiceSnapshot struct {
	Service string                  `json:"service"`
	Web     darwinServiceProxyState `json:"web"`
	Secure  darwinServiceProxyState `json:"secure"`
}

// darwinPlatformInterface configures system-wide macOS HTTP/HTTPS proxy settings via `networksetup`.
// Note: `networksetup` modifies system-wide network service proxy settings and may require administrator
// privileges depending on macOS authorization settings. Prior proxy settings are snapshotted to disk before
// modification and restored on disable, reset, or crash recovery.
type darwinPlatformInterface struct {
	daemon             *Daemon
	access             sync.Mutex
	proxyServer        string
	proxyPort          uint16
	savedSnapshots     []darwinServiceSnapshot
	systemProxyActive  bool
	systemProxyEnabled bool
}

func newPlatformInterface(daemonInstance *Daemon) (daemonPlatform, error) {
	p := &darwinPlatformInterface{
		daemon:             daemonInstance,
		systemProxyEnabled: true,
	}
	// Crash recovery: if a prior daemon exited abruptly while holding system proxy settings, restore them.
	p.recoverSnapshotLocked()
	return p, nil
}

func (p *darwinPlatformInterface) snapshotPath() string {
	dir := ""
	if p.daemon != nil {
		dir = p.daemon.WorkingDirectory()
	}
	if dir == "" {
		dir = workingDirectory
	}
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, darwinProxySnapshotName)
}

func (p *darwinPlatformInterface) recoverSnapshotLocked() {
	path := p.snapshotPath()
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var snaps []darwinServiceSnapshot
	if err := json.Unmarshal(raw, &snaps); err != nil || len(snaps) == 0 {
		_ = os.Remove(path)
		return
	}
	for _, snap := range snaps {
		_ = restoreDarwinServiceSnapshot(snap)
	}
	_ = os.Remove(path)
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
	// Always clear local proxy target state even when networksetup fails so future starts never wedge on "only one enabled".
	p.proxyServer = ""
	p.proxyPort = 0
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
	var snapshots []darwinServiceSnapshot
	for _, svc := range services {
		snap := snapshotDarwinServiceProxy(svc)
		if err := runNetworkSetup("-setwebproxy", svc, p.proxyServer, portStr); err != nil {
			continue
		}
		if err := runNetworkSetup("-setsecurewebproxy", svc, p.proxyServer, portStr); err != nil {
			_ = restoreDarwinServiceSnapshot(snap)
			continue
		}
		snapshots = append(snapshots, snap)
	}
	if len(snapshots) == 0 {
		return E.New("networksetup failed on all macOS network services (admin privileges may be required)")
	}
	p.savedSnapshots = snapshots
	p.systemProxyActive = true
	if path := p.snapshotPath(); path != "" {
		if raw, err := json.Marshal(snapshots); err == nil {
			_ = os.MkdirAll(filepath.Dir(path), 0o700)
			_ = os.WriteFile(path, raw, 0o600)
		}
	}
	return nil
}

func (p *darwinPlatformInterface) disableSystemProxyLocked() error {
	if !p.systemProxyActive && len(p.savedSnapshots) == 0 {
		return nil
	}
	var errs []error
	for _, snap := range p.savedSnapshots {
		if err := restoreDarwinServiceSnapshot(snap); err != nil {
			errs = append(errs, err)
		}
	}
	p.savedSnapshots = nil
	p.systemProxyActive = false
	if path := p.snapshotPath(); path != "" {
		_ = os.Remove(path)
	}
	return E.Errors(errs...)
}

func snapshotDarwinServiceProxy(service string) darwinServiceSnapshot {
	return darwinServiceSnapshot{
		Service: service,
		Web:     readDarwinProxyState("-getwebproxy", service),
		Secure:  readDarwinProxyState("-getsecurewebproxy", service),
	}
}

func readDarwinProxyState(flag string, service string) darwinServiceProxyState {
	out, err := exec.Command("/usr/sbin/networksetup", flag, service).Output()
	if err != nil {
		return darwinServiceProxyState{}
	}
	var st darwinServiceProxyState
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "Enabled":
			st.Enabled = strings.EqualFold(v, "Yes")
		case "Server":
			st.Server = v
		case "Port":
			if v != "0" {
				st.Port = v
			}
		}
	}
	return st
}

func restoreDarwinServiceSnapshot(snap darwinServiceSnapshot) error {
	var errs []error
	if snap.Web.Enabled && snap.Web.Server != "" && snap.Web.Port != "" {
		if err := runNetworkSetup("-setwebproxy", snap.Service, snap.Web.Server, snap.Web.Port); err != nil {
			errs = append(errs, err)
		}
	} else {
		if err := runNetworkSetup("-setwebproxystate", snap.Service, "off"); err != nil {
			errs = append(errs, err)
		}
	}
	if snap.Secure.Enabled && snap.Secure.Server != "" && snap.Secure.Port != "" {
		if err := runNetworkSetup("-setsecurewebproxy", snap.Service, snap.Secure.Server, snap.Secure.Port); err != nil {
			errs = append(errs, err)
		}
	} else {
		if err := runNetworkSetup("-setsecurewebproxystate", snap.Service, "off"); err != nil {
			errs = append(errs, err)
		}
	}
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
