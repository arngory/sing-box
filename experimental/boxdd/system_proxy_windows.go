//go:build windows

package boxdd

// niko: the owner's own WinINet proxy settings, kept while the daemon's system proxy is on and put back exactly when
// it goes off. Upstream's Disable clears the proxy (direct and automatic detection), which leaves the server it set in
// the registry and loses a proxy the user had (a corporate one). They are read and written as the owner, impersonated
// as upstream's Enable and Disable are (HKEY_CURRENT_USER is the owner's there: newPlatformInterface turns off the
// predefined handles' cache), and kept in a file of the owner's beside the start options, so a crash while the proxy is
// on does not lose them: kept settings found while the proxy is not on are put back as the owner is set, and before it
// goes on again. Where none were kept, upstream's clear is all there is.

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode/utf16"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/tailscale/atomicfile"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const savedSystemProxyFileName = "saved_system_proxy.json"

const (
	internetSettingsKey    = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	internetConnectionsKey = internetSettingsKey + `\Connections`
)

// savedProxyValues are the registry values of HKCU the system proxy is: those WinINet writes when it changes.
var savedProxyValues = []struct{ key, name string }{
	{internetSettingsKey, "ProxyEnable"},
	{internetSettingsKey, "ProxyServer"},
	{internetSettingsKey, "ProxyOverride"},
	{internetSettingsKey, "AutoConfigURL"},
	{internetConnectionsKey, "DefaultConnectionSettings"},
}

// savedSystemProxy is the owner's proxy settings before the daemon's: each value as it was, Type 0 for none.
type savedSystemProxy struct {
	Values []savedProxyValue `json:"values"`
}

type savedProxyValue struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Type uint32 `json:"type,omitempty"`
	Data []byte `json:"data,omitempty"`
}

// readProxyValues and writeProxyValues read and put back the current user's values (the owner's, impersonated);
// notifyProxyChanged tells WinINet; a test's own.
var (
	readProxyValues    = readRegistryProxyValues
	writeProxyValues   = writeRegistryProxyValues
	notifyProxyChanged = notifyWinINet
)

func readRegistryProxyValues() (*savedSystemProxy, error) {
	saved := &savedSystemProxy{}
	for _, value := range savedProxyValues {
		entry := savedProxyValue{Key: value.key, Name: value.name}
		key, err := registry.OpenKey(registry.CURRENT_USER, value.key, registry.QUERY_VALUE)
		if err == nil {
			entry.Data, entry.Type, err = rawValue(key, value.name)
			key.Close()
		}
		if err != nil && !errors.Is(err, registry.ErrNotExist) && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return nil, E.Cause(err, "read ", value.name)
		}
		saved.Values = append(saved.Values, entry)
	}
	return saved, nil
}

func rawValue(key registry.Key, name string) ([]byte, uint32, error) {
	n, valueType, err := key.GetValue(name, nil)
	if err != nil {
		return nil, 0, err
	}
	data := make([]byte, n)
	n, valueType, err = key.GetValue(name, data)
	if err != nil {
		return nil, 0, err
	}
	return data[:n], valueType, nil
}

func writeRegistryProxyValues(saved *savedSystemProxy) error {
	for _, value := range saved.Values {
		key, err := registry.OpenKey(registry.CURRENT_USER, value.Key, registry.SET_VALUE)
		if err != nil {
			if value.Type == 0 && errors.Is(err, registry.ErrNotExist) {
				continue
			}
			return E.Cause(err, "open ", value.Key)
		}
		err = setRawValue(key, value)
		key.Close()
		if err != nil {
			return E.Cause(err, "put back ", value.Name)
		}
	}
	return nil
}

// notifyWinINet has WinINet read the settings again (run as the owner).
func notifyWinINet() error {
	for _, option := range []uintptr{internetOptionSettingsChanged, internetOptionRefresh} {
		if result, _, err := procInternetSetOption.Call(0, option, 0, 0); result != 1 {
			return os.NewSyscallError("InternetSetOption", err)
		}
	}
	return nil
}

func setRawValue(key registry.Key, value savedProxyValue) error {
	switch value.Type {
	case 0:
		err := key.DeleteValue(value.Name)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	case registry.DWORD:
		if len(value.Data) != 4 {
			return E.New("a DWORD of ", len(value.Data), " bytes")
		}
		return key.SetDWordValue(value.Name, binary.LittleEndian.Uint32(value.Data))
	case registry.SZ:
		return key.SetStringValue(value.Name, utf16String(value.Data))
	case registry.EXPAND_SZ:
		return key.SetExpandStringValue(value.Name, utf16String(value.Data))
	case registry.BINARY:
		return key.SetBinaryValue(value.Name, value.Data)
	}
	return E.New("a value of type ", value.Type)
}

func utf16String(data []byte) string {
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	for len(units) > 0 && units[len(units)-1] == 0 {
		units = units[:len(units)-1]
	}
	return string(utf16.Decode(units))
}

var procInternetSetOption = windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

func savedSystemProxyPath(ownerUserID string) string {
	return filepath.Join(userWorkingDirectory(ownerUserID), savedSystemProxyFileName)
}

// errKeptUnreadable: the kept file was read and is not settings (errKeptSetAside once it is set aside); a failure to
// read it is the file system's, and may pass.
var (
	errKeptUnreadable = errors.New("the owner's kept proxy settings are not readable")
	errKeptSetAside   = errors.New("the owner's kept proxy settings were set aside")
)

func loadSavedSystemProxy(ownerUserID string) (*savedSystemProxy, error) {
	content, err := os.ReadFile(savedSystemProxyPath(ownerUserID))
	if err != nil {
		return nil, err
	}
	saved, err := json.UnmarshalExtended[savedSystemProxy](content)
	if err != nil {
		return nil, E.Errors(errKeptUnreadable, err)
	}
	return &saved, nil
}

// isDaemons: the values are the daemon's own proxy on, as a crash leaves them, not the owner's settings: on, and the
// server one the daemon sets (servers: this run's, and the last one set, which a crash may have left on another port).
// It takes WinINet to write ProxyServer to the registry as it was given ("http://" and the address, as upstream's
// Enable gives it).
func (s *savedSystemProxy) isDaemons(servers ...string) bool {
	enabled, current := false, ""
	for _, value := range s.Values {
		switch {
		case value.Name == "ProxyEnable" && value.Type == registry.DWORD && len(value.Data) == 4:
			enabled = binary.LittleEndian.Uint32(value.Data) == 1
		case value.Name == "ProxyServer" && value.Type == registry.SZ:
			current = utf16String(value.Data)
		}
	}
	if !enabled || current == "" {
		return false
	}
	for _, server := range servers {
		if server == current {
			return true
		}
	}
	return false
}

// lastSystemProxyServerFileName holds the servers the daemon may have left on for the owner, a line each: before its
// proxy goes on, those it held and this run's; once it is on, this run's alone. A crash's proxy is told apart by them
// when the next run's is on another port, also where a run in between failed to turn its own on. A file of one line
// (an older daemon's) is a set of one.
const lastSystemProxyServerFileName = "last_system_proxy_server"

func lastSystemProxyServerPath(ownerUserID string) string {
	return filepath.Join(userWorkingDirectory(ownerUserID), lastSystemProxyServerFileName)
}

func loadLastSystemProxyServers(ownerUserID string) []string {
	content, err := os.ReadFile(lastSystemProxyServerPath(ownerUserID))
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(content), "\n") {
		if line = strings.TrimSpace(line); line != "" && !slices.Contains(servers, line) {
			servers = append(servers, line)
		}
	}
	return servers
}

func saveLastSystemProxyServers(ownerUserID string, servers []string) error {
	err := os.MkdirAll(userWorkingDirectory(ownerUserID), 0o700)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(lastSystemProxyServerPath(ownerUserID), []byte(strings.Join(servers, "\n")), 0o600)
}

// systemProxySetter is the system proxy as the platform sets it (settings.WindowsSystemProxy); a test's own.
type systemProxySetter interface {
	IsEnabled() bool
	Enable() error
	Disable() error
}

// canRunAsOwnerLocked: the owner's operations can run: in development mode or user-mode as this process,
// as a service with the owner's token. Without it upstream's runUserOperationLocked does nothing, and the owner's settings are not reached.
func (p *windowsPlatformInterface) canRunAsOwnerLocked() bool {
	return p.ownerUserID != "" && (listenAddress != "" || userMode || p.token != 0)
}

// enableSystemProxyLocked turns the daemon's system proxy on for the owner, their own settings kept first. Settings
// kept already are stale (a crash, a failed restore): put back first, so what is kept is the user's as they are now;
// where that fails, the old ones stay kept and the proxy goes on all the same.
func (p *windowsPlatformInterface) enableSystemProxyLocked() error {
	var last []string
	if p.canRunAsOwnerLocked() {
		last = loadLastSystemProxyServers(p.ownerUserID)
		err := p.restoreKeptProxyLocked()
		if errors.Is(err, errKeptSetAside) {
			// set aside: the registry's kept anew as below, unless it is a daemon's own proxy of a crash
			p.warn(err)
			err = nil
		}
		switch {
		case err != nil:
			// the kept ones cannot be put back: not this Enable's, so their failure does not stop the next stop
			p.keptUnrestorable = true
			p.warn(err)
		default:
			p.keptUnrestorable = false
			var saved *savedSystemProxy
			err = p.runUserOperationLocked(func() (readError error) {
				saved, readError = readProxyValues()
				return readError
			})
			// the daemon's own proxy (a crash's, none kept) is not the owner's: not kept
			if err == nil && saved != nil && !saved.isDaemons(append(last, p.systemProxyServer)...) {
				err = writeSavedSystemProxy(p.ownerUserID, saved)
			}
			if err != nil {
				return E.Cause(err, "keep the owner's proxy settings")
			}
		}
		if p.systemProxyServer != "" {
			err = saveLastSystemProxyServers(p.ownerUserID, appendServer(last, p.systemProxyServer))
			if err != nil {
				return E.Cause(err, "keep the server set")
			}
		}
	}
	err := p.runUserOperationLocked(p.systemProxy.Enable)
	if err == nil && p.canRunAsOwnerLocked() && p.systemProxyServer != "" {
		// on: the servers a crash may have left are this run's alone now
		if saveError := saveLastSystemProxyServers(p.ownerUserID, []string{p.systemProxyServer}); saveError != nil {
			p.warn(E.Cause(saveError, "keep the server set"))
		}
	}
	return err
}

func appendServer(servers []string, server string) []string {
	if slices.Contains(servers, server) {
		return servers
	}
	return append(slices.Clone(servers), server)
}

// disableSystemProxyLocked turns it off (upstream's clear) and puts the owner's own settings back: an error where
// this call turned the daemon's proxy off. Settings kept while it was not on are stale (an Enable that failed, a
// restore that did): put back where they can be, else told and kept for the next try.
func (p *windowsPlatformInterface) disableSystemProxyLocked() error {
	if p.systemProxy != nil && p.systemProxy.IsEnabled() {
		err := p.runUserOperationLocked(p.systemProxy.Disable)
		if err != nil {
			return err
		}
		err = p.restoreKeptProxyLocked()
		if err != nil && (p.keptUnrestorable || errors.Is(err, errKeptSetAside)) {
			// kept before this run and not put back when it went on: told, kept for the next try
			p.warn(err)
			return nil
		}
		return err
	}
	p.recoverKeptProxyLocked()
	return nil
}

// restoreKeptProxyLocked writes the owner's kept settings back as the owner and forgets them; none kept, or no way to
// run as the owner: nothing, and they stay kept. One that cannot be written stays kept, for the next try.
func (p *windowsPlatformInterface) restoreKeptProxyLocked() error {
	if !p.canRunAsOwnerLocked() {
		return nil
	}
	path := savedSystemProxyPath(p.ownerUserID)
	saved, err := loadSavedSystemProxy(p.ownerUserID)
	if os.IsNotExist(err) {
		return nil
	}
	if errors.Is(err, errKeptUnreadable) {
		// read and not settings, which no later try changes: set aside, not tried at every start and stop; one
		// that cannot be moved stays, told
		if renameError := os.Rename(path, path+".bad"); renameError != nil {
			p.warn(E.Cause(renameError, "set aside the owner's proxy settings"))
		}
		return E.Errors(errKeptSetAside, err)
	}
	if err != nil {
		// the file system's (a lock, a denial): kept for the next try
		return E.Cause(err, "read the owner's proxy settings")
	}
	err = p.runUserOperationLocked(func() error {
		writeError := writeProxyValues(saved)
		if writeError != nil {
			return writeError
		}
		return notifyProxyChanged()
	})
	if err != nil {
		return E.Cause(err, "put back the owner's proxy settings")
	}
	err = os.Remove(savedSystemProxyPath(p.ownerUserID))
	if err != nil && !os.IsNotExist(err) {
		p.warn(E.Cause(err, "forget the owner's proxy settings"))
	}
	return nil
}

// recoverKeptProxyLocked: an owner's settings kept while the daemon's proxy is not on are stale (a crash, a failed
// restore): put back as the owner is set; told, not failed, and tried again later.
func (p *windowsPlatformInterface) recoverKeptProxyLocked() {
	if p.systemProxy != nil && p.systemProxy.IsEnabled() {
		return
	}
	if err := p.restoreKeptProxyLocked(); err != nil {
		p.warn(err)
	}
}

func (p *windowsPlatformInterface) warn(err error) {
	if p.daemon != nil && p.daemon.logger != nil {
		p.daemon.logger.Warn(err)
	}
}

func writeSavedSystemProxy(ownerUserID string, saved *savedSystemProxy) error {
	content, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	err = os.MkdirAll(userWorkingDirectory(ownerUserID), 0o700)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(savedSystemProxyPath(ownerUserID), content, 0o600)
}
