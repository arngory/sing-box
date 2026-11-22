//go:build windows

package boxdd

// niko: the owner's own WinINet proxy settings, kept while the daemon's system proxy is on and put back exactly when
// it goes off. Upstream's Disable clears the proxy (direct and automatic detection), which leaves the server it set in
// the registry and loses a proxy the user had (a corporate one). They are read and written in the owner's hive
// (HKEY_USERS\<SID>), and kept in a file of the owner's beside the start options, so a crash while the proxy is on does
// not lose them: kept settings found while the proxy is not on are put back as the owner is set, and before it goes
// on again. Where none were kept, upstream's clear is all there is.

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
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

// readProxyValues and writeProxyValues read and put back an owner's values; notifyProxyChanged tells WinINet, as the
// owner; a test's own.
var (
	readProxyValues    = readRegistryProxyValues
	writeProxyValues   = writeRegistryProxyValues
	notifyProxyChanged = notifyWinINet
)

// userKeyPath is where a key of the owner's is: their hive, HKEY_USERS\<their SID>, as HKEY_CURRENT_USER is the
// process's own (SYSTEM's for the service) and does not follow an impersonation; in development mode the daemon runs
// as its user, and the owner has no SID there ("local").
func userKeyPath(ownerUserID string, path string) (registry.Key, string) {
	if listenAddress != "" {
		return registry.CURRENT_USER, path
	}
	return registry.USERS, ownerUserID + `\` + path
}

// openUserKey opens a key of the owner's (userKeyPath); a test's own.
var openUserKey = func(ownerUserID string, path string, access uint32) (registry.Key, error) {
	root, full := userKeyPath(ownerUserID, path)
	return registry.OpenKey(root, full, access)
}

func readRegistryProxyValues(ownerUserID string) (*savedSystemProxy, error) {
	saved := &savedSystemProxy{}
	for _, value := range savedProxyValues {
		entry := savedProxyValue{Key: value.key, Name: value.name}
		key, err := openUserKey(ownerUserID, value.key, registry.QUERY_VALUE)
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

func writeRegistryProxyValues(ownerUserID string, saved *savedSystemProxy) error {
	for _, value := range saved.Values {
		key, err := openUserKey(ownerUserID, value.Key, registry.SET_VALUE)
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

func loadSavedSystemProxy(ownerUserID string) (*savedSystemProxy, error) {
	content, err := os.ReadFile(savedSystemProxyPath(ownerUserID))
	if err != nil {
		return nil, err
	}
	saved, err := json.UnmarshalExtended[savedSystemProxy](content)
	if err != nil {
		return nil, err
	}
	return &saved, nil
}

// systemProxySetter is the system proxy as the platform sets it (settings.WindowsSystemProxy); a test's own.
type systemProxySetter interface {
	IsEnabled() bool
	Enable() error
	Disable() error
}

// enableSystemProxyLocked turns the daemon's system proxy on for the owner, their own settings kept first. Settings
// kept already are stale (a crash, a failed restore): put back first, so what is kept is the user's as they are now.
func (p *windowsPlatformInterface) enableSystemProxyLocked() error {
	if p.ownerUserID != "" && (listenAddress != "" || p.token != 0) {
		err := p.restoreKeptProxyLocked()
		if err != nil {
			return err
		}
		saved, err := readProxyValues(p.ownerUserID)
		if err != nil {
			return E.Cause(err, "keep the owner's proxy settings")
		}
		err = writeSavedSystemProxy(p.ownerUserID, saved)
		if err != nil {
			return E.Cause(err, "keep the owner's proxy settings")
		}
	}
	return p.runUserOperationLocked(p.systemProxy.Enable)
}

// disableSystemProxyLocked turns it off (upstream's clear) and puts the owner's own settings back where they were
// kept: also where it is not on (an Enable that failed, a restore to try again).
func (p *windowsPlatformInterface) disableSystemProxyLocked() error {
	if p.systemProxy != nil && p.systemProxy.IsEnabled() {
		err := p.runUserOperationLocked(p.systemProxy.Disable)
		if err != nil {
			return err
		}
	}
	return p.restoreKeptProxyLocked()
}

// restoreKeptProxyLocked writes the owner's kept settings back and forgets them; none kept: nothing. One that cannot
// be written stays kept, for the next try.
func (p *windowsPlatformInterface) restoreKeptProxyLocked() error {
	if p.ownerUserID == "" {
		return nil
	}
	saved, err := loadSavedSystemProxy(p.ownerUserID)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read the owner's proxy settings")
	}
	err = writeProxyValues(p.ownerUserID, saved)
	if err != nil {
		return E.Cause(err, "put back the owner's proxy settings")
	}
	err = p.runUserOperationLocked(notifyProxyChanged)
	if err != nil {
		return E.Cause(err, "put back the owner's proxy settings")
	}
	err = os.Remove(savedSystemProxyPath(p.ownerUserID))
	if err != nil && !os.IsNotExist(err) && p.daemon != nil {
		p.daemon.logger.Warn("forget the owner's proxy settings: ", err)
	}
	return nil
}

// recoverKeptProxyLocked: an owner's settings kept while the daemon's proxy is not on are stale (a crash, a failed
// restore): put back as the owner is set; told, not failed, and tried again later.
func (p *windowsPlatformInterface) recoverKeptProxyLocked() {
	if p.systemProxy != nil && p.systemProxy.IsEnabled() {
		return
	}
	err := p.restoreKeptProxyLocked()
	if err != nil && p.daemon != nil {
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
