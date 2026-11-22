//go:build windows

package boxdd

// niko: the owner's own WinINet proxy settings, kept while the daemon's system proxy is on and put back exactly when
// it goes off. Upstream's Disable clears the proxy (direct and automatic detection), which leaves the server it set in
// the registry and loses a proxy the user had (a corporate one). The values are kept in a file of the owner's beside
// the start options, so a crash while the proxy is on does not lose them: the next start finds them, and they are put
// back when its proxy goes off. Where none were kept, upstream's clear is all there is.

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

// readProxyValues and writeProxyValues read and put back the current user's values (the owner's, impersonated); a
// test's own.
var (
	readProxyValues  = readRegistryProxyValues
	writeProxyValues = writeRegistryProxyValues
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
	// WinINet reads them again
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

// enableSystemProxyLocked turns the daemon's system proxy on for the owner, their own settings kept first, as the user
// it impersonates; the file is written by the daemon itself. Those kept already (by a run that crashed with its proxy
// on) stay: the daemon's own are in the registry now.
func (p *windowsPlatformInterface) enableSystemProxyLocked() error {
	if p.ownerUserID != "" {
		if _, err := os.Stat(savedSystemProxyPath(p.ownerUserID)); os.IsNotExist(err) {
			var saved *savedSystemProxy
			err = p.runUserOperationLocked(func() (readError error) {
				saved, readError = readProxyValues()
				return readError
			})
			if err != nil {
				return E.Cause(err, "keep the owner's proxy settings")
			}
			if saved != nil {
				err = writeSavedSystemProxy(p.ownerUserID, saved)
				if err != nil {
					return E.Cause(err, "keep the owner's proxy settings")
				}
			}
		}
	}
	return p.runUserOperationLocked(p.systemProxy.Enable)
}

// disableSystemProxyLocked turns it off (upstream's clear) and puts the owner's own settings back where they were
// kept, then forgets them; none kept: the clear stays.
func (p *windowsPlatformInterface) disableSystemProxyLocked() error {
	if p.systemProxy == nil || !p.systemProxy.IsEnabled() {
		return nil
	}
	var saved *savedSystemProxy
	if p.ownerUserID != "" {
		var err error
		saved, err = loadSavedSystemProxy(p.ownerUserID)
		if err != nil && !os.IsNotExist(err) {
			return E.Cause(err, "read the owner's proxy settings")
		}
	}
	restored := false
	err := p.runUserOperationLocked(func() error {
		disableError := p.systemProxy.Disable()
		if disableError != nil || saved == nil {
			return disableError
		}
		restored = true
		return writeProxyValues(saved)
	})
	if err != nil {
		return err
	}
	if restored {
		return os.Remove(savedSystemProxyPath(p.ownerUserID))
	}
	return nil
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
