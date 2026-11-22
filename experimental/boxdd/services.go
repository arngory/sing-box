package boxdd

// niko: boxdd as a package (Niko's docs/desktop/STAGE3.md, slice 1). A program builds its daemon from it with gRPC
// services of its own beside the daemon's, each with a policy for who may call its methods; cmd/boxdd passes none and
// is upstream's boxdd.

import (
	"context"
	"runtime"
	"strings"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Options are what a program adds to the daemon.
type Options struct {
	Services []Service
}

// Service is a gRPC service the daemon serves beside its own, through the same listener, credentials and
// interceptors.
type Service struct {
	Desc *grpc.ServiceDesc
	// New makes the implementation once the daemon is built; what it may use of the daemon is Host.
	New func(host Host) (any, error)
	// Policy is who may call the service's methods; Methods overrides it for a method by its name (a unary method's
	// MethodName, a stream's StreamName). The zero policy refuses.
	Policy  MethodPolicy
	Methods map[string]MethodPolicy
}

// MethodPolicy is who may call a method of an added service.
type MethodPolicy int

const (
	// PolicyRefuse: no one, as a method the daemon does not know.
	PolicyRefuse MethodPolicy = iota
	// PolicyCaller: any caller the daemon verified (on Windows the installed client, on Linux a local process by its
	// credentials), as DesktopService.
	PolicyCaller
	// PolicyOwner: the daemon's owner only, under its lifecycle lock, as StartedService and ManagedService.
	PolicyOwner
	// PolicyOwnerUnlocked: the daemon's owner only, checked under the lifecycle lock and run outside it: for a long
	// read of the running core (a lookup through its DNS), which a stop, a start or the service's own shutdown must
	// not wait for. Such a method takes the running core for itself and ends with its context.
	PolicyOwnerUnlocked
)

// Host is what an added service sees of the daemon.
type Host interface {
	// Context is the daemon's: its services and platform interface, not a running core's.
	Context() context.Context
	// StartedService runs the core: its RunningInstance is the core running now, or nil.
	StartedService() *daemon.StartedService
	Logger() log.ContextLogger
	// StartService starts or reloads the core with a config for the caller of ctx, as DesktopService.StartService
	// does with no options: the caller becomes the daemon's owner, the stored start options stay, and the config is
	// kept for the daemon's next start. With a systemProxy, that is the owner's system proxy while the core runs, as a
	// TUN's platform.http_proxy is (SystemProxy). PermissionDenied when another user owns the daemon; the core's own
	// error for a config it refuses. It takes the lifecycle lock: a method that calls it is not PolicyOwner's.
	StartService(ctx context.Context, configContent string, systemProxy *SystemProxy) error
}

// SystemProxy is a system proxy a core's start asks for, as a TUN's platform.http_proxy (an HTTP proxy of the
// config's, often its mixed inbound): set by the daemon for its owner, not for the user the daemon runs as (SYSTEM,
// root), as the inbound's own set_system_proxy would be. Kept with the start options, it is set again when the daemon
// starts the core again; ManagedService.SetSystemProxyEnabled turns it off and on, and a stop takes it away. The
// bypass list is Windows' alone (Linux's settings take none). A config whose TUN sets platform.http_proxy has the
// system proxy already: one asked beside it is refused (InvalidArgument).
type SystemProxy struct {
	Server       string   `json:"server"`
	Port         uint16   `json:"port"`
	BypassDomain []string `json:"bypass_domain,omitempty"`
}

// setSystemProxyLocked has the platform set the system proxy asked, after the core started: refused where the
// config's TUN took it, an error where the platform has none (Linux without gsettings or kwriteconfig).
func (d *Daemon) setSystemProxyLocked(p *SystemProxy) error {
	proxyStatus, err := d.platform.SystemProxyStatus()
	if err != nil {
		return err
	}
	if proxyStatus.Available {
		return status.Error(codes.InvalidArgument, "the config already sets tun.platform.http_proxy")
	}
	if runtime.GOOS != "windows" && len(p.BypassDomain) > 0 {
		d.logger.Warn("system proxy: the bypass list applies on Windows only")
	}
	err = d.platform.ProcessPlatformOptions(p.platformOptions())
	if err != nil {
		return E.Cause(err, "set system proxy")
	}
	proxyStatus, err = d.platform.SystemProxyStatus()
	if err != nil {
		return err
	}
	if !proxyStatus.Available {
		return E.New("set system proxy: this system has none the daemon can set")
	}
	return nil
}

func (p *SystemProxy) platformOptions() option.TunPlatformOptions {
	return option.TunPlatformOptions{HTTPProxy: &option.HTTPProxyOptions{
		Enabled:       true,
		ServerOptions: option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		BypassDomain:  p.BypassDomain,
	}}
}

// the services Main was given; newDaemon registers them
var addedServices []Service

func (d *Daemon) Context() context.Context {
	return d.ctx
}

func (d *Daemon) StartedService() *daemon.StartedService {
	return d.startedService
}

func (d *Daemon) Logger() log.ContextLogger {
	return d.logger
}

func (d *Daemon) StartService(ctx context.Context, configContent string, systemProxy *SystemProxy) error {
	identity, err := peerIdentityFromContext(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	return d.startServiceFor(ctx, identity, configContent, nil, systemProxy)
}

// registerServices makes and registers the added services, refusing one whose name is taken or whose Methods name a
// method it has not.
func (d *Daemon) registerServices(services []Service, setServing func(string)) error {
	taken := make(map[string]bool)
	for name := range d.server.GetServiceInfo() {
		taken[name] = true
	}
	for _, added := range services {
		if added.Desc == nil || added.New == nil {
			return E.New("an added service without its description or constructor")
		}
		name := added.Desc.ServiceName
		if taken[name] {
			return E.New("service ", name, ": the name is taken")
		}
		taken[name] = true
		for method := range added.Methods {
			if !serviceHasMethod(added.Desc, method) {
				return E.New("service ", name, ": no method ", method)
			}
		}
		implementation, err := added.New(d)
		if err != nil {
			return E.Cause(err, "service ", name)
		}
		d.server.RegisterService(added.Desc, implementation)
		setServing(name)
	}
	d.services = services
	return nil
}

func serviceHasMethod(desc *grpc.ServiceDesc, name string) bool {
	for _, method := range desc.Methods {
		if method.MethodName == name {
			return true
		}
	}
	for _, stream := range desc.Streams {
		if stream.StreamName == name {
			return true
		}
	}
	return false
}

// methodPolicy is the policy of an added service's method; false: the method is not an added service's.
func (d *Daemon) methodPolicy(method string) (MethodPolicy, bool) {
	for _, added := range d.services {
		name, found := strings.CutPrefix(method, "/"+added.Desc.ServiceName+"/")
		if !found {
			continue
		}
		if policy, overridden := added.Methods[name]; overridden {
			return policy, true
		}
		return added.Policy, true
	}
	return PolicyRefuse, false
}

// ownerProtected: the method is the owner's and runs under the lifecycle lock: the daemon's StartedService and
// ManagedService, an added service's with PolicyOwner.
func (d *Daemon) ownerProtected(method string) bool {
	if ownerProtectedMethod(method) {
		return true
	}
	policy, added := d.methodPolicy(method)
	return added && policy == PolicyOwner
}

// ownerChecked: the method is the owner's, checked under the lifecycle lock and run outside it (PolicyOwnerUnlocked).
func (d *Daemon) ownerChecked(method string) bool {
	policy, added := d.methodPolicy(method)
	return added && policy == PolicyOwnerUnlocked
}
