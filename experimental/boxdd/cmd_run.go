package boxdd

import (
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var (
	workingDirectory string
	socketPath       string
	listenAddress    string
)

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "Run the daemon",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(E.Cause(err, "run daemon"))
		}
	},
}

func init() {
	commandRun.Flags().StringVarP(&workingDirectory, "working-directory", "D", "", "working directory")
	commandRun.Flags().StringVar(&socketPath, "socket", "", "listen on the specified unix domain socket path, or named pipe path on Windows")
	commandRun.Flags().StringVar(&listenAddress, "listen", "", "listen on the specified TCP address (development only)")
	mainCommand.AddCommand(commandRun)
}

func prepareWorkingDirectory() error {
	if workingDirectory == "" {
		return E.New("missing working directory")
	}
	absoluteWorkingDirectory, err := filepath.Abs(workingDirectory)
	if err != nil {
		return err
	}
	workingDirectory = absoluteWorkingDirectory
	err = preparePlatformWorkingDirectory()
	if err != nil {
		return err
	}
	err = os.Chdir(workingDirectory)
	if err != nil {
		return err
	}
	err = libbox.Setup(&libbox.SetupOptions{
		BasePath:          workingDirectory,
		WorkingPath:       workingDirectory,
		TempPath:          workingDirectory,
		CrashReportSource: "Daemon",
		AppVersion:        C.Version,
	})
	if err != nil {
		return err
	}
	libbox.PromoteOOMDraft()
	libbox.DiscardPowerReportDraft()
	return nil
}

var loopbackIPv4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// niko: --listen accepts 127.0.0.1:<1024..65535> literally, and only when the binary was built with
// DevelopmentListen enabled (docs/design/desktop-stage3.md, §6).
func validateListenAddress(raw string) (netip.AddrPort, error) {
	if !activeOptions.DevelopmentListen {
		return netip.AddrPort{}, E.New("this build has no development mode")
	}
	addrPort, err := netip.ParseAddrPort(raw)
	if err != nil {
		return netip.AddrPort{}, E.New("--listen takes 127.0.0.1:<1024..65535> and nothing else")
	}
	if !addrPort.Addr().Is4() || addrPort.Addr() != loopbackIPv4 || addrPort.Addr().Zone() != "" {
		return netip.AddrPort{}, E.New("--listen takes 127.0.0.1:<1024..65535> and nothing else")
	}
	if addrPort.Port() < 1024 {
		return netip.AddrPort{}, E.New("--listen port must be between 1024 and 65535")
	}
	return addrPort, nil
}

func run() error {
	if listenAddress != "" {
		if _, err := validateListenAddress(listenAddress); err != nil {
			return err
		}
	}
	handled, err := runService()
	if handled {
		return err
	}
	err = prepareWorkingDirectory()
	if err != nil {
		return err
	}
	d, err := newDaemon()
	if err != nil {
		return err
	}
	err = d.Start()
	if err != nil {
		return err
	}
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	<-signalChannel
	d.Close()
	return nil
}
