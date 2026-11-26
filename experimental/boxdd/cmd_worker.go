package boxdd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	workerSocketPath            string
	workerDaemonRelaySocketPath string
	workerDaemonRelayUnixPath   string
	workerParentProcessID       uint32
	workerUserMode              bool
	workerWorkingDirectory      string
)

type workerParent interface {
	Close() error
	Exited() <-chan struct{}
}

var commandWorker = &cobra.Command{
	Use:   "worker",
	Short: "Serve the non-privileged application worker for the application process",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := runWorker()
		if err != nil {
			log.Fatal(E.Cause(err, "run application worker"))
		}
	},
}

func init() {
	commandWorker.Flags().StringVar(&workerSocketPath, "socket", "", "listen on the specified unix domain socket path, or named pipe path on Windows")
	commandWorker.Flags().StringVar(&workerDaemonRelaySocketPath, "daemon-relay-socket", "", "relay the authenticated Windows daemon connection on the specified named pipe path")
	commandWorker.Flags().StringVar(&workerDaemonRelayUnixPath, "daemon-relay-unix", "", "relay the authenticated Windows daemon connection on the specified AF_UNIX socket path")
	commandWorker.Flags().Uint32Var(&workerParentProcessID, "parent-pid", 0, "expected application parent process ID")
	commandWorker.Flags().BoolVar(&workerUserMode, "user-mode", false, "host the unprivileged user-mode daemon directly behind the authenticated AF_UNIX worker socket")
	commandWorker.Flags().StringVarP(&workerWorkingDirectory, "working-directory", "D", "", "working directory for --user-mode worker")
	mainCommand.AddCommand(commandWorker)
}

func validateWorkerFlags(transport WorkerTransport, socket, relaySocket, relayUnix string, parentPID uint32) error {
	if parentPID == 0 {
		return E.New("missing --parent-pid")
	}
	switch transport {
	case WorkerTransportUnix:
		if socket != "" || relaySocket != "" {
			return E.New("--socket and --daemon-relay-socket are not supported in AF_UNIX worker mode")
		}
		if relayUnix == "" {
			return E.New("missing --daemon-relay-unix")
		}
		return validateWorkerUnixSocketPath(relayUnix)
	case WorkerTransportPipe:
		if relayUnix != "" {
			return E.New("--daemon-relay-unix is not supported in named pipe worker mode")
		}
		if socket == "" {
			return E.New("missing --socket")
		}
		return nil
	default:
		return E.New("unsupported worker transport")
	}
}

func runWorker() error {
	if err := validateWorkerFlags(
		activeOptions.WorkerTransport,
		workerSocketPath,
		workerDaemonRelaySocketPath,
		workerDaemonRelayUnixPath,
		workerParentProcessID,
	); err != nil {
		return err
	}
	if activeOptions.WorkerTransport == WorkerTransportUnix {
		if workerUserMode {
			return runUserModeWorker()
		}
		return runUnixRelayWorker()
	}
	parent, err := prepareWorkerParent(workerParentProcessID)
	if err != nil {
		return err
	}
	defer parent.Close()
	listener, err := listenWorkerEndpoint(workerSocketPath, parent)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(daemon.UnaryLocaleInterceptor),
		grpc.ChainStreamInterceptor(daemon.StreamLocaleInterceptor),
	)
	RegisterApplicationServiceServer(server, &applicationService{
		startedService: daemon.NewStartedService(daemon.ServiceOptions{Context: include.Context(context.Background())}),
	})
	relayErrorChannel := make(chan error, 1)
	relay, err := startWorkerDaemonRelay(workerDaemonRelaySocketPath, parent, func(relayError error) {
		select {
		case relayErrorChannel <- relayError:
		default:
		}
		server.Stop()
	})
	if err != nil {
		return err
	}
	if relay != nil {
		defer relay.Close()
	}
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		if relay != nil {
			relay.Close()
		}
		server.Stop()
	}()
	fmt.Println("READY")
	err = server.Serve(listener)
	select {
	case relayError := <-relayErrorChannel:
		return relayError
	default:
	}
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

func runUnixRelayWorker() error {
	key, err := readWorkerKey(os.Stdin, workerHandshakeTimeout)
	if err != nil {
		return err
	}
	defer zeroBytes(key[:])

	parent, err := prepareWorkerParent(workerParentProcessID)
	if err != nil {
		return err
	}
	defer parent.Close()

	relayErrorChannel := make(chan error, 1)
	doneChannel := make(chan struct{})
	relay, bindPath, err := startWorkerUnixDaemonRelay(workerDaemonRelayUnixPath, parent, key, func(relayError error) {
		select {
		case relayErrorChannel <- relayError:
		default:
		}
	})
	if err != nil {
		return err
	}
	defer relay.Close()

	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(doneChannel)
	}()

	fmt.Printf("READY %s\n", bindPath)
	_ = os.Stdout.Sync()

	select {
	case relayError := <-relayErrorChannel:
		return relayError
	case <-doneChannel:
		return nil
	case <-parent.Exited():
		return nil
	}
}
