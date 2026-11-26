//go:build windows

package boxdd

import (
	"testing"
)

func TestNekoValidateWorkerCommandLine(t *testing.T) {
	defaultNames := DefaultNames()
	nikoNames := nikoTestNames()
	unixSock := `C:\Users\Alice\AppData\Local\Niko\run\w-0123456789abcdef.sock`

	validPipe := []string{
		`C:\Program Files\sing-box\resources\daemon\sing-box-daemon.exe`,
		"worker",
		"--socket", `\\.\pipe\sing-box-worker.app`,
		"--parent-pid", "4242",
		"--daemon-relay-socket", `\\.\pipe\sing-box-worker.relay`,
	}
	if err := validateWorkerCommandLine(validPipe, 4242, WorkerTransportPipe, defaultNames); err != nil {
		t.Fatalf("valid pipe command line rejected: %v", err)
	}
	if err := validateWorkerCommandLine(validPipe, 4242, WorkerTransportUnix, nikoNames); err == nil {
		t.Fatal("pipe command line accepted in unix transport mode")
	}

	validUnix := []string{
		`C:\Program Files\Niko\resources\daemon\niko-daemon.exe`,
		"worker",
		"--parent-pid", "4242",
		"--daemon-relay-unix", unixSock,
	}
	if err := validateWorkerCommandLine(validUnix, 4242, WorkerTransportUnix, nikoNames); err != nil {
		t.Fatalf("valid unix command line rejected: %v", err)
	}
	if err := validateWorkerCommandLine(validUnix, 4242, WorkerTransportPipe, defaultNames); err == nil {
		t.Fatal("unix command line accepted in pipe transport mode")
	}
	if err := validateWorkerCommandLine(validUnix, 9999, WorkerTransportUnix, nikoNames); err == nil {
		t.Fatal("mismatched parent PID accepted")
	}

	badUnixPath := []string{
		`C:\Program Files\Niko\resources\daemon\niko-daemon.exe`,
		"worker",
		"--parent-pid", "4242",
		"--daemon-relay-unix", `\\.\pipe\niko-worker.sock`,
	}
	if err := validateWorkerCommandLine(badUnixPath, 4242, WorkerTransportUnix, nikoNames); err == nil {
		t.Fatal("named pipe accepted for --daemon-relay-unix")
	}
}
