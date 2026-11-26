package boxdd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var commandServiceTakeOverFlagUID string

var commandServiceInstall = &cobra.Command{
	Use:   "install",
	Short: "Install or update the system service",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := serviceInstallLinux(defaultLinuxInstallEnv())
		if err != nil {
			var exitErr *installExitError
			if errors.As(err, &exitErr) {
				log.Error(E.Cause(err, "install service"))
				os.Exit(exitErr.code)
			}
			log.Fatal(E.Cause(err, "install service"))
		}
	},
}

var commandServiceUninstall = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the system service",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := serviceUninstallLinux(defaultLinuxInstallEnv())
		if err != nil {
			var exitErr *installExitError
			if errors.As(err, &exitErr) {
				log.Error(E.Cause(err, "uninstall service"))
				os.Exit(exitErr.code)
			}
			log.Fatal(E.Cause(err, "uninstall service"))
		}
	},
}

var commandServiceTakeOver = &cobra.Command{
	Use:   "take-over",
	Short: "Transfer service ownership to a local user (root CLI)",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := serviceTakeOverLinux(defaultLinuxInstallEnv(), commandServiceTakeOverFlagUID)
		if err != nil {
			var exitErr *installExitError
			if errors.As(err, &exitErr) {
				log.Error(E.Cause(err, "take over service"))
				os.Exit(exitErr.code)
			}
			log.Fatal(E.Cause(err, "take over service"))
		}
	},
}

var commandServiceRestart = &cobra.Command{
	Use:   "restart",
	Short: "Restart the system service",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := serviceRestart()
		if err != nil {
			log.Fatal(E.Cause(err, "restart service"))
		}
	},
}

var commandServiceSetInsecureMode = &cobra.Command{
	Use:   "set-insecure-mode <enabled>",
	Short: "Set whether configurations may use privileges unrelated to networking",
	Args:  cobra.ExactArgs(1),
	Run: func(command *cobra.Command, args []string) {
		err := serviceSetInsecureMode(args[0])
		if err != nil {
			log.Fatal(E.Cause(err, "set insecure mode"))
		}
	},
}

func addPlatformServiceCommands() {
	commandServiceTakeOver.Flags().StringVar(&commandServiceTakeOverFlagUID, "uid", "", "numeric UID of the new service owner (defaults to PKEXEC_UID or SUDO_UID)")
	commandService.AddCommand(commandServiceInstall)
	commandService.AddCommand(commandServiceUninstall)
	commandService.AddCommand(commandServiceTakeOver)
	commandService.AddCommand(commandServiceRestart)
	commandService.AddCommand(commandServiceSetInsecureMode)
}

func serviceSetInsecureMode(value string) error {
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return E.Cause(err, "parse value")
	}
	if os.Geteuid() != 0 {
		return E.New("setting insecure mode requires an elevated process")
	}
	directory, err := filepath.Abs(commandServiceFlagWorkingDirectory)
	if err != nil {
		return E.Cause(err, "resolve working directory")
	}
	err = validateProtectedLinuxDirectory(directory)
	if err != nil {
		return E.Cause(err, "validate working directory")
	}
	return updateDaemonSettings(directory, func(settings *daemonSettings) {
		settings.InsecureModeEnabled = enabled
	})
}

func runSystemctl(arguments ...string) error {
	output, err := exec.Command("systemctl", arguments...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return E.Cause(err, "systemctl ", strings.Join(arguments, " "))
		}
		return E.New("systemctl ", strings.Join(arguments, " "), ": ", message)
	}
	return nil
}

func serviceStart() error {
	return runSystemctl("start", activeNames.serviceUnitName())
}

func serviceStop() error {
	installed, err := serviceInstalled()
	if err != nil {
		return err
	}
	if !installed {
		log.Info("service not installed")
		return nil
	}
	return runSystemctl("stop", activeNames.serviceUnitName())
}

func serviceRestart() error {
	return runSystemctl("restart", activeNames.serviceUnitName())
}

func serviceInstalled() (bool, error) {
	loadState, err := systemctlProperty("LoadState")
	if err != nil {
		return false, err
	}
	return loadState != "" && loadState != "not-found", nil
}

func systemctlProperty(property string) (string, error) {
	output, err := exec.Command("systemctl", "show", "--property="+property, "--value", activeNames.serviceUnitName()).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return "", E.Cause(err, "query system service")
		}
		return "", E.New("query system service: ", message)
	}
	return strings.TrimSpace(string(output)), nil
}

func parseSystemdExecStartPath(raw string) string {
	// systemctl show --property=ExecStart --value outputs e.g.:
	// "{ path=/usr/local/libexec/niko/niko-daemon ; argv[]=/usr/local/libexec/niko/niko-daemon run ... ; ... }"
	idx := strings.Index(raw, "path=")
	if idx < 0 {
		return ""
	}
	rest := raw[idx+len("path="):]
	if end := strings.IndexAny(rest, " ;}"); end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}

func serviceStatus() (*serviceStatusResult, error) {
	installed, err := serviceInstalled()
	if err != nil {
		return nil, err
	}
	if !installed {
		return &serviceStatusResult{exitCode: 3, description: "not installed"}, nil
	}
	activeState, err := systemctlProperty("ActiveState")
	if err != nil {
		return nil, err
	}
	binaryPath := ""
	if execStart, err := systemctlProperty("ExecStart"); err == nil {
		binaryPath = parseSystemdExecStartPath(execStart)
	}
	if activeState == "active" {
		return &serviceStatusResult{exitCode: 0, description: "running", binary: binaryPath}, nil
	}
	return &serviceStatusResult{exitCode: 2, description: "stopped", binary: binaryPath}, nil
}
