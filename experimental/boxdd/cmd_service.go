package boxdd

import (
	"encoding/json"
	"os"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var (
	commandServiceFlagWorkingDirectory string
	commandServiceStatusFlagFormat     string
)

var commandService = &cobra.Command{
	Use:   "service",
	Short: "Manage the system service",
}

var commandServiceStart = &cobra.Command{
	Use:   "start",
	Short: "Start the system service",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := serviceStart()
		if err != nil {
			log.Fatal(E.Cause(err, "start service"))
		}
	},
}

var commandServiceStop = &cobra.Command{
	Use:   "stop",
	Short: "Stop the system service",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := serviceStop()
		if err != nil {
			log.Fatal(E.Cause(err, "stop service"))
		}
	},
}

var commandServiceStatus = &cobra.Command{
	Use:   "status",
	Short: "Print the system service status",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		status, err := serviceStatus()
		if err != nil {
			log.Fatal(E.Cause(err, "query service status"))
		}
		switch commandServiceStatusFlagFormat {
		case "", "text":
			os.Stdout.WriteString(status.description + "\n")
		case "json":
			payload, marshalErr := json.Marshal(struct {
				State  string `json:"state"`
				Binary string `json:"binary,omitempty"`
			}{
				State:  status.state(),
				Binary: status.binary,
			})
			if marshalErr != nil {
				log.Fatal(E.Cause(marshalErr, "encode service status"))
			}
			os.Stdout.WriteString(string(payload) + "\n")
		default:
			log.Fatal(E.New("unsupported status format: ", commandServiceStatusFlagFormat))
		}
		os.Exit(status.exitCode)
	},
}

type serviceStatusResult struct {
	exitCode    int
	description string
	binary      string
}

func (r *serviceStatusResult) state() string {
	switch r.exitCode {
	case 0:
		return "running"
	case 2:
		return "stopped"
	case 3:
		return "not-installed"
	default:
		return r.description
	}
}

func init() {
	commandService.PersistentFlags().StringVarP(&commandServiceFlagWorkingDirectory, "working-directory", "D", activeNames.defaultWorkingDirectory(), "daemon working directory")
	commandServiceStatus.Flags().StringVar(&commandServiceStatusFlagFormat, "format", "text", "output format: text or json")
	commandService.AddCommand(commandServiceStart)
	commandService.AddCommand(commandServiceStop)
	commandService.AddCommand(commandServiceStatus)
	addPlatformServiceCommands()
	mainCommand.AddCommand(commandService)
}
