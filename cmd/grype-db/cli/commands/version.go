package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/grype-db/cmd/grype-db/application"
)

func Version(_ *application.Application) *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "version",
		Short: fmt.Sprintf("show %s version information", application.Name),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return err
			}
			// note: we intentionally do not execute through the application infrastructure (no app config is required for this command)

			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			// note: we intentionally do not execute through the application infrastructure (no app config is required for this command)

			buildInfo := application.ReadBuildInfo()

			switch format {
			case "text":
				fmt.Println("Application:       ", application.Name)
				fmt.Println("Version:           ", buildInfo.Version)
				fmt.Println("BuildDate:         ", buildInfo.BuildDate)
				fmt.Println("GitCommit:         ", buildInfo.GitCommit)
				fmt.Println("GitDescription:    ", buildInfo.GitDescription)
				fmt.Println("Platform:          ", buildInfo.Platform)
				fmt.Println("GoVersion:         ", buildInfo.GoVersion)
				fmt.Println("Compiler:          ", buildInfo.Compiler)

			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetEscapeHTML(false)
				enc.SetIndent("", " ")
				err := enc.Encode(&struct {
					application.BuildInfo
					Application string `json:"application"`
				}{
					BuildInfo:   buildInfo,
					Application: application.Name,
				})
				if err != nil {
					return fmt.Errorf("failed to show version information: %w", err)
				}
			default:
				return fmt.Errorf("unsupported output format: %s", format)
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&format, "output", "o", "text", "the format to show the results (allowable: [text json])")

	commonConfiguration(nil, cmd, nil)

	return cmd
}
