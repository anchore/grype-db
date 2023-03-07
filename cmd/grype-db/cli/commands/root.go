package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/utils"
)

func Root(app *application.Application) *cobra.Command {
	opts := app.Config

	cmd := &cobra.Command{
		Use:     "",
		Version: application.ReadBuildInfo().Version,
		PreRunE: app.Setup(nil),
		Example: formatRootExamples(),
	}

	commonConfiguration(nil, cmd, nil)

	cmd.SetVersionTemplate(fmt.Sprintf("%s {{.Version}}\n", application.Name))

	flags := cmd.PersistentFlags()

	flags.StringVarP(&opts.ConfigPath, "config", "c", "", "path to the application config")
	flags.CountVarP(&opts.Log.Verbosity, "verbose", "v", "increase verbosity (-v = debug, -vv = trace)")
	flags.BoolVarP(&opts.Log.Quiet, "quiet", "q", false, "suppress all logging output")

	return cmd
}

func formatRootExamples() string {
	cfg := application.Config{
		DisableLoadFromDisk: true,
	}
	// best effort to load current or default values
	// intentionally don't read from the environment
	_ = cfg.Load(viper.New())

	cfgString := utils.Indent(options.Summarize(cfg, nil), "  ")
	return fmt.Sprintf(`Application Config:
 (search locations: %+v)
%s`, strings.Join(application.ConfigSearchLocations, ", "), strings.TrimSuffix(cfgString, "\n"))
}
