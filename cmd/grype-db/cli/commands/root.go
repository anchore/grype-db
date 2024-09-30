package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/utils"
)

var _ options.Interface = &rootConfig{}

type rootConfig struct {
	options.Provider `yaml:"provider" json:"provider" mapstructure:"provider"`
	options.Pull     `yaml:"pull" json:"pull" mapstructure:"pull"`
	options.Build    `yaml:"build" json:"build" mapstructure:"build"`
	options.Package  `yaml:"package" json:"package" mapstructure:"package"`
}

func (o *rootConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Provider, &o.Build, &o.Pull, &o.Package)
}

func (o *rootConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Provider, &o.Build, &o.Pull, &o.Package)
}

func Root(app *application.Application) *cobra.Command {
	cfg := rootConfig{
		Provider: options.DefaultProvider(),
		Pull:     options.DefaultPull(),
		Build:    options.DefaultBuild(),
		Package:  options.DefaultPackage(),
	}
	appCfg := app.Config

	cmd := &cobra.Command{
		Use:     "",
		Short:   "pull all vulnerability data, build the database, and package it for distribution",
		Version: application.ReadBuildInfo().Version,
		PreRunE: app.Setup(&cfg),
		Example: formatRootExamples(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				if err := runPull(pullConfig{
					Pull:     cfg.Pull,
					Provider: cfg.Provider,
				}); err != nil {
					return err
				}

				if err := runBuild(buildConfig{
					Build:    cfg.Build,
					Provider: cfg.Provider,
				}); err != nil {
					return err
				}

				return runPackage(packageConfig{
					DBLocation: cfg.Build.DBLocation,
					Package:    cfg.Package,
				})
			}))
		},
	}

	commonConfiguration(nil, cmd, &cfg)

	cmd.SetVersionTemplate(fmt.Sprintf("%s {{.Version}}\n", application.Name))

	flags := cmd.PersistentFlags()

	flags.StringVarP(&appCfg.ConfigPath, "config", "c", "", "path to the application config")
	flags.BoolVarP(&appCfg.DryRun, "dry-run", "", false, "parse the application config, CLI flags, and exit.")
	flags.CountVarP(&appCfg.Log.Verbosity, "verbose", "v", "increase verbosity (-v = debug, -vv = trace)")
	flags.BoolVarP(&appCfg.Log.Quiet, "quiet", "q", false, "suppress all logging output")

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
