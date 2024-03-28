package commands

import (
	"fmt"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/pkg/process"
)

var _ options.Interface = &buildConfig{}

type packageConfig struct {
	options.DBLocation `yaml:"build" json:"build" mapstructure:"build"`
	options.Package    `yaml:"package" json:"package" mapstructure:"package"`
}

func (o *packageConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.DBLocation, &o.Package)
}

func (o *packageConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.DBLocation, &o.Package)
}

func Package(app *application.Application) *cobra.Command {
	cfg := packageConfig{
		DBLocation: options.DefaultDBLocation(),
		Package:    options.DefaultPackage(),
	}

	cmd := &cobra.Command{
		Use:     "package",
		Short:   "package the already built database file into an archive ready for upload and serving",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.OverrideArchiveExtension != "" {
				if !strset.New("tar.gz", "tar.zst").Has(cfg.OverrideArchiveExtension) {
					return fmt.Errorf("archive-extension must be 'tar.gz' or 'tar.zst'")
				}
			}

			return app.Run(cmd.Context(), async(func() error {
				return runPackage(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func runPackage(cfg packageConfig) error {
	return process.Package(cfg.DBLocation.Directory, cfg.PublishBaseURL, cfg.OverrideArchiveExtension)
}
