package commands

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype/grype/db"
)

var _ options.Interface = &cacheBackupConfig{}

type cacheBackupConfig struct {
	options.CacheArchive `yaml:"cache" json:"cache" mapstructure:"cache"`
	Provider             struct {
		options.Store     `yaml:",inline" mapstructure:",squash"`
		options.Selection `yaml:",inline" mapstructure:",squash"`
	} `yaml:"provider" json:"provider" mapstructure:"provider"`
	options.Results `yaml:"results" json:"results" mapstructure:"results"`
}

func (o *cacheBackupConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.CacheArchive, &o.Provider.Store, &o.Provider.Selection, &o.Results)
}

func (o *cacheBackupConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := options.Bind(v, "results.results-only", flags.Lookup("results-only")); err != nil {
		return err
	}
	return options.BindAllFlags(flags, v, &o.CacheArchive, &o.Provider.Store, &o.Provider.Selection, &o.Results)
}

func CacheBackup(app *application.Application) *cobra.Command {
	cfg := cacheBackupConfig{
		CacheArchive: options.DefaultCacheArchive(),
	}
	cfg.Provider.Store = options.DefaultStore()
	cfg.Provider.Selection = options.DefaultSelection()
	cfg.Results = options.DefaultResults()

	cmd := &cobra.Command{
		Use:     "backup",
		Short:   "backup provider cache to an archive",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return db.CacheBackup(
					db.CacheBackupConfig{
						ArchivePath:           cfg.CacheArchive.Path,
						ProviderRoot:          cfg.Provider.Root,
						ProviderIncludeFilter: cfg.Provider.IncludeFilter,
						ResultsOnly:           cfg.Results.ResultsOnly,
					},
				)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}
