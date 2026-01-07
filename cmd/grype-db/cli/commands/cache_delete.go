package commands

import (
	"errors"
	"os"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype/grype/db/provider"
)

var _ options.Interface = &cacheDeleteConfig{}

type cacheDeleteConfig struct {
	Provider struct {
		options.Store     `yaml:",inline" mapstructure:",squash"`
		options.Selection `yaml:",inline" mapstructure:",squash"`
	} `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func (o *cacheDeleteConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Provider.Store, &o.Provider.Selection)
}

func (o *cacheDeleteConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Provider.Store, &o.Provider.Selection)
}

func CacheDelete(app *application.Application) *cobra.Command {
	cfg := cacheDeleteConfig{}
	cfg.Provider.Store = options.DefaultStore()
	cfg.Provider.Selection = options.DefaultSelection()

	cmd := &cobra.Command{
		Use:     "delete",
		Short:   "delete all provider cache",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return cacheDelete(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func cacheDelete(cfg cacheDeleteConfig) error {
	allowableProviders := strset.New(cfg.Provider.IncludeFilter...)

	providerNames, err := readProviderNamesFromRoot(cfg.Provider.Root)
	if err != nil {
		return err
	}

	if len(providerNames) == 0 {
		log.Info("no provider data found to delete")
		return nil
	}

	for _, name := range providerNames {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(name) {
			log.WithFields("provider", name).Trace("skipping...")
			continue
		}

		if err := deleteProviderCache(cfg.Provider.Root, name); err != nil {
			return err
		}
	}

	if allowableProviders.Size() == 0 {
		log.Info("all provider data deleted")
	}

	return nil
}

func deleteProviderCache(root string, name string) error {
	workspace := provider.NewWorkspace(root, name)
	dir := workspace.Path()

	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		log.WithFields("dir", dir).Debug("provider cache does not exist, skipping...")
		return nil
	}

	log.WithFields("dir", dir).Info("deleting provider data")
	return os.RemoveAll(dir)
}
