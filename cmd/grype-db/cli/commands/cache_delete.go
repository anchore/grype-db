package commands

import (
	"errors"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"os"

	"github.com/anchore/grype-db/internal/log"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/spf13/cobra"
)

var _ options.Interface = &cacheDeleteConfig{}

type cacheDeleteConfig struct {
	options.FilterProviders `yaml:",inline" json:",inline" mapstructure:",squash"`
	options.Provider        `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func (o *cacheDeleteConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Provider, &o.FilterProviders)
}

func (o *cacheDeleteConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Provider, &o.FilterProviders)
}

func CacheDelete(app *application.Application) *cobra.Command {
	cfg := cacheDeleteConfig{
		Provider: options.DefaultProvider(),
	}

	cmd := &cobra.Command{
		Use:     "delete",
		Short:   "delete all provider cache",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return cacheDelete(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func cacheDelete(cfg cacheDeleteConfig) error {
	allowableProviders := strset.New(cfg.FilterProviders.ProviderNames...)

	for _, p := range cfg.Provider.Configs {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(p.Name) {
			log.WithFields("provider", p.Name).Trace("skipping...")
			continue
		}

		if err := deleteProviderCache(cfg.Provider.Root, p); err != nil {
			return err
		}
	}

	if allowableProviders.Size() == 0 {
		log.Info("all provider cache deleted")
	}

	return nil
}

func deleteProviderCache(root string, p provider.Config) error {
	workspace := provider.NewWorkspace(root, p.Name)
	dir := workspace.Path()

	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		log.WithFields("dir", dir).Debug("provider cache does not exist, skipping...")
		return nil
	}

	log.WithFields("dir", dir).Info("deleting provider cache")
	return os.RemoveAll(dir)
}
