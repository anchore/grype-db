package commands

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/internal/providers"
	"github.com/anchore/grype-db/cmd/grype-db/cli/internal/providers/vunnel"
	"github.com/anchore/grype-db/cmd/grype-db/cli/internal/pull"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype/grype/db/provider"
)

var _ options.Interface = &pullConfig{}

type pullConfig struct {
	options.Pull     `yaml:"pull" json:"pull" mapstructure:"pull"`
	options.Provider `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func (o *pullConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Pull, &o.Provider)
}

func (o *pullConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Pull, &o.Provider)
}

func Pull(app *application.Application) *cobra.Command {
	cfg := pullConfig{
		Pull:     options.DefaultPull(),
		Provider: options.DefaultProvider(),
	}

	cmd := &cobra.Command{
		Use:     "pull",
		Short:   "pull and process all upstream vulnerability data",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return runPull(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func runPull(cfg pullConfig) error {
	ps, err := providers.New(cfg.Root, vunnel.Config{
		Config:           cfg.Vunnel.Config,
		Executor:         cfg.Vunnel.Executor,
		DockerTag:        cfg.Vunnel.DockerTag,
		DockerImage:      cfg.Vunnel.DockerImage,
		GenerateConfigs:  cfg.Vunnel.GenerateConfigs,
		ExcludeProviders: cfg.Vunnel.ExcludeProviders,
		Env:              cfg.Vunnel.Env,
	}, cfg.Configs...)
	if err != nil {
		if errors.Is(err, providers.ErrNoProviders) {
			log.Error("configure a provider via the application config or use -g to generate a list of configs from vunnel")
		}
		return err
	}

	if len(cfg.IncludeFilter) > 0 {
		log.WithFields("keep-only", cfg.Provider.IncludeFilter).Debug("filtering providers by name")
		ps = ps.Filter(cfg.IncludeFilter...)
	}

	c := pull.Config{
		Parallelism: cfg.Parallelism,
		Collection: provider.Collection{
			Root:      cfg.Root,
			Providers: ps,
		},
	}

	return pull.Pull(c)
}
