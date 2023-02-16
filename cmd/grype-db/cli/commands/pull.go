package commands

import (
	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/process"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/providers"
	"github.com/anchore/grype-db/pkg/provider/providers/vunnel"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return pull(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func pull(cfg pullConfig) error {
	ps, err := providers.New(cfg.Root, vunnel.Config{
		Executor:    cfg.Vunnel.Executor,
		DockerTag:   cfg.Vunnel.DockerTag,
		DockerImage: cfg.Vunnel.DockerImage,
		Env:         cfg.Vunnel.Env,
	}, cfg.Provider.Configs...)
	if err != nil {
		return err
	}

	if len(cfg.FilterProviders.ProviderNames) > 0 {
		log.WithFields("keep-only", cfg.FilterProviders.ProviderNames).Debug("filtering providers by name")
		ps = ps.Filter(cfg.FilterProviders.ProviderNames...)
	}

	c := process.PullConfig{
		Parallelism: cfg.Parallelism,
		Collection: provider.Collection{
			Root:      cfg.Root,
			Providers: ps,
		},
	}

	return process.Pull(c)
}
