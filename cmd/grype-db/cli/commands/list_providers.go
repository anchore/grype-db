package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/provider/providers"
	"github.com/anchore/grype-db/pkg/provider/providers/vunnel"
)

var _ options.Interface = &listProvidersConfig{}

type listProvidersConfig struct {
	options.Format   `yaml:",inline" mapstructure:",squash"`
	options.Provider `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func (o *listProvidersConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Format, &o.Provider)
}

func (o *listProvidersConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Format, &o.Provider)
}

func ListProviders(app *application.Application) *cobra.Command {
	cfg := listProvidersConfig{
		Provider: options.DefaultProvider(),
		Format: options.Format{
			Output:           "text",
			AllowableFormats: []string{"text", "json"},
		},
	}

	cmd := &cobra.Command{
		Use:   "list-providers",
		Short: "list all configured providers",
		Args: chainArgs(
			cobra.NoArgs,
			func(_ *cobra.Command, _ []string) error {
				allowableOutputs := strset.New(cfg.Format.AllowableFormats...)
				if !allowableOutputs.Has(cfg.Format.Output) {
					return fmt.Errorf("invalid output format: %s (allowable: %s)", cfg.Format.Output, strings.Join(cfg.Format.AllowableFormats, ", "))
				}
				return nil
			},
		),
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return runListProviders(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func runListProviders(cfg listProvidersConfig) error {
	ps, err := providers.New(cfg.Root, vunnel.Config{
		Executor:         cfg.Vunnel.Executor,
		DockerTag:        cfg.Vunnel.DockerTag,
		DockerImage:      cfg.Vunnel.DockerImage,
		GenerateConfigs:  cfg.Vunnel.GenerateConfigs,
		ExcludeProviders: cfg.Vunnel.ExcludeProviders,
		Env:              cfg.Vunnel.Env,
	}, cfg.Provider.Configs...)
	if err != nil {
		if errors.Is(err, providers.ErrNoProviders) {
			log.Error("configure a provider via the application config or use -g to generate a list of configs from vunnel")
		}
		return err
	}

	if cfg.Format.Output == "text" {
		for _, p := range ps {
			fmt.Println(p.ID().Name)
		}
	} else if cfg.Format.Output == "json" {
		names := make([]string, 0, len(ps))
		for _, p := range ps {
			names = append(names, p.ID().Name)
		}
		by, err := json.Marshal(names)
		if err != nil {
			return err
		}
		fmt.Println(string(by))
	}

	return nil
}
