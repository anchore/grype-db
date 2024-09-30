package commands

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/process"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/providers"
	"github.com/anchore/grype-db/pkg/provider/providers/vunnel"
)

var _ options.Interface = &buildConfig{}

type buildConfig struct {
	options.Build    `yaml:"build" json:"build" mapstructure:"build"`
	options.Provider `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func (o *buildConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Build, &o.Provider)
}

func (o *buildConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Build, &o.Provider)
}

func Build(app *application.Application) *cobra.Command {
	cfg := buildConfig{
		Build:    options.DefaultBuild(),
		Provider: options.DefaultProvider(),
	}

	cmd := &cobra.Command{
		Use:     "build",
		Short:   "build a SQLite DB from the vulnerability feeds data for a particular schema version",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return runBuild(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func runBuild(cfg buildConfig) error {
	// make the db dir if it does not already exist
	if _, err := os.Stat(cfg.Build.Directory); os.IsNotExist(err) {
		if err := os.MkdirAll(cfg.Build.Directory, 0755); err != nil {
			return fmt.Errorf("unable to make db build dir: %w", err)
		}
	}

	pvdrs, err := providers.New(cfg.Provider.Root, vunnel.Config{
		Config:           cfg.Vunnel.Config,
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
		return fmt.Errorf("unable to create providers: %w", err)
	}

	if len(cfg.Provider.IncludeFilter) > 0 {
		log.WithFields("keep-only", cfg.Provider.IncludeFilter).Debug("filtering providers by name")
		pvdrs = pvdrs.Filter(cfg.Provider.IncludeFilter...)
	}

	states, err := providerStates(cfg.SkipValidation, pvdrs)
	if err != nil {
		return fmt.Errorf("unable to get provider states: %w", err)
	}

	return process.Build(process.BuildConfig{
		SchemaVersion: cfg.SchemaVersion,
		Directory:     cfg.Directory,
		States:        states,
		Timestamp:     earliestTimestamp(states),
	})
}

func providerStates(skipValidation bool, providers []provider.Provider) ([]provider.State, error) {
	var states []provider.State
	log.Debug("reading all provider state")

	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}

	for _, p := range providers {
		log.WithFields("provider", p.ID().Name).Debug("reading state")

		sd, err := p.State()
		if err != nil {
			return nil, fmt.Errorf("unable to read provider state: %w", err)
		}

		if !skipValidation {
			log.WithFields("provider", p.ID().Name).Trace("validating state")
			if err := sd.Verify(); err != nil {
				return nil, fmt.Errorf("invalid provider state: %w", err)
			}
		}
		states = append(states, *sd)
	}
	if !skipValidation {
		log.Debugf("state validated for all providers")
	}
	return states, nil
}

func earliestTimestamp(states []provider.State) time.Time {
	earliest := states[0].Timestamp
	for _, s := range states {
		if s.Timestamp.Before(earliest) {
			earliest = s.Timestamp
		}
	}
	return earliest
}
