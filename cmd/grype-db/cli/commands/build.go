package commands

import (
	"fmt"
	"github.com/anchore/grype-db/pkg/provider/providers/vunnel"
	"os"
	"time"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/process"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/providers"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return build(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func build(cfg buildConfig) error {
	// make the db dir if it does not already exist
	if _, err := os.Stat(cfg.Build.Directory); os.IsNotExist(err) {
		if err := os.MkdirAll(cfg.Build.Directory, 0755); err != nil {
			return fmt.Errorf("unable to make db build dir: %w", err)
		}
	}

	pvdrs, err := providers.New(cfg.Provider.Root, vunnel.Config{
		Executor:    cfg.Vunnel.Executor,
		DockerTag:   cfg.Vunnel.DockerTag,
		DockerImage: cfg.Vunnel.DockerImage,
		Env:         cfg.Vunnel.Env,
	}, cfg.Provider.Configs...)
	if err != nil {
		return fmt.Errorf("unable to create providers: %w", err)
	}

	var states []provider.State
	stateTimestamp := time.Now()
	log.Info("reading all provider state")
	for _, p := range pvdrs {
		log.WithFields("provider", p.ID().Name).Debug("reading state")

		sd, err := p.State()
		if err != nil {
			return fmt.Errorf("unable to read provider state: %w", err)
		}

		if !cfg.SkipValidation {
			log.WithFields("provider", p.ID().Name).Trace("validating state")
			if err := sd.Verify(); err != nil {
				return fmt.Errorf("invalid provider state: %w", err)
			}
		}

		if sd.Timestamp.Before(stateTimestamp) {
			stateTimestamp = sd.Timestamp
		}
		states = append(states, *sd)
	}

	if !cfg.SkipValidation {
		log.Debugf("state validated for all providers")
	}

	return process.Build(process.BuildConfig{
		SchemaVersion: cfg.SchemaVersion,
		Directory:     cfg.Directory,
		States:        states,
		Timestamp:     stateTimestamp,
	})
}
