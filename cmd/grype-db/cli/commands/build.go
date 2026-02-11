package commands

import (
	"errors"
	"fmt"
	"os"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/internal/providers"
	"github.com/anchore/grype-db/cmd/grype-db/cli/internal/providers/vunnel"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/db/provider"
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
			if err := validateCPEParts(cfg.IncludeCPEParts); err != nil {
				return err
			}
			return app.Run(cmd.Context(), async(func() error {
				return runBuild(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func validateCPEParts(parts []string) error {
	validParts := strset.New("a", "o", "h")
	for _, part := range parts {
		if !validParts.Has(part) {
			return fmt.Errorf("invalid CPE part: %s", part)
		}
	}
	if len(parts) == 0 {
		return errors.New("no CPE parts provided")
	}
	return nil
}

func runBuild(cfg buildConfig) error {
	// make the db dir if it does not already exist
	if _, err := os.Stat(cfg.Directory); os.IsNotExist(err) {
		if err := os.MkdirAll(cfg.Directory, 0755); err != nil {
			return fmt.Errorf("unable to make db build dir: %w", err)
		}
	}

	pvdrs, err := providers.New(cfg.Root, vunnel.Config{
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
		return fmt.Errorf("unable to create providers: %w", err)
	}

	if len(cfg.IncludeFilter) > 0 {
		log.WithFields("keep-only", cfg.Provider.IncludeFilter).Debug("filtering providers by name")
		pvdrs = pvdrs.Filter(cfg.IncludeFilter...)
	}

	states, err := providerStates(cfg.SkipValidation, pvdrs)
	if err != nil {
		return fmt.Errorf("unable to get provider states: %w", err)
	}

	earliest, err := provider.States(states).EarliestTimestamp()
	if err != nil {
		return fmt.Errorf("unable to get earliest timestamp: %w", err)
	}

	return db.Build(db.BuildConfig{
		SchemaVersion:        cfg.SchemaVersion,
		Directory:            cfg.Directory,
		States:               states,
		Timestamp:            earliest,
		IncludeCPEParts:      cfg.IncludeCPEParts,
		InferNVDFixVersions:  cfg.InferNVDFixVersions,
		Hydrate:              cfg.Hydrate,
		FailOnMissingFixDate: cfg.FailOnMissingFixDate,
		BatchSize:            cfg.BatchSize,
	})
}

func providerStates(skipValidation bool, providers []provider.Reader) ([]provider.State, error) {
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
