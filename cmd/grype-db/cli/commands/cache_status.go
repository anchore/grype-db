package commands

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/entry"
)

var _ options.Interface = &cacheStatusConfig{}

type cacheStatusConfig struct {
	Provider struct {
		options.Store     `yaml:",inline" mapstructure:",squash"`
		options.Selection `yaml:",inline" mapstructure:",squash"`
	} `yaml:"provider" json:"provider" mapstructure:"provider"`
	minRows int64 `yaml:"min-rows" mapstructure:"min-rows"`
}

func (o *cacheStatusConfig) AddFlags(flags *pflag.FlagSet) {
	flags.Int64VarP(
		&o.minRows,
		"min-rows", "", o.minRows,
		"fail validation unless more than this many rows are present in the provider results",
	)
	options.AddAllFlags(flags, &o.Provider.Store, &o.Provider.Selection)
}

func (o *cacheStatusConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Provider.Store, &o.Provider.Selection)
}

func CacheStatus(app *application.Application) *cobra.Command {
	cfg := cacheStatusConfig{}
	cfg.Provider.Store = options.DefaultStore()
	cfg.Provider.Selection = options.DefaultSelection()

	cmd := &cobra.Command{
		Use:     "status",
		Short:   "verify the status of the existing provider cache",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return cacheStatus(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func cacheStatus(cfg cacheStatusConfig) error {
	providerNames, err := readProviderNamesFromRoot(cfg.Provider.Root)
	if err != nil {
		return err
	}

	providerNames, missingProvidersErr := validateRequestedProviders(providerNames, cfg.Provider.IncludeFilter)

	var sds []*provider.State
	var errs []error

	for _, name := range providerNames {
		workspace := provider.NewWorkspace(cfg.Provider.Root, name)
		sd, err := workspace.ReadState()
		if err != nil {
			sds = append(sds, nil)
			errs = append(errs, err)
			continue
		}

		if err := sd.Verify(workspace.Path()); err != nil {
			sds = append(sds, nil)
			errs = append(errs, err)
			continue
		}

		errs = append(errs, nil)
		sds = append(sds, sd)
	}

	success := true

	for idx, sd := range sds {
		validMsg := "valid"
		isValid := true
		if errs[idx] != nil {
			validMsg = fmt.Sprintf("INVALID (%s)", errs[idx].Error())
			isValid = false
		} else if sd == nil {
			validMsg = "INVALID (no state description found)"
			isValid = false
		}

		var count int64
		name := providerNames[idx]

		if sd != nil {
			name = sd.Provider
			counter := func() (int64, error) {
				return entry.Count(sd.Store, sd.ResultPaths())
			}
			count, err = validateCount(cfg, counter)
			if err != nil {
				isValid = false
				validMsg = fmt.Sprintf("INVALID (%s)", err.Error())
			}
		}

		success = success && isValid

		fmt.Printf("  • %s\n", name)
		statusFmt := color.HiRed
		if isValid {
			fmt.Printf("    ├── results: %d\n", count)
			fmt.Printf("    ├── created: %s\n", sd.Timestamp.Format(time.RFC3339))
			statusFmt = color.HiGreen
		}

		fmt.Printf("    └── status:  %s\n", statusFmt.Sprint(validMsg))
	}

	if missingProvidersErr != nil {
		success = false
		fmt.Printf("INVALID (%s)\n", missingProvidersErr.Error())
	}

	if !success {
		os.Exit(1)
	}

	return nil
}

func validateCount(cfg cacheStatusConfig, counter func() (int64, error)) (int64, error) {
	count, err := counter()
	if err != nil {
		return 0, fmt.Errorf("unable to count entries: %w", err)
	}
	if count <= cfg.minRows {
		return 0, fmt.Errorf("data has %d rows, must have more than %d", count, cfg.minRows)
	}
	return count, nil
}

// validateRequestedProviders takes the set of providers found on disk, and the set of providers
// requested at the command line. It returns the subset of providers on disk that were requested.
// If providers were requested that are not present on disk, it returns an error.
// If no providers are explicitly requested, it returns the entire set.
func validateRequestedProviders(providersOnDisk []string, requestedProviders []string) ([]string, error) {
	if len(requestedProviders) == 0 {
		return providersOnDisk, nil
	}
	var result []string
	requestedSet := strset.New(requestedProviders...)
	for _, p := range providersOnDisk {
		if requestedSet.Has(p) {
			result = append(result, p)
			requestedSet.Remove(p)
		}
	}
	if requestedSet.Size() > 0 {
		return nil, fmt.Errorf("providers requested but not present on disk: %s", strings.Join(requestedSet.List(), ", "))
	}
	return result, nil
}

func readProviderNamesFromRoot(root string) ([]string, error) {
	// list all the directories in "root"
	listing, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	var providers []string
	for _, f := range listing {
		if !f.IsDir() {
			continue
		}
		providers = append(providers, f.Name())
	}
	return providers, nil
}
