package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/gookit/color"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
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
		RunE: func(cmd *cobra.Command, args []string) error {
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

	if len(providerNames) == 0 {
		fmt.Println("no provider state cache found")
		return nil
	}

	var sds []*provider.State
	var errs []error

	allowableProviders := strset.New(cfg.Provider.IncludeFilter...)

	for _, name := range providerNames {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(name) {
			log.WithFields("provider", name).Trace("skipping...")
			continue
		}

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
			count, err = entry.Count(sd.Store, sd.ResultPaths())
			if err != nil {
				isValid = false
				validMsg = fmt.Sprintf("INVALID (unable to count entries: %s)", err.Error())
			} else if count <= cfg.minRows {
				isValid = false
				validMsg = fmt.Sprintf("INVALID (data has %d rows, must have more than %d)", count, cfg.minRows)
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

	if !success {
		os.Exit(1)
	}

	return nil
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
