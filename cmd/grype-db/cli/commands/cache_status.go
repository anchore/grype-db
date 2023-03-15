package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/gookit/color"
	"github.com/spf13/cobra"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/entry"
)

var _ options.Interface = &cacheStatusConfig{}

type cacheStatusConfig struct {
	options.Store `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func CacheStatus(app *application.Application) *cobra.Command {
	cfg := cacheStatusConfig{
		Store: options.DefaultStore(),
	}

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
	providerNames, err := readProviderNamesFromRoot(cfg.Store.Root)
	if err != nil {
		return err
	}

	if len(providerNames) == 0 {
		fmt.Println("no provider state cache found")
		return nil
	}

	var sds []*provider.State
	var errs []error

	for _, name := range providerNames {
		workspace := provider.NewWorkspace(cfg.Store.Root, name)
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
			}
		}

		fmt.Printf("  • %s\n", name)
		statusFmt := color.HiRed
		if isValid {
			fmt.Printf("    ├── results: %d\n", count)
			fmt.Printf("    ├── created: %s\n", sd.Timestamp.Format(time.RFC3339))
			statusFmt = color.HiGreen
		}

		fmt.Printf("    └── status:  %s\n", statusFmt.Sprint(validMsg))
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
