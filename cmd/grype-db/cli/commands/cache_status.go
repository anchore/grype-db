package commands

import (
	"fmt"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/entry"
)

var _ options.Interface = &cacheStatusConfig{}

type cacheStatusConfig struct {
	options.Provider `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func CacheStatus(app *application.Application) *cobra.Command {
	cfg := cacheStatusConfig{
		Provider: options.DefaultProvider(),
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
	if len(cfg.Provider.Configs) == 0 {
		fmt.Println("no provider state cache found")
		return nil
	}

	var sds []*provider.State
	var errs []error

	allowableProviders := strset.New(cfg.Provider.IncludeFilter...)

	for _, p := range cfg.Provider.Configs {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(p.Name) {
			log.WithFields("provider", p.Name).Trace("skipping...")
			continue
		}

		workspace := provider.NewWorkspace(cfg.Provider.Root, p.Name)
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

	if allowableProviders.Size() == 0 {
		fmt.Printf("providers: %d\n", len(sds))
	}

	for idx, sd := range sds {
		validMsg := "valid"
		if errs[idx] != nil {
			validMsg = fmt.Sprintf("INVALID: %s", errs[idx].Error())
		} else if sd == nil {
			validMsg = "INVALID: no state description found"
		}

		providerIndex := idx + 1

		if sd == nil {
			fmt.Printf("  • provider (%d): %s\n", providerIndex, validMsg)
			continue
		}

		count, err := entry.Count(sd.Store, sd.ResultPaths())
		if err != nil {
			log.WithFields("provider", sd.Provider, "error", err).Error("unable to count entries")
		}

		fmt.Printf("  • %s\n", sd.Provider)
		fmt.Printf("    ├── is valid?     %s\n", validMsg)
		fmt.Printf("    ├── timestamp:    %s\n", sd.Timestamp)
		fmt.Printf("    └── result files: %d\n", count)
	}
	return nil
}
