package commands

import (
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/pkg/provider"
)

var _ options.Interface = &cacheListFilesConfig{}

type cacheListFilesConfig struct {
	options.Provider `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func CacheListFiles(app *application.Application) *cobra.Command {
	cfg := cacheListFilesConfig{
		Provider: options.DefaultProvider(),
	}

	cmd := &cobra.Command{
		Use:     "list-files",
		Short:   "list the result files for all providers",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return cacheListFiles(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func cacheListFiles(cfg cacheListFilesConfig) error {
	var errs error
	for _, p := range cfg.Provider.Configs {
		workspace := provider.NewWorkspace(cfg.Provider.Root, p.Name)

		sd, err := workspace.ReadState()
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		for _, f := range sd.ResultPaths() {
			fmt.Println(f)
		}
	}
	return errs
}
