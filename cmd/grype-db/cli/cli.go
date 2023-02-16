package cli

import (
	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/commands"
	"github.com/spf13/cobra"
)

type config struct {
	app *application.Application
}

type Option func(*config)

func WithApplication(app *application.Application) Option {
	return func(config *config) {
		config.app = app
	}
}

func New(opts ...Option) *cobra.Command {
	cfg := &config{
		app: application.New(),
	}
	for _, fn := range opts {
		fn(cfg)
	}

	app := cfg.app

	cache := commands.Cache(app)
	cache.AddCommand(commands.CacheListFiles(app))
	cache.AddCommand(commands.CacheStatus(app))
	cache.AddCommand(commands.CacheDelete(app))
	cache.AddCommand(commands.CacheBackup(app))
	cache.AddCommand(commands.CacheRestore(app))

	root := commands.Root(app)
	root.AddCommand(commands.Version(app))
	root.AddCommand(commands.Pull(app))
	root.AddCommand(commands.Build(app))
	root.AddCommand(commands.Package(app))
	root.AddCommand(cache)

	return root
}
