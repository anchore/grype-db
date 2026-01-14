package commands

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/internal/tarutil"
	"github.com/anchore/grype/grype/db/provider"
)

var _ options.Interface = &cacheBackupConfig{}

type cacheBackupConfig struct {
	options.CacheArchive `yaml:"cache" json:"cache" mapstructure:"cache"`
	Provider             struct {
		options.Store     `yaml:",inline" mapstructure:",squash"`
		options.Selection `yaml:",inline" mapstructure:",squash"`
	} `yaml:"provider" json:"provider" mapstructure:"provider"`
	options.Results `yaml:"results" json:"results" mapstructure:"results"`
}

func (o *cacheBackupConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.CacheArchive, &o.Provider.Store, &o.Provider.Selection, &o.Results)
}

func (o *cacheBackupConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := options.Bind(v, "results.results-only", flags.Lookup("results-only")); err != nil {
		return err
	}
	return options.BindAllFlags(flags, v, &o.CacheArchive, &o.Provider.Store, &o.Provider.Selection, &o.Results)
}

func CacheBackup(app *application.Application) *cobra.Command {
	cfg := cacheBackupConfig{
		CacheArchive: options.DefaultCacheArchive(),
	}
	cfg.Provider.Store = options.DefaultStore()
	cfg.Provider.Selection = options.DefaultSelection()
	cfg.Results = options.DefaultResults()

	cmd := &cobra.Command{
		Use:     "backup",
		Short:   "backup provider cache to an archive",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return cacheBackup(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func cacheBackup(cfg cacheBackupConfig) error {
	providers := "all"
	if len(cfg.Provider.IncludeFilter) > 0 {
		providers = fmt.Sprintf("%s", cfg.Provider.IncludeFilter)
	}
	log.WithFields("providers", providers).Info("backing up provider state")

	writer, err := tarutil.NewWriter(cfg.Path)
	if err != nil {
		return fmt.Errorf("unable to create archive writer: %w", err)
	}
	defer writer.Close()

	allowableProviders := strset.New(cfg.Provider.IncludeFilter...)

	providerNames, err := readProviderNamesFromRoot(cfg.Provider.Root)
	if err != nil {
		return err
	}

	for _, name := range providerNames {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(name) {
			log.WithFields("provider", name).Trace("skipping...")
			continue
		}

		log.WithFields("provider", name).Trace("validating provider")
		workspace := provider.NewWorkspace(cfg.Provider.Root, name)
		sd, err := workspace.ReadState()
		if err != nil {
			return fmt.Errorf("unable to read provider %q state: %w", name, err)
		}

		if err := sd.Verify(workspace.Path()); err != nil {
			return fmt.Errorf("provider %q state is invalid: %w", name, err)
		}

		log.WithFields("provider", name).Debug("archiving data")
		if err := archiveProvider(cfg, name, writer); err != nil {
			return err
		}
	}

	log.WithFields("path", cfg.CacheArchive.Path).Info("provider state archived")

	return nil
}

func archiveProvider(cfg cacheBackupConfig, name string, writer tarutil.Writer) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	err = os.Chdir(cfg.Provider.Root)
	if err != nil {
		return err
	}

	defer func(dir string) {
		if err := os.Chdir(dir); err != nil {
			log.Errorf("unable to restore directory: %w", err)
		}
	}(wd)

	var visitor pathVisitor
	if cfg.ResultsOnly {
		log.WithFields("provider", name).Debug("archiving results only")

		visitor = newCacheResultsOnlyWorkspaceVisitStrategy(writer, name)
	} else {
		log.WithFields("provider", name).Debug("archiving full workspace")

		visitor = cacheFullWorkspaceVisitStrategy{
			writer: writer,
		}
	}

	return filepath.Walk(name, visitor.visitPath)
}

type pathVisitor interface {
	visitPath(path string, info fs.FileInfo, err error) error
}

var (
	_ pathVisitor = (*cacheFullWorkspaceVisitStrategy)(nil)
	_ pathVisitor = (*cacheResultsOnlyWorkspaceVisitStrategy)(nil)
)

type cacheFullWorkspaceVisitStrategy struct {
	writer tarutil.Writer
}

func (t cacheFullWorkspaceVisitStrategy) visitPath(p string, info fs.FileInfo, err error) error {
	if err != nil {
		return err
	}

	if info.IsDir() {
		return nil
	}

	return t.writer.WriteEntry(tarutil.NewEntryFromFilePath(p))
}

type cacheResultsOnlyWorkspaceVisitStrategy struct {
	writer       tarutil.Writer
	providerName string
	metadataPath string
	inputPath    string
}

func newCacheResultsOnlyWorkspaceVisitStrategy(writer tarutil.Writer, providerName string) cacheResultsOnlyWorkspaceVisitStrategy {
	return cacheResultsOnlyWorkspaceVisitStrategy{
		writer:       writer,
		providerName: providerName,
		metadataPath: filepath.Join(providerName, "metadata.json"),
		inputPath:    filepath.Join(providerName, "input"),
	}
}

func (t cacheResultsOnlyWorkspaceVisitStrategy) visitPath(p string, info fs.FileInfo, err error) error {
	if err != nil {
		return err
	}

	if info.IsDir() {
		return nil
	}

	switch {
	case strings.HasPrefix(p, t.inputPath):
		// skip input data
		return nil

	case p == t.metadataPath:
		// mark metadata stale

		var state provider.State
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()

		err = json.NewDecoder(f).Decode(&state)
		if err != nil {
			return err
		}

		state.Stale = true

		// stream this to the archive
		stateJSON, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}

		return t.writer.WriteEntry(tarutil.NewEntryFromBytes(stateJSON, p, info))
	}

	return t.writer.WriteEntry(tarutil.NewEntryFromFilePath(p))
}
