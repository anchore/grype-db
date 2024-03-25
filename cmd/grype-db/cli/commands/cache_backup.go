package commands

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/anchore/grype-db/pkg/provider"
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
		RunE: func(cmd *cobra.Command, args []string) error {
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
	if len(cfg.Provider.Selection.IncludeFilter) > 0 {
		providers = fmt.Sprintf("%s", cfg.Provider.Selection.IncludeFilter)
	}
	log.WithFields("providers", providers).Info("backing up provider state")

	archive, err := os.Create(cfg.CacheArchive.Path)
	if err != nil {
		return err
	}

	gw := gzip.NewWriter(archive)
	defer func(gw *gzip.Writer) {
		if err := gw.Close(); err != nil {
			log.Errorf("unable to close gzip writer: %w", err)
		}
	}(gw)
	tw := tar.NewWriter(gw)
	defer func(tw *tar.Writer) {
		if err := tw.Close(); err != nil {
			log.Errorf("unable to close tar writer: %w", err)
		}
	}(tw)

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
		if err := archiveProvider(cfg, cfg.Provider.Root, name, tw); err != nil {
			return err
		}
	}

	log.WithFields("path", cfg.CacheArchive.Path).Info("provider state archived")

	return nil
}

func archiveProvider(cfg cacheBackupConfig, root string, name string, writer *tar.Writer) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	err = os.Chdir(root)
	if err != nil {
		return err
	}
	defer func(dir string) {
		if err := os.Chdir(dir); err != nil {
			log.Errorf("unable to restore directory: %w", err)
		}
	}(wd)

	return filepath.Walk(name,
		func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}
			if cfg.Results.ResultsOnly {
				if strings.Compare(path, name+"/metadata.json") == 0 {
					log.WithFields("file", name+"/metadata.json").Debug("Marking metadata stale")

					// Mark metadata stale
					var state provider.State
					f, err := os.Open(path)
					if err != nil {
						return err
					}
					defer f.Close()

					err = json.NewDecoder(f).Decode(&state)
					if err != nil {
						return err
					}

					state.Stale = true
					// Stream this to the archive
					stateJSON, err := json.MarshalIndent(state, "", "  ")
					if err != nil {
						return err
					}

					return addBytesToArchive(writer, path, stateJSON, info)
				}
				if strings.HasPrefix(path, name+"/input") {
					log.WithFields("path", path).Debug("Skipping input directory")
					return nil
				}
			}

			return addToArchive(writer, path)
		},
	)
}

func addToArchive(writer *tar.Writer, filename string) error {
	log.WithFields("path", filename).Trace("adding to archive")

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}

	// use full path as name (FileInfoHeader only takes the basename)
	// If we don't do this the directory structure would
	// not be preserved
	// https://golang.org/src/archive/tar/common.go?#L626
	header.Name = filename

	err = writer.WriteHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	if err != nil {
		return err
	}

	return nil
}

func addBytesToArchive(writer *tar.Writer, filename string, bytes []byte, info os.FileInfo) error {
	log.WithFields("path", filename).Trace("adding stream to archive")

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}
	header.Name = filename
	header.Size = int64(len(bytes))
	err = writer.WriteHeader(header)
	if err != nil {
		return err
	}

	_, err = writer.Write(bytes)
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}

	return nil
}
