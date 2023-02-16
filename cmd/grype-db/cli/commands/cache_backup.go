package commands

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/internal/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/spf13/cobra"
)

var _ options.Interface = &cacheBackupConfig{}

type cacheBackupConfig struct {
	options.FilterProviders `yaml:",inline" json:",inline" mapstructure:",squash"`
	options.CacheArchive    `yaml:"cache" json:"cache" mapstructure:"cache"`
	options.Provider        `yaml:"provider" json:"provider" mapstructure:"provider"`
}

func (o *cacheBackupConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.CacheArchive, &o.Provider, &o.FilterProviders)
}

func (o *cacheBackupConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.CacheArchive, &o.Provider, &o.FilterProviders)
}

func CacheBackup(app *application.Application) *cobra.Command {
	cfg := cacheBackupConfig{
		CacheArchive: options.DefaultCacheArchive(),
		Provider:     options.DefaultProvider(),
	}

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
	log.WithFields("archive", cfg.CacheArchive.Path).Info("backing up provider cache")

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

	allowableProviders := strset.New(cfg.FilterProviders.ProviderNames...)

	for _, p := range cfg.Provider.Configs {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(p.Name) {
			log.WithFields("provider", p.Name).Trace("skipping...")
			continue
		}
		log.WithFields("provider", p.Name).Debug("backing up cache")
		if err := archiveProvider(cfg.Provider.Root, p, tw); err != nil {
			return err
		}
	}

	log.WithFields("path", cfg.CacheArchive.Path).Info("provider cache archived")

	return nil
}

func archiveProvider(root string, p provider.Config, writer *tar.Writer) error {
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

	return filepath.Walk(p.Name,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			return addToArchive(writer, path)
		},
	)
}

func addToArchive(writer *tar.Writer, filename string) error {
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
