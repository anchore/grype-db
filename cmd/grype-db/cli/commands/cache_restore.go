package commands

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
)

var _ options.Interface = &cacheRestoreConfig{}

type cacheRestoreConfig struct {
	Cache            cacheRestoreCache `yaml:"cache" json:"cache" mapstructure:"cache"`
	options.Provider `yaml:"provider" json:"provider" mapstructure:"provider"`
}

type cacheRestoreCache struct {
	options.CacheArchive `yaml:",inline" json:"inline" mapstructure:",squash"`
	options.CacheRestore `yaml:"restore" json:"restore" mapstructure:"restore"`
}

func (o *cacheRestoreConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Cache.CacheRestore, &o.Cache.CacheArchive, &o.Provider)
}

func (o *cacheRestoreConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := options.Bind(v, "cache.delete-existing", flags.Lookup("delete-existing")); err != nil {
		return err
	}
	return options.BindAllFlags(flags, v, &o.Cache.CacheRestore, &o.Cache.CacheArchive, &o.Provider)
}

func CacheRestore(app *application.Application) *cobra.Command {
	cfg := cacheRestoreConfig{
		Cache: cacheRestoreCache{
			CacheArchive: options.DefaultCacheArchive(),
			CacheRestore: options.DefaultCacheRestore(),
		},
		Provider: options.DefaultProvider(),
	}

	cmd := &cobra.Command{
		Use:     "restore",
		Short:   "restore provider cache from a backup archive",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return cacheRestore(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func cacheRestore(cfg cacheRestoreConfig) error {
	if err := os.MkdirAll(cfg.Provider.Root, 0755); err != nil {
		return fmt.Errorf("failed to create provider root directory: %w", err)
	}

	if cfg.Cache.DeleteExisting {
		log.Info("deleting existing provider cache")
		for _, p := range cfg.Provider.Configs {
			if err := deleteProviderCache(cfg.Provider.Root, p); err != nil {
				return fmt.Errorf("failed to delete provider cache: %w", err)
			}
		}
	} else {
		for _, p := range cfg.Provider.Configs {
			dir := filepath.Join(cfg.Provider.Root, p.Name)
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				log.WithFields("dir", dir).Debug("note: there is pre-existing provider cache, but it will not be deleted")
			}
		}
	}

	log.WithFields("archive", cfg.Cache.CacheArchive.Path).Info("restoring provider cache from backup")

	f, err := os.Open(cfg.Cache.CacheArchive.Path)
	if err != nil {
		return fmt.Errorf("failed to open cache archive: %w", err)
	}

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

	if err := extractTarGz(f); err != nil {
		return fmt.Errorf("failed to extract cache archive: %w", err)
	}

	log.WithFields("path", cfg.Cache.CacheArchive.Path).Info("provider cache restored")

	return nil
}

func extractTarGz(reader io.Reader) error {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(header.Name, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			parentPath := filepath.Dir(header.Name)
			if parentPath != "" {
				if err := os.MkdirAll(parentPath, 0755); err != nil {
					return fmt.Errorf("failed to create parent directory %q for file %q: %w", parentPath, header.Name, err)
				}
			}

			outFile, err := os.Create(header.Name)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}
			if err := safeCopy(outFile, tr); err != nil {
				return fmt.Errorf("failed to copy file: %w", err)
			}
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("failed to close file: %w", err)
			}

		default:
			log.WithFields("name", header.Name, "type", header.Typeflag).Warn("unknown file type in backup archive")
		}
	}
	return nil
}

const (
	// represents the order of bytes
	_  = iota
	kb = 1 << (10 * iota) //nolint:deadcode
	mb                    //nolint:deadcode
	gb
)

const perFileReadLimit = 10 * gb

// safeCopy limits the copy from the reader. This is useful when extracting files from archives to
// protect against decompression bomb attacks.
func safeCopy(writer io.Writer, reader io.Reader) error {
	numBytes, err := io.Copy(writer, io.LimitReader(reader, perFileReadLimit))
	if numBytes >= perFileReadLimit || errors.Is(err, io.EOF) {
		return fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
	}
	return nil
}
