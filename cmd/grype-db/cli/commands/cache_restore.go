package commands

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/grype-db/cmd/grype-db/application"
	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/internal/log"
)

var _ options.Interface = &cacheRestoreConfig{}

type cacheRestoreConfig struct {
	Cache    cacheRestoreCache `yaml:"cache" json:"cache" mapstructure:"cache"`
	Provider struct {
		options.Store     `yaml:",inline" mapstructure:",squash"`
		options.Selection `yaml:",inline" mapstructure:",squash"`
	} `yaml:"provider" json:"provider" mapstructure:"provider"`
}

type cacheRestoreCache struct {
	options.CacheArchive `yaml:",inline" json:"inline" mapstructure:",squash"`
	options.CacheRestore `yaml:"restore" json:"restore" mapstructure:"restore"`
}

func (o *cacheRestoreConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Cache.CacheRestore, &o.Cache.CacheArchive, &o.Provider.Store, &o.Provider.Selection)
}

func (o *cacheRestoreConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := options.Bind(v, "cache.delete-existing", flags.Lookup("delete-existing")); err != nil {
		return err
	}
	return options.BindAllFlags(flags, v, &o.Cache.CacheRestore, &o.Cache.CacheArchive, &o.Provider.Store, &o.Provider.Selection)
}

func CacheRestore(app *application.Application) *cobra.Command {
	cfg := cacheRestoreConfig{
		Cache: cacheRestoreCache{
			CacheArchive: options.DefaultCacheArchive(),
			CacheRestore: options.DefaultCacheRestore(),
		},
	}

	cfg.Provider.Store = options.DefaultStore()
	cfg.Provider.Selection = options.DefaultSelection()

	cmd := &cobra.Command{
		Use:     "restore",
		Short:   "restore provider cache from a backup archive",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(&cfg),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return cacheRestore(cfg)
			}))
		},
	}

	commonConfiguration(app, cmd, &cfg)

	return cmd
}

func cacheRestore(cfg cacheRestoreConfig) error {
	providers := "all"
	if len(cfg.Provider.IncludeFilter) > 0 {
		providers = fmt.Sprintf("%s", cfg.Provider.IncludeFilter)
	}
	log.WithFields("providers", providers).Info("restoring provider state")

	if err := os.MkdirAll(cfg.Provider.Root, 0755); err != nil {
		return fmt.Errorf("failed to create provider root directory: %w", err)
	}

	allowableProviders := strset.New(cfg.Provider.IncludeFilter...)
	restorableProviders, err := readProviderNamesFromTarGz(cfg.Cache.Path)
	if err != nil {
		return err
	}

	selectedProviders := strset.New()

	for _, name := range restorableProviders {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(name) {
			log.WithFields("provider", name).Trace("skipping...")
			continue
		}

		selectedProviders.Add(name)

		if cfg.Cache.DeleteExisting {
			log.WithFields("provider", name).Info("deleting existing provider data")
			if err := deleteProviderCache(cfg.Provider.Root, name); err != nil {
				return fmt.Errorf("failed to delete provider cache: %w", err)
			}
		} else {
			dir := filepath.Join(cfg.Provider.Root, name)
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				log.WithFields("provider", name, "dir", dir).Debug("note: there is pre-existing provider data which could be overwritten by the restore operation")
			}
		}
	}

	log.WithFields("archive", cfg.Cache.CacheArchive.Path).Info("restoring provider data from backup")

	f, err := os.Open(cfg.Cache.Path)
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

	maxFileSize, err := parseSize(cfg.Cache.CacheRestore.MaxFileSize)
	if err != nil {
		return fmt.Errorf("invalid max-file-size: %w", err)
	}

	if err := extractTarGz(f, selectedProviders, maxFileSize); err != nil {
		return fmt.Errorf("failed to extract cache archive: %w", err)
	}

	log.WithFields("path", cfg.Cache.CacheArchive.Path).Info("provider data restored")

	return nil
}

func getProviderNameFromPath(path string) string {
	pathComponents := strings.Split(filepath.Clean(path), string(os.PathSeparator))

	if len(pathComponents) > 0 {
		return pathComponents[0]
	}

	return ""
}

func readProviderNamesFromTarGz(tarPath string) ([]string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache archive: %w", err)
	}

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}

	providers := strset.New()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		provider := getProviderNameFromPath(header.Name)

		if provider != "" {
			providers.Add(provider)
		}
	}

	f.Close()

	return providers.List(), nil
}

func extractTarGz(reader io.Reader, selectedProviders *strset.Set, maxFileSize int64) error {
	gr, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}

	tr := tar.NewReader(gr)

	rootPath, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	rootPath, err = filepath.Abs(rootPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	var restoredAny bool
	fs := afero.NewOsFs()
	for {
		header, err := tr.Next()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		provider := getProviderNameFromPath(header.Name)
		if !selectedProviders.Has(provider) {
			log.WithFields("path", header.Name, "provider", provider).Trace("skipping...")
			continue
		}

		restoredAny = true

		if err := processTarHeader(fs, rootPath, header, tr, maxFileSize); err != nil {
			return err
		}
	}

	if !restoredAny {
		return fmt.Errorf("no provider data was restored")
	}
	return nil
}

func processTarHeader(fs afero.Fs, rootPath string, header *tar.Header, reader io.Reader, maxFileSize int64) error {
	// clean the path to avoid traversal (removes "..", ".", etc.)
	cleanedPath := cleanPathRelativeToRoot(rootPath, header.Name)

	if err := detectPathTraversal(rootPath, cleanedPath); err != nil {
		return err
	}

	log.WithFields("path", cleanedPath).Trace("extracting file")

	switch header.Typeflag {
	case tar.TypeDir:
		if err := fs.Mkdir(cleanedPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	case tar.TypeSymlink:
		if err := handleSymlink(fs, rootPath, cleanedPath, header.Linkname); err != nil {
			return fmt.Errorf("failed to create symlink: %w", err)
		}
	case tar.TypeReg:
		if err := handleFile(fs, cleanedPath, reader, maxFileSize); err != nil {
			return fmt.Errorf("failed to handle file: %w", err)
		}
	default:
		log.WithFields("name", cleanedPath, "type", header.Typeflag).Warn("unknown file type in backup archive")
	}
	return nil
}

func handleFile(fs afero.Fs, cleanedPath string, reader io.Reader, maxFileSize int64) error {
	if cleanedPath == "" {
		return fmt.Errorf("empty path")
	}

	parentPath := filepath.Dir(cleanedPath)
	if parentPath != "" {
		if err := fs.MkdirAll(parentPath, 0755); err != nil {
			return fmt.Errorf("failed to create parent directory %q for file %q: %w", parentPath, cleanedPath, err)
		}
	}

	outFile, err := fs.Create(cleanedPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	bytesWritten, err := safeCopy(outFile, reader, maxFileSize, cleanedPath)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	// Log size info for monitoring
	logFileSizeInfo(cleanedPath, bytesWritten, maxFileSize)

	return nil
}

func handleSymlink(fs afero.Fs, rootPath, cleanedPath, linkName string) error {
	if err := detectLinkTraversal(rootPath, cleanedPath, linkName); err != nil {
		return err
	}

	linkReader, ok := fs.(afero.LinkReader)
	if !ok {
		return afero.ErrNoReadlink
	}

	// check if the symlink already exists and is pointing to the correct target
	if linkTarget, err := linkReader.ReadlinkIfPossible(cleanedPath); err == nil {
		if linkTarget == linkName {
			return nil
		}

		if err := fs.Remove(cleanedPath); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	linker, ok := fs.(afero.Linker)
	if !ok {
		return afero.ErrNoSymlink
	}

	if err := linker.SymlinkIfPossible(linkName, cleanedPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}
	return nil
}

func cleanPathRelativeToRoot(rootPath, path string) string {
	return filepath.Join(rootPath, filepath.Clean(path))
}

func detectLinkTraversal(rootPath, cleanedPath, linkTarget string) error {
	linkTarget = filepath.Clean(linkTarget)
	if filepath.IsAbs(linkTarget) {
		return detectPathTraversal(rootPath, linkTarget)
	}

	linkTarget = filepath.Join(filepath.Dir(cleanedPath), linkTarget)

	if !strings.HasPrefix(linkTarget, rootPath) {
		return fmt.Errorf("symlink points outside root: %s -> %s", cleanedPath, linkTarget)
	}
	return nil
}

func detectPathTraversal(rootPath, cleanedPath string) error {
	if cleanedPath == "" {
		return nil
	}

	if !strings.HasPrefix(cleanedPath, rootPath) {
		return fmt.Errorf("path traversal detected: %s", cleanedPath)
	}
	return nil
}

const (
	// represents the order of bytes
	_  = iota
	kb = 1 << (10 * iota) //nolint:deadcode
	mb                    //nolint:deadcode
	gb
	tb
)

// parseSize parses a human-readable size string (e.g., "25GB", "1TB") into bytes
func parseSize(size string) (int64, error) {
	if size == "" {
		return 25 * gb, nil // default to 25GB for backwards compatibility
	}

	size = strings.ToUpper(strings.TrimSpace(size))

	var multiplier int64
	var suffix string

	if strings.HasSuffix(size, "TB") {
		multiplier = tb
		suffix = "TB"
	} else if strings.HasSuffix(size, "GB") {
		multiplier = gb
		suffix = "GB"
	} else if strings.HasSuffix(size, "MB") {
		multiplier = mb
		suffix = "MB"
	} else if strings.HasSuffix(size, "KB") {
		multiplier = kb
		suffix = "KB"
	} else {
		return 0, fmt.Errorf("size must end with KB, MB, GB, or TB (got: %s)", size)
	}

	numStr := strings.TrimSuffix(size, suffix)
	numStr = strings.TrimSpace(numStr)

	var num int64
	_, err := fmt.Sscanf(numStr, "%d", &num)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %w", err)
	}

	if num <= 0 {
		return 0, fmt.Errorf("size must be positive (got: %d)", num)
	}

	return num * multiplier, nil
}

// logFileSizeInfo logs information about file sizes for monitoring purposes
func logFileSizeInfo(path string, size int64, maxSize int64) {
	// Calculate percentage of limit used
	percentUsed := float64(size) / float64(maxSize) * 100

	// Log at different levels based on how close we are to the limit
	switch {
	case percentUsed >= 90:
		log.WithFields("path", path, "size_bytes", size, "max_bytes", maxSize, "percent_used", fmt.Sprintf("%.1f%%", percentUsed)).
			Error("file size is dangerously close to extraction limit - consider increasing max-file-size")
	case percentUsed >= 80:
		log.WithFields("path", path, "size_bytes", size, "max_bytes", maxSize, "percent_used", fmt.Sprintf("%.1f%%", percentUsed)).
			Warn("file size is approaching extraction limit - monitor for future increases")
	case percentUsed >= 50:
		log.WithFields("path", path, "size_bytes", size, "max_bytes", maxSize, "percent_used", fmt.Sprintf("%.1f%%", percentUsed)).
			Info("large file extracted")
	default:
		log.WithFields("path", path, "size_bytes", size).Trace("file extracted")
	}
}

// safeCopy limits the copy from the reader. This is useful when extracting files from archives to
// protect against decompression bomb attacks. Returns the number of bytes written.
func safeCopy(writer io.Writer, reader io.Reader, maxFileSize int64, path string) (int64, error) {
	numBytes, err := io.Copy(writer, io.LimitReader(reader, maxFileSize))
	if numBytes >= maxFileSize || errors.Is(err, io.EOF) {
		return numBytes, fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
	}
	return numBytes, nil
}
