package tar

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Populate creates a gzipped tar from the given paths.
func Populate(tarPath string, filePaths ...string) error {
	f, err := os.Create(tarPath)
	if err != nil {
		return fmt.Errorf("unable to create tar (%s): %w", tarPath, err)
	}
	defer f.Close()

	var compressionWriter io.WriteCloser
	switch {
	case strings.HasSuffix(tarPath, ".tar.gz"):
		compressionWriter = gzip.NewWriter(f)
	case strings.HasSuffix(tarPath, ".tar.zst"):
		// adding zstd.WithWindowSize(zstd.MaxWindowSize), zstd.WithAllLitEntropyCompression(true)
		// will have slightly better results, but use a lot more memory
		compressionWriter, err = zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		if err != nil {
			return fmt.Errorf("unable to get compression stream: %w", err)
		}
	default:
		return fmt.Errorf("archive name has an unsupported suffix: %q", tarPath)
	}

	defer compressionWriter.Close()

	tarWriter := tar.NewWriter(compressionWriter)
	defer tarWriter.Close()

	for _, filePath := range filePaths {
		err := addFileToTarWriter(filePath, tarWriter)
		if err != nil {
			return fmt.Errorf("unable to add file to tar (file='%s'): %w", filePath, err)
		}
	}

	return nil
}

// addFileToTarWriter takes a given filepath and saves the content to the given tar.Writer.
func addFileToTarWriter(filePath string, tarWriter *tar.Writer) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("unable to open file (%s): %w", filePath, err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("unable to get stat for file (%s): %w", filePath, err)
	}

	header := &tar.Header{
		Name:    filePath,
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	err = tarWriter.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("unable to write header for file (%s): %w", filePath, err)
	}

	_, err = io.Copy(tarWriter, f)
	if err != nil {
		return fmt.Errorf("unable to copy data to the tar (file='%s'): %w", filePath, err)
	}

	return nil
}
