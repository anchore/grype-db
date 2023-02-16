package tar

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// Populate creates a gzipped tar from the given paths.
func Populate(tarPath string, filePaths ...string) error {
	f, err := os.Create(tarPath)
	if err != nil {
		return fmt.Errorf("unable to create tar (%s): %w", tarPath, err)
	}
	defer f.Close()

	gzipWriter := gzip.NewWriter(f)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
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
