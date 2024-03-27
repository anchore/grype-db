package tarutil

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
)

var ErrUnsupportedArchiveSuffix = fmt.Errorf("archive name has an unsupported suffix")

var _ Writer = (*writer)(nil)

type writer struct {
	compressor io.WriteCloser
	writer     *tar.Writer
}

// NewWriter creates a new tar writer that writes to the specified archive path. Supports .tar.gz and .tar.zst file extensions.
func NewWriter(archivePath string) (Writer, error) {
	w, err := newCompressor(archivePath)
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(w)

	return &writer{
		compressor: w,
		writer:     tw,
	}, nil
}

func newCompressor(archivePath string) (io.WriteCloser, error) {
	archive, err := os.Create(archivePath)
	if err != nil {
		return nil, err
	}

	switch {
	case strings.HasSuffix(archivePath, ".tar.gz"):
		return gzip.NewWriter(archive), nil
	case strings.HasSuffix(archivePath, ".tar.zst"):
		// adding zstd.WithWindowSize(zstd.MaxWindowSize), zstd.WithAllLitEntropyCompression(true)
		// will have slightly better results, but use a lot more memory
		w, err := zstd.NewWriter(archive, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		if err != nil {
			return nil, fmt.Errorf("unable to get zst compression stream: %w", err)
		}
		return w, nil
	case strings.HasSuffix(archivePath, ".tar"):
		return archive, nil
	}
	return nil, ErrUnsupportedArchiveSuffix
}

func (w *writer) WriteEntry(entry Entry) error {
	return entry.writeEntry(w.writer)
}

func (w *writer) Close() error {
	if w.writer != nil {
		err := w.writer.Close()
		w.writer = nil
		if err != nil {
			return fmt.Errorf("unable to close tar writer: %w", err)
		}
	}

	if w.compressor != nil {
		err := w.compressor.Close()
		w.compressor = nil
		return err
	}

	return nil
}
