package tarutil

import (
	"archive/tar"
	"bytes"
	"io"
	"os"

	"github.com/anchore/grype-db/internal/log"
)

var _ Entry = (*ReaderEntry)(nil)

type ReaderEntry struct {
	Reader   io.Reader
	Filename string
	FileInfo os.FileInfo
}

func NewEntryFromBytes(by []byte, filename string, fileInfo os.FileInfo) Entry {
	return ReaderEntry{
		Reader:   bytes.NewReader(by),
		Filename: filename,
		FileInfo: fileInfo,
	}
}

func (t ReaderEntry) writeEntry(tw lowLevelWriter) error {
	log.WithFields("path", t.Filename).Trace("adding stream to archive")
	return writeEntry(tw, t.Filename, t.FileInfo, func() (io.Reader, error) {
		return t.Reader, nil
	})
}

// getReaderSize determines the size of the reader's content without reading the entire content into memory.
// For known reader types (bytes.Reader, os.File), it queries the size directly.
// For unknown types, it falls back to reading all content into memory.
// Returns the size, a reader for the content (may be different from input), and any error.
func getReaderSize(reader io.Reader) (int64, io.Reader, error) {
	switch r := reader.(type) {
	case *bytes.Reader:
		// For bytes.Reader (used by NewEntryFromBytes), get actual size
		return r.Size(), reader, nil
	case interface{ Stat() (os.FileInfo, error) }:
		// For *os.File, use Stat to get size
		if stat, err := r.Stat(); err == nil {
			return stat.Size(), reader, nil
		}
		// Fallback: this is rare, but for seekable readers we could try other methods
		// For now, keep old behavior for unknown reader types
		contents, err := io.ReadAll(reader)
		if err != nil {
			return 0, nil, err
		}
		return int64(len(contents)), bytes.NewReader(contents), nil
	default:
		// Fallback for unknown reader types: read into memory
		contents, err := io.ReadAll(reader)
		if err != nil {
			return 0, nil, err
		}
		return int64(len(contents)), bytes.NewReader(contents), nil
	}
}

func writeEntry(tw lowLevelWriter, filename string, fileInfo os.FileInfo, opener func() (io.Reader, error)) error {
	log.WithFields("path", filename).Trace("adding file to archive")

	header, err := tar.FileInfoHeader(fileInfo, "")
	if err != nil {
		return err
	}

	header.Name = filename
	switch fileInfo.Mode() & os.ModeType {
	case os.ModeDir:
		header.Size = 0
		err = tw.WriteHeader(header)
		if err != nil {
			return err
		}
		return nil

	case os.ModeSymlink:
		linkTarget, err := os.Readlink(filename)
		if err != nil {
			return err
		}
		header.Linkname = linkTarget
		header.Size = 0
		err = tw.WriteHeader(header)
		if err != nil {
			return err
		}
		return nil

	default:
		reader, err := opener()
		if err != nil {
			return err
		}

		size, reader, err := getReaderSize(reader)
		if err != nil {
			return err
		}

		header.Size = size

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Stream the file contents directly to the tar writer
		if _, err := io.Copy(tw, reader); err != nil {
			return err
		}

		// Close the reader if it implements io.Closer
		if closer, ok := reader.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				return err
			}
		}

		// ensure proper alignment in the tar archive (padding with zeros)
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	return nil
}
