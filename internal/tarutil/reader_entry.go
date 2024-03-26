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

	header, err := tar.FileInfoHeader(t.FileInfo, t.FileInfo.Name())
	if err != nil {
		return err
	}

	contents, err := io.ReadAll(t.Reader)
	if err != nil {
		return err
	}

	header.Name = t.Filename
	header.Size = int64(len(contents))
	err = tw.WriteHeader(header)
	if err != nil {
		return err
	}

	_, err = tw.Write(contents)
	if err != nil {
		return err
	}

	// note: this will ensure that the tar entry is properly aligned in the tar archive (padding with zeros)
	err = tw.Flush()
	if err != nil {
		return err
	}

	return nil
}
