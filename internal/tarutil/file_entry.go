package tarutil

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
)

var _ Entry = (*FileEntry)(nil)

type FileEntry struct {
	Path string
}

func NewEntryFromFilePath(path string) Entry {
	return FileEntry{
		Path: path,
	}
}

func NewEntryFromFilePaths(paths ...string) []Entry {
	var entries []Entry
	for _, path := range paths {
		entries = append(entries, NewEntryFromFilePath(path))
	}
	return entries
}

func (t FileEntry) writeEntry(tw lowLevelWriter) error {
	filePath := t.Path
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

	err = tw.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("unable to write header for file (%s): %w", filePath, err)
	}

	_, err = io.Copy(tw, f)
	if err != nil {
		return fmt.Errorf("unable to copy data to the tar (file='%s'): %w", filePath, err)
	}

	return nil
}
