package file

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"github.com/spf13/afero"
)

func HashFile(fs afero.Fs, path string, hasher hash.Hash) (string, error) {
	f, err := fs.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file '%s': %w", path, err)
	}
	defer f.Close()

	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("failed to hash file '%s': %w", path, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
