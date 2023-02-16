package file

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/spf13/afero"
)

func ContentDigest(fs afero.Fs, path string, hasher hash.Hash) (string, error) {
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

func ValidateDigest(path, expectedDigest string, hasher hash.Hash) error {
	actual, err := ContentDigest(afero.NewOsFs(), path, hasher)
	if err != nil {
		return fmt.Errorf("failed to hash file %q: %w", path, err)
	}
	if !strings.HasSuffix(expectedDigest, actual) {
		return fmt.Errorf("hash mismatch for file %q: got %q expected %q", path, actual, expectedDigest)
	}
	return nil
}
