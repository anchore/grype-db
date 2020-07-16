package curation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"time"

	"github.com/anchore/go-version"
	"github.com/anchore/siren-db/internal/file"
	"github.com/spf13/afero"
)

// ListingEntry represents basic metadata about a database archive such as what is in the archive (built/version)
// as well as how to obtain and verify the archive (URL/checksum).
type ListingEntry struct {
	Built    time.Time // RFC 3339
	Version  *version.Version
	URL      *url.URL
	Checksum string
	Type     DatabaseType
}

// ListingEntryJSON is a helper struct for converting a ListingEntry into JSON (or parsing from JSON)
type ListingEntryJSON struct {
	Built    string `json:"built"`
	Version  string `json:"version"`
	URL      string `json:"url"`
	Checksum string `json:"checksum"`
	Type     string `json:"type"`
}

// NewListingEntryFromArchive creates a new ListingEntry based on the metadata from a database flat file.
func NewListingEntryFromArchive(fs afero.Fs, metadata Metadata, dbArchivePath string, baseURL *url.URL) (ListingEntry, error) {
	checksum, err := file.HashFile(fs, dbArchivePath, sha256.New())
	if err != nil {
		return ListingEntry{}, fmt.Errorf("unable to find db archive checksum: %w", err)
	}

	dbArchiveName := filepath.Base(dbArchivePath)
	fileURL, _ := url.Parse(baseURL.String())
	fileURL.Path = path.Join(fileURL.Path, dbArchiveName)
	dbType := ParseDatabaseTypeFromArchivePath(dbArchiveName)
	if dbType == UnknownDbType {
		return ListingEntry{}, fmt.Errorf("unable to determine db type from %q", dbArchiveName)
	}

	return ListingEntry{
		Built:    metadata.Built,
		Version:  metadata.Version,
		URL:      fileURL,
		Checksum: "sha256:" + checksum,
		Type:     dbType,
	}, nil
}

// ToListingEntry converts a ListingEntryJSON to a ListingEntry.
func (l ListingEntryJSON) ToListingEntry() (ListingEntry, error) {
	build, err := time.Parse(time.RFC3339, l.Built)
	if err != nil {
		return ListingEntry{}, fmt.Errorf("cannot convert built time (%s): %+v", l.Built, err)
	}

	ver, err := version.NewVersion(l.Version)
	if err != nil {
		return ListingEntry{}, fmt.Errorf("cannot parse version (%s): %+v", l.Version, err)
	}

	u, err := url.Parse(l.URL)
	if err != nil {
		return ListingEntry{}, fmt.Errorf("cannot parse url (%s): %+v", l.URL, err)
	}

	return ListingEntry{
		Built:    build.UTC(),
		Version:  ver,
		URL:      u,
		Checksum: l.Checksum,
		Type:     DatabaseType(l.Type),
	}, nil
}

func (l *ListingEntry) UnmarshalJSON(data []byte) error {
	var lej ListingEntryJSON
	if err := json.Unmarshal(data, &lej); err != nil {
		return err
	}
	le, err := lej.ToListingEntry()
	if err != nil {
		return err
	}
	*l = le
	return nil
}

func (l *ListingEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ListingEntryJSON{
		Built:    l.Built.Format(time.RFC3339),
		Version:  l.Version.String(),
		Checksum: l.Checksum,
		URL:      l.URL.String(),
		Type:     string(l.Type),
	})
}

func (l ListingEntry) String() string {
	return fmt.Sprintf("Listing(url=%s)", l.URL)
}
