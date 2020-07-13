package curation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/anchore/go-version"
	"github.com/anchore/siren-db/internal/log"
	"github.com/spf13/afero"
)

const ListingFileName = "listing.json"

// Listing represents the json file which is served up and made available for applications to download and
// consume one or more vulnerability db flat files.
type Listing struct {
	Latest    ListingEntry   `json:"latest"`
	Available []ListingEntry `json:"available"`
}

// NewListing creates a listing from one or more given ListingEntries.
func NewListing(entries ...ListingEntry) Listing {
	listing := Listing{
		Available: make([]ListingEntry, 0),
	}
	for idx, entry := range entries {
		if idx == 0 {
			listing.Latest = entry
			continue
		}
		listing.Available = append(listing.Available, entry)
	}
	return listing
}

// NewListingFromFile loads a Listing from a given filepath.
func NewListingFromFile(fs afero.Fs, path string) (Listing, error) {
	f, err := fs.Open(path)
	if err != nil {
		return Listing{}, fmt.Errorf("unable to open DB listing path: %w", err)
	}
	defer f.Close()

	var l Listing
	err = json.NewDecoder(f).Decode(&l)
	if err != nil {
		return Listing{}, fmt.Errorf("unable to parse DB listing: %w", err)
	}
	return l, nil
}

// NewListingFromURL loads a Listing from a URL.
func NewListingFromURL(fs afero.Fs, getter FileGetter, listingURL string) (Listing, error) {
	tempFile, err := afero.TempFile(fs, "", "siren-db-listing")
	if err != nil {
		return Listing{}, fmt.Errorf("unable to create listing temp file: %w", err)
	}
	defer func() {
		err := fs.RemoveAll(tempFile.Name())
		if err != nil {
			log.Errorf("failed to remove file (%s): %w", tempFile.Name(), err)
		}
	}()

	// download the listing file
	err = getter.GetFile(tempFile.Name(), listingURL)
	if err != nil {
		return Listing{}, fmt.Errorf("unable to download listing: %w", err)
	}

	// parse the listing file
	listing, err := NewListingFromFile(fs, tempFile.Name())
	if err != nil {
		return Listing{}, err
	}
	return listing, nil
}

// BestUpdate returns the ListingEntry from a Listing that meets the given version constraints.
func (l *Listing) BestUpdate(constraint version.Constraints) *ListingEntry {
	// extract the latest available db
	candidates := []ListingEntry{l.Latest}
	candidates = append(candidates, l.Available...)

	// TODO: sort candidates by version and built date

	for _, candidate := range candidates {
		log.Debugf("found update: %s", candidate)
	}

	var updateEntry *ListingEntry
	for _, candidate := range candidates {
		if constraint.Check(candidate.Version) {
			copy := candidate
			updateEntry = &copy
			break
		}
	}

	return updateEntry
}

// Write the current listing to the given filepath.
func (l Listing) Write(toPath string) error {
	contents, err := json.MarshalIndent(&l, "", " ")
	if err != nil {
		return fmt.Errorf("failed to encode listing file: %w", err)
	}

	err = ioutil.WriteFile(toPath, contents, 0600)
	if err != nil {
		return fmt.Errorf("failed to write listing file: %w", err)
	}
	return nil
}
