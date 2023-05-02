package process

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spf13/afero"

	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/internal/tar"
	"github.com/anchore/grype/grype/db"
)

func randomString() (string, error) {
	b := make([]byte, 10)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

func Package(dbDir, publishBaseURL, overrideArchiveExtension string) error {
	log.WithFields("from", dbDir, "url", publishBaseURL, "extension-override", overrideArchiveExtension).Info("packaging database")

	fs := afero.NewOsFs()
	metadata, err := db.NewMetadataFromDir(fs, dbDir)
	if err != nil {
		return err
	}

	if metadata == nil {
		return fmt.Errorf("no metadata found in %q", dbDir)
	}

	u, err := url.Parse(publishBaseURL)
	if err != nil {
		return err
	}

	trailer, err := randomString()
	if err != nil {
		return fmt.Errorf("unable to create random archive trailer: %w", err)
	}

	// TODO (alex): supporting tar.zst
	// var extension = "tar.zst"
	var extension = "tar.gz"

	if overrideArchiveExtension != "" {
		extension = strings.TrimLeft(overrideArchiveExtension, ".")
	}
	// TODO (alex): supporting tar.zst
	// else if metadata.Version < 5 {
	// 	extension = "tar.gz"
	// }

	var found bool
	for _, valid := range []string{"tar.zst", "tar.gz"} {
		if valid == extension {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("invalid archive extension %q", extension)
	}

	// we attach a random value at the end of the file name to prevent from overwriting DBs in S3 that are already
	// cached in the CDN. Ideally this would be based off of the archive checksum but a random string is simpler.
	tarName := fmt.Sprintf(
		"vulnerability-db_v%d_%s_%s.%s",
		metadata.Version,
		metadata.Built.Format(time.RFC3339),
		trailer,
		extension,
	)
	tarPath := path.Join(dbDir, tarName)

	if err := populate(tarName, dbDir); err != nil {
		return err
	}

	log.WithFields("path", tarPath).Info("created database archive")

	entry, err := db.NewListingEntryFromArchive(fs, *metadata, tarPath, u)
	if err != nil {
		return fmt.Errorf("unable to create listing entry from archive: %w", err)
	}

	listing := db.NewListing(entry)
	listingPath := path.Join(dbDir, db.ListingFileName)
	if err = listing.Write(listingPath); err != nil {
		return err
	}

	log.WithFields("path", listingPath).Debug("created initial listing file")

	return nil
}

func populate(tarName, dbDir string) error {
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("unable to get CWD: %w", err)
	}

	if err = os.Chdir(dbDir); err != nil {
		return fmt.Errorf("unable to cd to build dir: %w", err)
	}

	defer func() {
		if err = os.Chdir(originalDir); err != nil {
			log.Errorf("unable to cd to original dir: %w", err)
		}
	}()

	fileInfos, err := os.ReadDir("./")
	if err != nil {
		return fmt.Errorf("unable to list db directory: %w", err)
	}

	var files []string
	for _, fi := range fileInfos {
		if fi.Name() != "listing.json" && !strings.Contains(fi.Name(), ".tar.") {
			files = append(files, fi.Name())
		}
	}

	if err = tar.Populate(tarName, files...); err != nil {
		return fmt.Errorf("unable to create db archive: %w", err)
	}

	return nil
}
