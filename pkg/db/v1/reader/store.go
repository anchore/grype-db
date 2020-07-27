package reader

import (
	"fmt"

	"github.com/alicebob/sqlittle"
	v1 "github.com/anchore/grype-db/pkg/db/v1"
	"github.com/anchore/grype-db/pkg/db/v1/model"
)

// integrity check
var _ v1.StoreReader = &Store{}

// Store holds an instance of the database connection
type Store struct {
	db *sqlittle.DB
}

type CleanupFn func() error

// NewStore creates a new instance of the store
func NewStore(dbFilePath string) (*Store, CleanupFn, error) {
	d, err := Open(&config{
		DbPath:    dbFilePath,
		Overwrite: false,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a new connection to sqlite3 db: %s", err)
	}

	return &Store{
		db: d,
	}, d.Close, nil
}

func (b *Store) GetID() (*v1.ID, error) {
	var scanErr error
	var id v1.ID
	total := 0
	err := b.db.Select(model.IDTableName, func(row sqlittle.Row) {
		total++
		var m model.IDModel

		if scanErr = row.Scan(&m.BuildTimestamp, &m.SchemaVersion); scanErr != nil {
			return
		}

		id = m.Inflate()
	}, "build_timestamp", "schema_version")

	if err != nil {
		return nil, fmt.Errorf("unable to query for ID: %w", err)
	}
	if scanErr != nil {
		return nil, scanErr
	}

	switch {
	case total == 0:
		return nil, nil
	case total > 1:
		return nil, fmt.Errorf("discovered more than one DB ID")
	}

	return &id, nil
}

// Get retrieves one or more vulnerabilities given a namespace and package name
func (b *Store) GetVulnerability(namespace, name string) ([]v1.Vulnerability, error) {
	var vulnerabilities []v1.Vulnerability
	var scanErr error

	err := b.db.IndexedSelectEq(model.VulnerabilityTableName, model.GetVulnerabilityIndexName, sqlittle.Key{name, namespace}, func(row sqlittle.Row) {
		var m model.VulnerabilityModel

		if err := row.Scan(&m.Namespace, &m.PackageName, &m.ID, &m.RecordSource, &m.VersionConstraint, &m.VersionFormat, &m.CPEs, &m.ProxyVulnerabilities); err != nil {
			scanErr = fmt.Errorf("unable to scan over row: %w", err)
			return
		}

		vulnerabilities = append(vulnerabilities, m.Inflate())
	}, "namespace", "package_name", "id", "record_source", "version_constraint", "version_format", "cpes", "proxy_vulnerabilities")
	if err != nil {
		return nil, fmt.Errorf("unable to query: %w", err)
	}
	if scanErr != nil {
		return nil, scanErr
	}

	return vulnerabilities, nil
}

func (b *Store) GetVulnerabilityMetadata(id, recordSource string) (*v1.VulnerabilityMetadata, error) {
	var metadata v1.VulnerabilityMetadata
	var scanErr error
	total := 0

	err := b.db.PKSelect(model.VulnerabilityTableName, sqlittle.Key{id, recordSource}, func(row sqlittle.Row) {
		total++
		var m model.VulnerabilityMetadataModel

		if err := row.Scan(&m.ID, &m.RecordSource, &m.Severity, &m.Links); err != nil {
			scanErr = fmt.Errorf("unable to scan over row: %w", err)
			return
		}

		metadata = m.Inflate()
	}, "namespace", "package_name", "id", "record_source", "version_constraint", "version_format", "cpes", "proxy_vulnerabilities")
	if err != nil {
		return nil, fmt.Errorf("unable to query: %w", err)
	}
	if scanErr != nil {
		return nil, scanErr
	}

	switch {
	case total == 0:
		return nil, nil
	case total > 1:
		return nil, fmt.Errorf("discovered more than one DB metadata record")
	}

	return &metadata, nil
}
