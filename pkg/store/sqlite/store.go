package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anchore/go-version"
	"github.com/anchore/siren-db/internal/log"
	"github.com/anchore/siren-db/pkg/db"
)

// integrity check
var _ db.Store = &Store{}

// Store holds an instance of the database connection
type Store struct {
	db *sql.DB
}

type CleanupFn func() error

// NewStore creates a new instance of the store
func NewStore(options *Options) (*Store, CleanupFn, error) {
	d, err := Open(options)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a new connection to sqlite3 db: %s", err)
	}

	// When a new instance is created, ensure that the table exists
	initStatements := []string{
		// Vulnerabilities table
		`CREATE TABLE IF NOT EXISTS vulns(
		id INTEGER PRIMARY KEY,
		cve_id,
		description,
		epochless_version,
		name,
		namespace_name,
		severity,
		version,
		version_format,
		cpes);`,

		// index to optimize GetVulnerability()
		`CREATE INDEX IF NOT EXISTS vuln_name_namespace_index ON vulns (namespace_name, name);`,

		// ID table, restricting the primary key to a single value to enforce a single ID row
		`CREATE TABLE IF NOT EXISTS id(id INTEGER PRIMARY KEY CHECK (id = 0), build_timestamp, schema_version);`,

		// performance improvements (note: will result in lost data on interruption).
		// on my box it reduces the time to write from 10 minutes to 10 seconds (with ~1GB memory utilization spikes)
		`PRAGMA synchronous = OFF`,
		`PRAGMA journal_mode = MEMORY`,
	}

	for _, sqlStmt := range initStatements {
		_, err = d.Exec(sqlStmt)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s", err, sqlStmt)
		}
	}

	return &Store{
		db: d,
	}, d.Close, nil
}

func (b *Store) GetID() (db.ID, error) {
	rows, err := b.db.Query("SELECT build_timestamp, schema_version from id")
	if err != nil {
		return db.ID{}, fmt.Errorf("unable to query for ID: %w", err)
	}
	if err = rows.Err(); err != nil {
		return db.ID{}, fmt.Errorf("bad DB ID row: %w", err)
	}
	defer func() {
		err = rows.Close()
		if err != nil {
			log.Errorf("failed to close ID store row: %+v", err)
		}
	}()

	var idStr struct {
		BuildTimestamp string
		SchemaVersion  string
	}
	var id db.ID

	if !rows.Next() {
		return db.ID{}, fmt.Errorf("no DB ID rows")
	}
	if err = rows.Err(); err != nil {
		return db.ID{}, fmt.Errorf("bad DB ID row on read: %w", err)
	}

	if err := rows.Scan(&idStr.BuildTimestamp, &idStr.SchemaVersion); err != nil {
		return db.ID{}, fmt.Errorf("unable to scan over ID row: %w", err)
	}

	ver, err := version.NewVersion(idStr.SchemaVersion)
	if err != nil {
		return db.ID{}, fmt.Errorf("bad version from DB (%s): %w", idStr.SchemaVersion, err)
	}
	id.SchemaVersion = ver

	buildTime, err := time.Parse(time.RFC3339, idStr.BuildTimestamp)
	if err != nil {
		return db.ID{}, fmt.Errorf("bad build time from DB (%s): %w", idStr.BuildTimestamp, err)
	}
	id.BuildTimestamp = buildTime

	return id, nil
}

func (b *Store) SetID(id db.ID) error {
	insertStmt := `INSERT OR REPLACE INTO id('id', 'build_timestamp', 'schema_version') VALUES (?,?,?)`

	statement, err := b.db.Prepare(insertStmt)
	if err != nil {
		return fmt.Errorf("failed to prep DB ID entry: %w", err)
	}

	_, err = statement.Exec(0, id.BuildTimestamp.Format(time.RFC3339), id.SchemaVersion.String())
	if err != nil {
		return fmt.Errorf("failed to set DB ID entry: %w", err)
	}

	return nil
}

// Get retrieves one or more vulnerabilities given a namespace and package name
func (b *Store) GetVulnerability(namespace, name string) ([]db.Vulnerability, error) {
	var vulnerabilities []db.Vulnerability
	rows, err := b.db.Query("SELECT cve_id,name,namespace_name,severity,version,version_format,cpes from vulns WHERE (namespace_name=? AND name=?)", namespace, name)
	if err != nil {
		return nil, fmt.Errorf("unable to query: %w", err)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("bad DB row: %w", err)
	}

	defer func() {
		err = rows.Close()
		if err != nil {
			log.Errorf("failed to close vulnerability store row: %+v", err)
		}
	}()

	for rows.Next() {
		var v db.Vulnerability
		var cpesStr string
		if err := rows.Scan(&v.ID, &v.PackageName, &v.Namespace, &v.Severity, &v.VersionConstraint, &v.VersionFormat, &cpesStr); err != nil {
			return nil, fmt.Errorf("unable to scan over row: %w", err)
		}
		if err = rows.Err(); err != nil {
			return nil, fmt.Errorf("bad DB row on read: %w", err)
		}
		if err = json.Unmarshal([]byte(cpesStr), &v.CPEs); err != nil {
			return nil, fmt.Errorf("bad DB row on CPEs decode: %w", err)
		}

		vulnerabilities = append(vulnerabilities, v)
	}

	return vulnerabilities, nil
}

// AddVulnerability saves a vulnerability in the sqlite3 store
func (b *Store) AddVulnerability(vulns ...*db.Vulnerability) error {
	for _, v := range vulns {
		insertStmt := `INSERT INTO vulns('cve_id', 'namespace_name', 'name', 'version', 'version_format', 'severity', 'cpes') VALUES (?,?,?,?,?,?,?)`
		statement, err := b.db.Prepare(insertStmt)
		if err != nil {
			return fmt.Errorf("failed to prep vuln entry: %w", err)
		}

		data, err := json.Marshal(v.CPEs)
		if err != nil {
			return fmt.Errorf("failed to encode CPES: %w", err)
		}

		_, err = statement.Exec(v.ID, v.Namespace, v.PackageName, v.VersionConstraint, v.VersionFormat, v.Severity, data)
		if err != nil {
			return fmt.Errorf("failed to add vuln entry: %w", err)
		}
	}
	return nil
}
