package sqlite

import (
	"database/sql"
	"fmt"
	"os"

	// Required for its side-effects so that sql.Open understands sqlite3
	_ "github.com/mattn/go-sqlite3"
)

// Options defines the information needed to connect and create a sqlite3 database
type Options struct {
	FilePath string
	Clean    bool
}

// ConnectionString creates a connection string for sqlite3
func (o Options) ConnectionString() (string, error) {
	if o.FilePath == "" {
		o.FilePath = "flat.db"
	}
	return fmt.Sprintf("file:%s?cache=shared", o.FilePath), nil
}

// Open a new connection to the sqlite3 database file
func Open(option *Options) (*sql.DB, error) {
	if option == nil {
		option = &Options{}
	}
	if option.Clean {
		os.Remove(option.FilePath)
	}
	connStr, err := option.ConnectionString()
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, err
	}

	return db, nil
}
