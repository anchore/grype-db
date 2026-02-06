package process

import grypeDB "github.com/anchore/grype/grype/db/v6"

const (
	DefaultSchemaVersion = grypeDB.ModelVersion
	// DefaultBatchSize is the default number of database operations to batch together
	// before flushing to disk. This value balances throughput with memory usage.
	DefaultBatchSize = 2000
)
