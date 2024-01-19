package v5

type Store interface {
	StoreReader
	StoreWriter
	DBCloser
}

type StoreReader interface {
	IDReader
	VulnerabilityStoreReader
	VulnerabilityMetadataStoreReader
	VulnerabilityMatchExclusionStoreReader
}

type StoreWriter interface {
	IDWriter
	VulnerabilityStoreWriter
	VulnerabilityMetadataStoreWriter
	VulnerabilityMatchExclusionStoreWriter
}

type DBCloser interface {
	Close()
}
