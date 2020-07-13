package db

const StoreFileName = "vulnerability.db"

type Store interface {
	StoreReader
	StoreWriter
}

type StoreReader interface {
	GetID() (ID, error)
	VulnerabilityStoreReader
}

type StoreWriter interface {
	SetID(ID) error
	VulnerabilityStoreWriter
}

type VulnerabilityStore interface {
	VulnerabilityStoreReader
	VulnerabilityStoreWriter
}

type VulnerabilityStoreReader interface {
	// Get retrieves vulnerabilities associated with a namespace and a package name
	GetVulnerability(namespace, name string) ([]Vulnerability, error)
}

type VulnerabilityStoreWriter interface {
	// AddVulnerability inserts a new record of a vulnerability into the store
	AddVulnerability(v ...*Vulnerability) error
}
