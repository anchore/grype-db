package v3

// Entry represents a single DB entry for a vulnerability and it's metadata.
type Entry struct {
	Vulnerability         Vulnerability
	VulnerabilityMetadata VulnerabilityMetadata
}
