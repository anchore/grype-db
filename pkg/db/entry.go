package db

type Entry struct {
	Vulnerability         *Vulnerability
	VulnerabilityMetadata *VulnerabilityMetadata
	Err                   error
}
