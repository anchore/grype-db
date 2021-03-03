package v1

type Entry struct {
	Vulnerability         *Vulnerability
	VulnerabilityMetadata *VulnerabilityMetadata
	Err                   error
}
