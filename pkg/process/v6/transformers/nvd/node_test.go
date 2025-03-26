package nvd

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/cpe"
)

func TestDeduplicateCandidates(t *testing.T) {
	aVendorProduct1 := cpe.Attributes{
		Part:    "a",
		Vendor:  "vendor1",
		Product: "product1",
	}

	aVendorProduct2 := cpe.Attributes{
		Part:    "a",
		Vendor:  "vendor2",
		Product: "product2",
	}

	osProduct1 := cpe.Attributes{
		Part:    "o",
		Vendor:  "os1",
		Product: "os1product",
	}

	osProduct2 := cpe.Attributes{

		Part:    "o",
		Vendor:  "os2",
		Product: "os2product",
	}

	tests := []struct {
		name     string
		input    []affectedPackageCandidate
		expected []affectedPackageCandidate
	}{
		{
			name:     "empty input",
			input:    []affectedPackageCandidate{},
			expected: nil,
		},
		{
			name: "go case",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "deduplicate identical candidates",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "merge ranges for same CPE",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "2.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(
						affectedCPERange{ExactVersion: "1.0"},
						affectedCPERange{ExactVersion: "2.0"},
					),
				},
			},
		},
		{
			name: "merge platform CPEs for same vulnerable CPE",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					PlatformCPEs: []cpe.Attributes{
						osProduct1,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct1,
					PlatformCPEs: []cpe.Attributes{
						osProduct2,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					PlatformCPEs: []cpe.Attributes{
						osProduct1,
						osProduct2,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "different CPEs not deduplicated",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct2,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "2.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: aVendorProduct1,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: aVendorProduct2,
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "2.0",
					}),
				},
			},
		},
		{
			name: "deduplicate based on target software",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:     "a",
						Vendor:   "vendor",
						Product:  "product",
						TargetSW: "target1",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:     "a",
						Vendor:   "vendor",
						Product:  "product",
						TargetSW: "target2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:     "a",
						Vendor:   "vendor",
						Product:  "product",
						TargetSW: "target1",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:     "a",
						Vendor:   "vendor",
						Product:  "product",
						TargetSW: "target2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "derive ranges when none specified",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product",
						Version: "3.0",
						Update:  "p2",
					},
					Ranges: newAffectedRanges(),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product",
						Version: "3.0",
						Update:  "p2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "3.0",
						ExactUpdate:  "p2",
					}),
				},
			},
		},
		{
			name: "derive ranges for one candidate but not others",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product1",
						Version: "3.0",
					},
					Ranges: newAffectedRanges(),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product1",
						Version: "3.0",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "3.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:    "a",
						Vendor:  "vendor",
						Product: "product2",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
		},
		{
			name: "complex case with mixed input",
			input: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "enterprise",
					},
					PlatformCPEs: []cpe.Attributes{
						osProduct1,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "enterprise",
					},
					PlatformCPEs: []cpe.Attributes{
						osProduct2,
					},
					Ranges: newAffectedRanges(affectedCPERange{
						VersionStartIncluding: "1.0",
						VersionEndExcluding:   "2.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "community",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
			},
			expected: []affectedPackageCandidate{
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "community",
					},
					Ranges: newAffectedRanges(affectedCPERange{
						ExactVersion: "1.0",
					}),
				},
				{
					VulnerableCPE: cpe.Attributes{
						Part:      "a",
						Vendor:    "vendor",
						Product:   "product",
						Version:   "1.0",
						SWEdition: "enterprise",
					},
					PlatformCPEs: []cpe.Attributes{
						osProduct1,
						osProduct2,
					},
					Ranges: newAffectedRanges(
						affectedCPERange{
							ExactVersion: "1.0",
						},
						affectedCPERange{
							VersionStartIncluding: "1.0",
							VersionEndExcluding:   "2.0",
						},
					),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := deduplicateCandidates(tt.input)

			if diff := cmp.Diff(tt.expected, actual); diff != "" {
				t.Errorf("deduplicateCandidates() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
