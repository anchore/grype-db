package nvd

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/pkg/provider/unmarshal/nvd"
)

func newUniquePkgTrackerFromSlice(candidates []pkgCandidate) uniquePkgTracker {
	set := newUniquePkgTracker()
	for _, c := range candidates {
		set[c] = nil
	}
	return set
}

func TestFindUniquePkgs(t *testing.T) {
	boolPtr := func(b bool) *bool {
		return &b
	}
	operatorRef := func(o nvd.Operator) *nvd.Operator {
		return &o
	}
	tests := []struct {
		name     string
		nodes    []nvd.Node
		operator *nvd.Operator
		expected uniquePkgTracker
	}{
		{
			name: "simple-match",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendor:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendor",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name: "skip-hw",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:h:vendor:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{}),
		},
		{
			name: "skip-os",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:o:vendor:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
				},
			},
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{}),
		},
		{
			name: "duplicate-by-product",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendor:productA:3.3.3:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
						{
							Criteria:   "cpe:2.3:a:vendor:productB:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "productA",
						Vendor:         "vendor",
						TargetSoftware: "target",
					},
					{
						Product:        "productB",
						Vendor:         "vendor",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name: "duplicate-by-target",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendor:product:3.3.3:*:*:*:*:targetA:*:*",
							Vulnerable: true,
						},
						{
							Criteria:   "cpe:2.3:a:vendor:product:2.2.0:*:*:*:*:targetB:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendor",
						TargetSoftware: "targetA",
					},
					{
						Product:        "product",
						Vendor:         "vendor",
						TargetSoftware: "targetB",
					},
				}),
		},
		{
			name: "duplicate-by-vendor",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendorA:product:3.3.3:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
						{
							Criteria:   "cpe:2.3:a:vendorB:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendorA",
						TargetSoftware: "target",
					},
					{
						Product:        "product",
						Vendor:         "vendorB",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name: "de-duplicate-case",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendor:product:3.3.3:A:B:C:D:target:E:F",
							Vulnerable: true,
						},
						{
							Criteria:   "cpe:2.3:a:vendor:product:2.2.0:Q:R:S:T:target:U:V",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendor",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name: "duplicate-from-nested-nodes",
			nodes: []nvd.Node{
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendorB:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
				{
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:   "cpe:2.3:a:vendorA:product:2.2.0:*:*:*:*:target:*:*",
							Vulnerable: true,
						},
					},
					Operator: "OR",
				},
			},
			expected: newUniquePkgTrackerFromSlice(
				[]pkgCandidate{
					{
						Product:        "product",
						Vendor:         "vendorA",
						TargetSoftware: "target",
					},
					{
						Product:        "product",
						Vendor:         "vendorB",
						TargetSoftware: "target",
					},
				}),
		},
		{
			name:     "cpe with multiple platforms",
			operator: operatorRef(nvd.And),
			nodes: []nvd.Node{
				{
					Negate:   boolPtr(false),
					Operator: nvd.Or,
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:        "cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*",
							MatchCriteriaID: "5EBE5E1C-C881-4A76-9E36-4FB7C48427E6",
							Vulnerable:      true,
						},
					},
				},
				{
					Negate:   boolPtr(false),
					Operator: nvd.Or,
					CpeMatch: []nvd.CpeMatch{
						{
							Criteria:        "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
							MatchCriteriaID: "902B8056-9E37-443B-8905-8AA93E2447FB",
							Vulnerable:      false,
						},
						{
							Criteria:        "cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
							MatchCriteriaID: "3D94DA3B-FA74-4526-A0A0-A872684598C6",
							Vulnerable:      false,
						},
						{
							Criteria:        "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
							MatchCriteriaID: "DEECE5FC-CACF-4496-A3E7-164736409252",
							Vulnerable:      false,
						},
						{
							Criteria:        "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
							MatchCriteriaID: "07B237A9-69A3-4A9C-9DA0-4E06BD37AE73",
							Vulnerable:      false,
						},
						{
							Criteria:        "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
							MatchCriteriaID: "FA6FEEC2-9F11-4643-8827-749718254FED",
							Vulnerable:      false,
						},
					},
				},
			},
			// TODO: why is this adding nils?
			expected: newUniquePkgTrackerFromSlice([]pkgCandidate{
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
				},
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
				},
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
				},
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
				},
				{
					Product:        "redis",
					Vendor:         "redis",
					TargetSoftware: ANY,
					PlatformCPE:    "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
				},
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := findUniquePkgs(nvd.Configuration{Nodes: test.nodes, Operator: test.operator})
			missing, extra := test.expected.Diff(actual)
			if len(missing) != 0 {
				for _, c := range missing {
					t.Errorf("missing candidate: %+v", c)
				}
			}

			if len(extra) != 0 {
				for _, c := range extra {
					t.Errorf("extra candidate: %+v", c)
				}
			}
		})
	}
}

func strRef(s string) *string {
	return &s
}

func TestBuildConstraints(t *testing.T) {
	tests := []struct {
		name     string
		matches  []nvd.CpeMatch
		expected string
	}{
		{
			name: "Equals",
			matches: []nvd.CpeMatch{
				{
					Criteria: "cpe:2.3:a:vendor:product:2.2.0:*:*:*:*:target:*:*",
				},
			},
			expected: "= 2.2.0",
		},
		{
			name: "VersionEndExcluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:            "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionEndExcluding: strRef("2.3.0"),
				},
			},
			expected: "< 2.3.0",
		},
		{
			name: "VersionEndIncluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:            "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionEndIncluding: strRef("2.3.0"),
				},
			},
			expected: "<= 2.3.0",
		},
		{
			name: "VersionStartExcluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartExcluding: strRef("2.3.0"),
				},
			},
			expected: "> 2.3.0",
		},
		{
			name: "VersionStartIncluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
				},
			},
			expected: ">= 2.3.0",
		},
		{
			name: "Version Range",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndIncluding:   strRef("2.5.0"),
				},
			},
			expected: ">= 2.3.0, <= 2.5.0",
		},
		{
			name: "Multiple Version Ranges",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndIncluding:   strRef("2.5.0"),
				},
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartExcluding: strRef("3.3.0"),
					VersionEndExcluding:   strRef("3.5.0"),
				},
			},
			expected: ">= 2.3.0, <= 2.5.0 || > 3.3.0, < 3.5.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := buildConstraints(test.matches)

			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(actual, test.expected, true)
				t.Errorf("Expected: %q", test.expected)
				t.Errorf("Got     : %q", actual)
				t.Errorf("Diff    : %q", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func Test_UniquePackageTrackerHandlesOnlyPlatformDiff(t *testing.T) {
	candidates := []pkgCandidate{
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
		},
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
		},
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
		},
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
		},
		{
			Product:        "redis",
			Vendor:         "redis",
			TargetSoftware: ANY,
			PlatformCPE:    "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
		},
	}
	cpeMatch := nvd.CpeMatch{
		Criteria:        "cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*",
		MatchCriteriaID: "5EBE5E1C-C881-4A76-9E36-4FB7C48427E6",
	}
	applicationNode := nvd.CpeMatch{
		Criteria:        "cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*",
		MatchCriteriaID: "some-uuid",
		Vulnerable:      true,
	}
	tracker := newUniquePkgTracker()
	for _, c := range candidates {
		candidate, err := newPkgCandidate(applicationNode, c.PlatformCPE)
		require.NoError(t, err)
		tracker.Add(*candidate, cpeMatch)
	}
	assert.Len(t, tracker, len(candidates))
}
