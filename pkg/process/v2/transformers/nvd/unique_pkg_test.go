package nvd

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"

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
	tests := []struct {
		name     string
		nodes    []nvd.Node
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := findUniquePkgs(nvd.Configuration{Nodes: test.nodes})
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
