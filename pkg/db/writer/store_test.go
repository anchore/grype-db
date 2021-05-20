package writer

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/anchore/grype-db/pkg/db"
	"github.com/anchore/grype-db/pkg/db/model"
	"github.com/anchore/grype-db/pkg/db/reader"
	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
)

func assertIDReader(t *testing.T, reader db.IDReader, expected db.ID) {
	t.Helper()
	if actual, err := reader.GetID(); err != nil {
		t.Fatalf("failed to get ID: %+v", err)
	} else {
		diffs := deep.Equal(&expected, actual)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("Diff: %+v", d)
			}
		}
	}
}

func TestStore_GetID_SetID(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
	defer cleanupFn()
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	expected := db.ID{
		BuildTimestamp: time.Now().UTC(),
		SchemaVersion:  2,
	}

	if err = store.SetID(expected); err != nil {
		t.Fatalf("failed to set ID: %+v", err)
	}

	assertIDReader(t, store, expected)

	// gut check on reader
	storeReader, othercleanfn, err := reader.NewStore(dbTempFile.Name())
	defer othercleanfn()
	if err != nil {
		t.Fatalf("could not open db reader: %+v", err)
	}
	assertIDReader(t, storeReader, expected)

}

func assertVulnerabilityReader(t *testing.T, reader db.VulnerabilityStoreReader, namespace, name string, expected []*db.Vulnerability) {
	if actual, err := reader.GetVulnerability(namespace, name); err != nil {
		t.Fatalf("failed to get Vulnerability: %+v", err)
	} else {
		if len(actual) != len(expected) {
			t.Fatalf("unexpected number of vulns: %d", len(actual))
		}
		for idx := range actual {
			diffs := deep.Equal(expected[idx], &actual[idx])
			if len(diffs) > 0 {
				for _, d := range diffs {
					t.Errorf("Diff: %+v", d)
				}
			}
		}
	}
}

func TestStore_GetVulnerability_SetVulnerability(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
	defer cleanupFn()
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	extra := []*db.Vulnerability{
		{
			ID:                   "my-cve-33333",
			RecordSource:         "record-source",
			PackageName:          "package-name-2",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 1.0",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
			FixedInVersion:       "2.0.1",
		},
		{
			ID:                   "my-other-cve-33333",
			RecordSource:         "record-source",
			PackageName:          "package-name-3",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 509.2.2",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
		},
	}

	expected := []*db.Vulnerability{
		{
			ID:                   "my-cve",
			RecordSource:         "record-source",
			PackageName:          "package-name",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 1.0",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
			FixedInVersion:       "1.0.1",
		},
		{
			ID:                   "my-other-cve",
			RecordSource:         "record-source",
			PackageName:          "package-name",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 509.2.2",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
			FixedInVersion:       "4.0.5",
		},
	}

	total := append(expected, extra...)

	// case: ignore nil entries
	if err = store.AddVulnerability(nil, nil, nil, nil); err != nil {
		t.Fatalf("failed to set Vulnerability: %+v", err)
	}

	if err = store.AddVulnerability(total...); err != nil {
		t.Fatalf("failed to set Vulnerability: %+v", err)
	}

	var allEntries []model.VulnerabilityModel
	store.vulnDb.Find(&allEntries)
	if len(allEntries) != len(total) {
		t.Fatalf("unexpected number of entries: %d", len(allEntries))
	}

	assertVulnerabilityReader(t, store, expected[0].Namespace, expected[0].PackageName, expected)

	// gut check on reader
	storeReader, othercleanfn, err := reader.NewStore(dbTempFile.Name())
	defer othercleanfn()
	if err != nil {
		t.Fatalf("could not open db reader: %+v", err)
	}
	assertVulnerabilityReader(t, storeReader, expected[0].Namespace, expected[0].PackageName, expected)

}

func assertVulnerabilityMetadataReader(t *testing.T, reader db.VulnerabilityMetadataStoreReader, id, recordSource string, expected db.VulnerabilityMetadata) {
	if actual, err := reader.GetVulnerabilityMetadata(id, recordSource); err != nil {
		t.Fatalf("failed to get metadata: %+v", err)
	} else {
		sortMetadataCvss(actual.Cvss)
		sortMetadataCvss(expected.Cvss)

		// make sure they both have the same number of CVSS entries - preventing a panic on later assertions
		assert.Len(t, expected.Cvss, len(actual.Cvss))
		for idx, actualCvss := range actual.Cvss {
			assert.Equal(t, actualCvss.Vector, expected.Cvss[idx].Vector)
			assert.Equal(t, actualCvss.Version, expected.Cvss[idx].Version)
			assert.Equal(t, actualCvss.Metrics, expected.Cvss[idx].Metrics)

			actualVendor, err := json.Marshal(actualCvss.VendorMetadata)
			if err != nil {
				t.Errorf("unable to marshal vendor metadata: %q", err)
			}
			expectedVendor, err := json.Marshal(expected.Cvss[idx].VendorMetadata)
			if err != nil {
				t.Errorf("unable to marshal vendor metadata: %q", err)
			}
			assert.Equal(t, string(actualVendor), string(expectedVendor))

		}

		// nil the Cvss field because it is an interface - verification of Cvss
		// has already happened at this point
		expected.Cvss = nil
		actual.Cvss = nil
		assert.Equal(t, &expected, actual)
	}

}

func sortMetadataCvss(cvss []db.Cvss) {
	sort.Slice(cvss, func(i, j int) bool {
		// first, sort by Vector
		if cvss[i].Vector > cvss[j].Vector {
			return true
		}
		if cvss[i].Vector < cvss[j].Vector {
			return false
		}
		// then try to sort by BaseScore if Vector is the same
		return cvss[i].Metrics.BaseScore < cvss[j].Metrics.BaseScore
	})
}

// CustomMetadata is effectively a noop, its values aren't meaningful and are
// mostly useful to ensure that any type can be stored and then retrieved for
// assertion in these test cases where custom vendor CVSS scores are used
type CustomMetadata struct {
	SuperScore string
	Vendor     string
}

func TestStore_GetVulnerabilityMetadata_SetVulnerabilityMetadata(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
	defer cleanupFn()
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	total := []*db.VulnerabilityMetadata{
		{
			ID:           "my-cve",
			RecordSource: "record-source",
			Severity:     "pretty bad",
			Links:        []string{"https://ancho.re"},
			Description:  "best description ever",
			Cvss: []db.Cvss{
				{
					VendorMetadata: CustomMetadata{
						Vendor:     "redhat",
						SuperScore: "1000",
					},
					Version: "2.0",
					Metrics: db.NewCvssMetrics(
						1.1,
						2.2,
						3.3,
					),
					Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--NOT",
				},
				{
					Version: "3.0",
					Metrics: db.NewCvssMetrics(
						1.3,
						2.1,
						3.2,
					),
					Vector:         "AV:N/AC:L/Au:N/C:P/I:P/A:P--NICE",
					VendorMetadata: nil,
				},
			},
		},
		{
			ID:           "my-other-cve",
			RecordSource: "record-source",
			Severity:     "pretty bad",
			Links:        []string{"https://ancho.re"},
			Description:  "worst description ever",
			Cvss: []db.Cvss{
				{
					Version: "2.0",
					Metrics: db.NewCvssMetrics(
						4.1,
						5.2,
						6.3,
					),
					Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
				},
				{
					Version: "3.0",
					Metrics: db.NewCvssMetrics(
						1.4,
						2.5,
						3.6,
					),
					Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
				},
			},
		},
	}

	// case: ignore nil entries
	if err = store.AddVulnerabilityMetadata(nil, nil, nil, nil); err != nil {
		t.Fatalf("failed to set metadata: %+v", err)
	}

	if err = store.AddVulnerabilityMetadata(total...); err != nil {
		t.Fatalf("failed to set metadata: %+v", err)
	}

	var allEntries []model.VulnerabilityMetadataModel
	store.vulnDb.Find(&allEntries)
	if len(allEntries) != len(total) {
		t.Fatalf("unexpected number of entries: %d", len(allEntries))
	}

	// gut check on reader
	storeReader, othercleanfn, err := reader.NewStore(dbTempFile.Name())
	defer othercleanfn()
	if err != nil {
		t.Fatalf("could not open db reader: %+v", err)
	}

	assertVulnerabilityMetadataReader(t, storeReader, total[0].ID, total[0].RecordSource, *total[0])

}

func TestStore_MergeVulnerabilityMetadata(t *testing.T) {
	tests := []struct {
		name     string
		add      []db.VulnerabilityMetadata
		expected db.VulnerabilityMetadata
		err      bool
	}{
		{
			name: "go-case",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re"},
				Description:  "worst description ever",
				Cvss: []db.Cvss{
					{
						Version: "2.0",
						Metrics: db.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "3.0",
						Metrics: db.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
		{
			name: "merge-links",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://google.com"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://yahoo.com"},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re", "https://google.com", "https://yahoo.com"},
				Cvss:         []db.Cvss{},
			},
		},
		{
			name: "bad-severity",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "meh, push that for next tuesday...",
					Links:        []string{"https://redhat.com"},
				},
			},
			err: true,
		},
		{
			name: "mismatch-description",
			err:  true,
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
		},
		{
			name: "mismatch-cvss2",
			err:  false,
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re"},
				Description:  "best description ever",
				Cvss: []db.Cvss{
					{
						Version: "2.0",
						Metrics: db.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "3.0",
						Metrics: db.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
					{
						Version: "2.0",
						Metrics: db.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:P--VERY",
					},
				},
			},
		},
		{
			name: "mismatch-cvss3",
			err:  false,
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								0,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re"},
				Description:  "best description ever",
				Cvss: []db.Cvss{
					{
						Version: "2.0",
						Metrics: db.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "3.0",
						Metrics: db.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
					{
						Version: "3.0",
						Metrics: db.NewCvssMetrics(
							1.4,
							0,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbTempDir, err := ioutil.TempDir("", "grype-db-test-store")
			if err != nil {
				t.Fatalf("could not create temp file: %+v", err)
			}
			defer os.RemoveAll(dbTempDir)

			store, cleanupFn, err := NewStore(dbTempDir, true)
			defer cleanupFn()
			if err != nil {
				t.Fatalf("could not create store: %+v", err)
			}

			// add each metadata in order
			var theErr error
			for _, metadata := range test.add {
				err = store.AddVulnerabilityMetadata(&metadata)
				if err != nil {
					theErr = err
					break
				}
			}

			if test.err && theErr == nil {
				t.Fatalf("expected error but did not get one")
			} else if !test.err && theErr != nil {
				t.Fatalf("expected no error but got one: %+v", theErr)
			} else if test.err && theErr != nil {
				// test pass...
				return
			}

			// ensure there is exactly one entry
			var allEntries []model.VulnerabilityMetadataModel
			store.vulnDb.Find(&allEntries)
			if len(allEntries) != 1 {
				t.Fatalf("unexpected number of entries: %d", len(allEntries))
			}

			// get the resulting metadata object
			if actual, err := store.GetVulnerabilityMetadata(test.expected.ID, test.expected.RecordSource); err != nil {
				t.Fatalf("failed to get metadata: %+v", err)
			} else {
				diffs := deep.Equal(&test.expected, actual)
				if len(diffs) > 0 {
					for _, d := range diffs {
						t.Errorf("Diff: %+v", d)
					}
				}
			}
		})
	}
}

func TestCvssScoresInMetadata(t *testing.T) {
	tests := []struct {
		name     string
		add      []db.VulnerabilityMetadata
		expected db.VulnerabilityMetadata
	}{
		{
			name: "append-cvss",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []db.Cvss{
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re"},
				Description:  "worst description ever",
				Cvss: []db.Cvss{
					{
						Version: "2.0",
						Metrics: db.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "3.0",
						Metrics: db.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
		{
			name: "append-vendor-cvss",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []db.Cvss{
						{
							Version: "2.0",
							Metrics: db.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
							VendorMetadata: CustomMetadata{
								SuperScore: "100",
								Vendor:     "debian",
							},
						},
					},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re"},
				Description:  "worst description ever",
				Cvss: []db.Cvss{
					{
						Version: "2.0",
						Metrics: db.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "2.0",
						Metrics: db.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						VendorMetadata: CustomMetadata{
							SuperScore: "100",
							Vendor:     "debian",
						},
					},
				},
			},
		},
		{
			name: "avoids-duplicate-cvss",
			add: []db.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []db.Cvss{
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Severity:     "pretty bad",
					Links:        []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []db.Cvss{
						{
							Version: "3.0",
							Metrics: db.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re"},
				Description:  "worst description ever",
				Cvss: []db.Cvss{
					{
						Version: "3.0",
						Metrics: db.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbTempDir, err := ioutil.TempDir("", "grype-db-test-store")
			if err != nil {
				t.Fatalf("could not create temp file: %+v", err)
			}
			defer os.RemoveAll(dbTempDir)

			store, cleanupFn, err := NewStore(dbTempDir, true)
			defer cleanupFn()
			if err != nil {
				t.Fatalf("could not create store: %+v", err)
			}

			// add each metadata in order
			for _, metadata := range test.add {
				err = store.AddVulnerabilityMetadata(&metadata)
				if err != nil {
					t.Fatalf("unable to store vulnerability metadata: %+v", err)
				}
			}

			// ensure there is exactly one entry
			var allEntries []model.VulnerabilityMetadataModel
			store.vulnDb.Find(&allEntries)
			if len(allEntries) != 1 {
				t.Fatalf("unexpected number of entries: %d", len(allEntries))
			}

			assertVulnerabilityMetadataReader(t, store, test.expected.ID, test.expected.RecordSource, test.expected)
		})
	}
}
