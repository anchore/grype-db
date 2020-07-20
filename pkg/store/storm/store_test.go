package storm

import (
	"github.com/anchore/go-version"
	"github.com/anchore/siren-db/pkg/db"
	"github.com/anchore/siren-db/pkg/store/storm/model"
	"github.com/go-test/deep"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestStore_GetID_SetID(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "siren-db-test-store")
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
		SchemaVersion:  *version.Must(version.NewVersion("2.3.4")),
	}

	if err = store.SetID(expected); err != nil {
		t.Fatalf("failed to set ID: %+v", err)
	}

	if actual, err := store.GetID(); err != nil {
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

func TestStore_GetVulnerability_SetVulnerability(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "siren-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
	defer cleanupFn()
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	extra := &db.Vulnerability{

		ID:                   "my-cve",
		RecordSource:         "record-source",
		PackageName:          "SOME-OTHER-name",
		Namespace:            "my-namespace",
		VersionConstraint:    "< 1.0",
		VersionFormat:        "semver",
		CPEs:                 []string{"a-cool-cpe"},
		ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},

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
		},
		{
			ID:                   "my-other-cve",
			RecordSource:         "record-source",
			PackageName:          "package-name",
			Namespace:            "my-namespace",
			VersionConstraint:    "< 1.2",
			VersionFormat:        "semver",
			CPEs:                 []string{"a-cool-cpe"},
			ProxyVulnerabilities: []string{"another-cve", "an-other-cve"},
		},
	}

	total := append(expected, extra)

	// case: ignore nil entries
	if err = store.AddVulnerability(total...); err != nil {
		t.Fatalf("failed to set Vulnerability: %+v", err)
	}

	var allEntries []model.Vulnerability
	err = store.vulnDb.All(&allEntries)
	if err != nil {
		t.Fatalf("unable to find all models: %+v", err)
	}
	if len(allEntries) != len(total) {
		t.Fatalf("unexpected number of entries: %d", len(allEntries))
	}

	if actual, err := store.GetVulnerability(expected[0].Namespace, expected[0].PackageName); err != nil {
		t.Fatalf("failed to get Vulnerability: %+v", err)
	} else {
		if len(actual) != len(expected) {
			t.Fatalf("unexpected number of vulns: %d", len(actual))
		}

		for idx := range actual {
			diffs := deep.Equal(expected[idx], &actual[idx])
			if len(diffs) > 0 {
				for _, d := range diffs {
					t.Errorf("Diff @%d: %+v", idx, d)
				}
			}
		}
	}
}

func TestStore_GetVulnerabilityMetadata_SetVulnerabilityMetadata(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "siren-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
	defer cleanupFn()
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	expected := db.VulnerabilityMetadata{
		ID:           "my-cve",
		RecordSource: "record-source",
		Severity:     "pretty bad",
		Links:        []string{"https://ancho.re"},
	}

	// case: ignore nil entries
	if err = store.AddVulnerabilityMetadata(&expected, nil, nil, nil); err != nil {
		t.Fatalf("failed to set metadata: %+v", err)
	}

	var allEntries []model.VulnerabilityMetadata
	err = store.vulnDb.All(&allEntries)
	if err != nil {
		t.Fatalf("unable to find all models: %+v", err)
	}
	if len(allEntries) != 1 {
		t.Fatalf("unexpected number of entries: %d", len(allEntries))
	}

	if actual, err := store.GetVulnerabilityMetadata(expected.ID, expected.RecordSource); err != nil {
		t.Fatalf("failed to get metadata: %+v", err)
	} else {

		diffs := deep.Equal(&expected, actual)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("Diff: %+v", d)
			}
		}
	}
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
				},
			},
			expected: db.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Severity:     "pretty bad",
				Links:        []string{"https://ancho.re"},
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbTempFile, err := ioutil.TempFile("", "siren-db-test-store")
			if err != nil {
				t.Fatalf("could not create temp file: %+v", err)
			}
			defer os.Remove(dbTempFile.Name())

			store, cleanupFn, err := NewStore(dbTempFile.Name(), true)
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
			var allEntries []model.VulnerabilityMetadata
			err = store.vulnDb.All(&allEntries)
			if err != nil {
				t.Fatalf("unable to find all models: %+v", err)
			}
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
