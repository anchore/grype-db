package osv

import (
	"testing"

	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/google/osv-scanner/pkg/models"
)

func Test_getPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  models.Package
		want *grypeDB.Package
	}{
		{
			name: "valid package",
			pkg: models.Package{
				Ecosystem: "Bitnami",
				Name:      "apache",
				Purl:      "pkg:bitnami/apache",
			},
			want: &grypeDB.Package{
				Name:      "apache",
				Ecosystem: "Bitnami",
			},
		},
		{
			name: "package with empty purl",
			pkg: models.Package{
				Ecosystem: "Bitnami",
				Name:      "apache",
				Purl:      "",
			},
			want: &grypeDB.Package{
				Name:      "apache",
				Ecosystem: "Bitnami",
			},
		},
		{
			name: "package with empty ecosystem",
			pkg: models.Package{
				Ecosystem: "",
				Name:      "apache",
				Purl:      "pkg:bitnami/apache",
			},
			want: &grypeDB.Package{
				Name:      "apache",
				Ecosystem: "",
			},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			got := getPackage(test.pkg)
			if got.Name != test.want.Name {
				t.Errorf("getPackage() got name = %v, want %v", got.Name, test.want.Name)
			}
			if got.Ecosystem != test.want.Ecosystem {
				t.Errorf("getPackage() got ecosystem = %v, want %v", got.Ecosystem, test.want.Ecosystem)
			}
		})
	}
}

func Test_extractCVSSInfo(t *testing.T) {
	tests := []struct {
		name        string
		cvss        string
		wantVersion string
		wantVector  string
		wantErr     bool
	}{
		{
			name:        "valid cvss",
			cvss:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantVersion: "3.1",
			wantVector:  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr:     false,
		},
		{
			name:        "invalid cvss",
			cvss:        "foo:3.1/bar",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
		{
			name:        "empty cvss",
			cvss:        "",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
		{
			name:        "invalid cvss version",
			cvss:        "CVSS:foo/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			gotVersion, gotVector, err := extractCVSSInfo(test.cvss)
			if (err != nil) != test.wantErr {
				t.Errorf("extractCVSSInfo() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if gotVersion != test.wantVersion {
				t.Errorf("extractCVSSInfo() got version = %v, want %v", gotVersion, test.wantVersion)
			}
			if gotVector != test.wantVector {
				t.Errorf("extractCVSSInfo() got vector = %v, want %v", gotVector, test.wantVector)
			}
		})
	}
}
