package commands

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype-db/cmd/grype-db/cli/options"
	"github.com/anchore/grype-db/pkg/provider"
)

func Test_archiveProvider(t *testing.T) {
	type args struct {
		cfg  cacheBackupConfig
		root string
		name string
	}
	tests := []struct {
		name           string
		args           args
		wantNames      *strset.Set
		wantStateStale bool
		wantErr        assert.ErrorAssertionFunc
	}{
		{
			name: "default config includes input",
			args: args{
				cfg: cacheBackupConfig{
					Results: options.Results{
						ResultsOnly: false,
					},
				},
				root: "test-fixtures/test-root",
				name: "test-provider",
			},
			wantStateStale: false,
			wantNames: strset.New([]string{
				"test-provider/input/some-input-file.txt",
				"test-provider/metadata.json",
				"test-provider/results/results.db",
			}...),
			wantErr: nil,
		},
		{
			name: "results only excludes input",
			args: args{
				cfg: cacheBackupConfig{
					Results: options.Results{
						ResultsOnly: true,
					},
				},
				root: "test-fixtures/test-root",
				name: "test-provider",
			},
			wantNames: strset.New(
				"test-provider/metadata.json",
				"test-provider/results/results.db",
			),
			wantStateStale: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			tw := tar.NewWriter(&b)
			err := archiveProvider(tt.args.cfg, tt.args.root, tt.args.name, tw)
			if tt.wantErr != nil {
				tt.wantErr(t, err)
				return
			}
			assert.NoError(t, err)
			r := bytes.NewReader(b.Bytes())
			var state provider.State
			foundNames := strset.New()
			tr := tar.NewReader(r)
			for {
				next, nextErr := tr.Next()
				if errors.Is(nextErr, io.EOF) {
					break
				}
				require.NoError(t, nextErr)
				if next.Name == path.Join(tt.args.name, "metadata.json") {
					err = json.NewDecoder(tr).Decode(&state)
					require.NoError(t, err)
				}
				foundNames.Add(next.Name)
			}
			assert.Equalf(t, tt.wantStateStale, state.Stale, "state had wrong staleness")
			setDiff := strset.SymmetricDifference(tt.wantNames, foundNames)
			assert.True(t, setDiff.IsEmpty())
		})
	}
}

func Test_pathWalker(t *testing.T) {
	type args struct {
		path   string
		info   os.FileInfo
		err    error
		cfg    cacheBackupConfig
		name   string
		writer *tar.Writer
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "passed in error is return",
			args: args{
				err: fmt.Errorf("surprising error"),
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if err == nil {
					t.Errorf("expected 'surprising error' but was nil")
					return false
				}
				if err.Error() != "surprising error" {
					t.Errorf("wanted %q but was %q", "surprising error", err.Error())
					return false
				}
				return true
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, pathWalker(tt.args.path, tt.args.info, tt.args.err, tt.args.cfg, tt.args.name, tt.args.writer),
				fmt.Sprintf("pathWalker(%v, %v, %v, %v, %v, %v)", tt.args.path, tt.args.info, tt.args.err, tt.args.cfg, tt.args.name, tt.args.writer))
		})
	}
}
