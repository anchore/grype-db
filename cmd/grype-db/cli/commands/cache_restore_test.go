package commands

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectLinkTraversal(t *testing.T) {
	rootPath := "/safe/root"

	tests := []struct {
		name        string
		cleanedPath string
		linkTarget  string
		wantErr     bool
	}{
		{
			name:        "valid symlink inside root",
			cleanedPath: "/safe/root/some/file",
			linkTarget:  "target/file",
			wantErr:     false,
		},
		{
			name:        "symlink outside root",
			cleanedPath: "/safe/root/some/file",
			linkTarget:  "../../outside/file",
			wantErr:     true,
		},
		{
			name:        "absolute symlink outside root",
			cleanedPath: "/safe/root/some/file",
			linkTarget:  "/other/path/file",
			wantErr:     true,
		},
		{
			name:        "valid symlink to a deeper path",
			cleanedPath: "/safe/root/some/file",
			linkTarget:  "another/file",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detectLinkTraversal(rootPath, tt.cleanedPath, tt.linkTarget)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDetectPathTraversal(t *testing.T) {
	rootPath := "/safe/root"

	tests := []struct {
		name        string
		cleanedPath string
		wantErr     bool
	}{
		{
			name:        "valid path inside root",
			cleanedPath: "/safe/root/some/file",
			wantErr:     false,
		},
		{
			name:        "path outside root",
			cleanedPath: "/unsafe/root/some/file",
			wantErr:     true,
		},
		{
			name:        "empty path",
			cleanedPath: "",
			wantErr:     false,
		},
		{
			name:        "root path itself",
			cleanedPath: "/safe/root",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detectPathTraversal(rootPath, tt.cleanedPath)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "path traversal detected")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandleFile(t *testing.T) {
	fs := afero.NewMemMapFs()

	tests := []struct {
		name       string
		path       string
		content    string
		wantErr    require.ErrorAssertionFunc
		verifyFunc func(t *testing.T, fs afero.Fs, path, content string)
	}{
		{
			name:    "valid file creation",
			path:    "/testdir/file.txt",
			content: "hello world",
			verifyFunc: func(t *testing.T, fs afero.Fs, path, expected string) {
				fileExists, err := afero.Exists(fs, path)
				require.NoError(t, err)
				assert.True(t, fileExists)

				fileContent, err := afero.ReadFile(fs, path)
				require.NoError(t, err)
				assert.Equal(t, expected, string(fileContent))
			},
		},
		{
			name:    "parent directory creation",
			path:    "/newdir/subdir/file.txt",
			content: "content in nested directory",
			verifyFunc: func(t *testing.T, fs afero.Fs, path, expected string) {
				fileExists, err := afero.Exists(fs, path)
				require.NoError(t, err)
				assert.True(t, fileExists)

				fileContent, err := afero.ReadFile(fs, path)
				require.NoError(t, err)
				assert.Equal(t, expected, string(fileContent))

				dirExists, err := afero.DirExists(fs, "/newdir/subdir")
				require.NoError(t, err)
				assert.True(t, dirExists)
			},
		},
		{
			name:    "file creation failure",
			path:    "",
			content: "should fail",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			reader := bytes.NewReader([]byte(tt.content))

			err := handleFile(fs, tt.path, reader)
			tt.wantErr(t, err)
			if tt.verifyFunc != nil {
				tt.verifyFunc(t, fs, tt.path, tt.content)
			}
		})
	}
}

func TestHandleSymlink(t *testing.T) {

	tests := []struct {
		name       string
		headerName string
		linkName   string
		setupFunc  func(fs afero.Fs, rootPath, path, linkTarget string) error
		wantErr    require.ErrorAssertionFunc
	}{
		{
			name:       "valid symlink creation",
			headerName: "symlink",
			linkName:   "target/file",
		},
		{
			name:       "symlink already exists and points to the correct target",
			headerName: "symlink",
			linkName:   "target/file",
			setupFunc: func(fs afero.Fs, rootPath, path, linkName string) error {
				linker, ok := fs.(afero.Linker)
				require.True(t, ok)
				return linker.SymlinkIfPossible(linkName, filepath.Join(rootPath, path))
			},
		},
		{
			name:       "symlink exists and points to a different target",
			headerName: "symlink",
			linkName:   "target/file",
			setupFunc: func(fs afero.Fs, rootPath, path, linkName string) error {
				linker, ok := fs.(afero.Linker)
				require.True(t, ok)
				return linker.SymlinkIfPossible("wrong/target", filepath.Join(rootPath, path))
			},
		},
		{
			name:       "detectLinkTraversal error",
			headerName: "symlink",
			linkName:   "../../outside",
			wantErr:    require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewOsFs()

			rootPath := t.TempDir()

			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			if tt.setupFunc != nil {
				err := tt.setupFunc(fs, rootPath, tt.headerName, tt.linkName)
				require.NoError(t, err)
			}

			cleanPath := cleanPathRelativeToRoot(rootPath, tt.headerName)
			err := handleSymlink(fs, rootPath, cleanPath, tt.linkName)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			// check if symlink was created and points to the correct target
			linkReader, ok := fs.(afero.LinkReader)
			require.True(t, ok)

			linkTarget, err := linkReader.ReadlinkIfPossible(cleanPath)
			require.NoError(t, err)
			assert.Equal(t, tt.linkName, linkTarget)

		})
	}
}
