package tarutil

import (
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ lowLevelWriter = (*mockTarWriter)(nil)

var _ os.FileInfo = (*mockFileInfo)(nil)

type mockFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	sys     any
}

func (m mockFileInfo) Name() string {
	return m.name
}

func (m mockFileInfo) Size() int64 {
	return m.size
}

func (m mockFileInfo) Mode() fs.FileMode {
	return m.mode
}

func (m mockFileInfo) ModTime() time.Time {
	return m.modTime
}

func (m mockFileInfo) IsDir() bool {
	return m.isDir
}

func (m mockFileInfo) Sys() any {
	return m.sys
}

func TestReaderEntry_writeEntry(t *testing.T) {

	tests := []struct {
		name     string
		bytes    []byte
		filename string
		fileinfo os.FileInfo
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "valid file",
			bytes:    []byte("hello world"),
			filename: "file.txt",
			fileinfo: &mockFileInfo{
				name:    "SOMEWHEREELSE/PLACES.txt",
				size:    11,
				mode:    0644,
				modTime: time.Now(),
				isDir:   false,
				sys:     nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			fe := NewEntryFromBytes(tt.bytes, tt.filename, tt.fileinfo)
			tw := &mockTarWriter{}

			err := fe.writeEntry(tw)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			assert.NoError(t, err)
			require.Len(t, tw.headers, 1)
			assert.Equal(t, tt.filename, tw.headers[0].Name)
			assert.Equal(t, int64(len(tt.bytes)), tw.headers[0].Size)
			assert.Equal(t, string(tt.bytes), tw.buffers[0].String())
			assert.True(t, tw.flushCalled)
		})
	}
}
