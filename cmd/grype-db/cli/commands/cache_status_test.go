package commands

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_validateCount(t *testing.T) {
	tests := []struct {
		name    string
		cfg     cacheStatusConfig
		counter func() (int64, error)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "empty count passes when min-rows is -1",
			cfg:  cacheStatusConfig{minRows: -1},
			counter: func() (int64, error) {
				return 0, nil
			},
		},
		{
			name: "empty count fails when min-rows is 0",
			cfg:  cacheStatusConfig{minRows: 0},
			counter: func() (int64, error) {
				return 0, nil
			},
			wantErr: assert.Error,
		},
		{
			name: "large count passes when min-rows is less",
			cfg:  cacheStatusConfig{minRows: 12},
			counter: func() (int64, error) {
				return 13, nil
			},
		},
		{
			name: "error is reported when counter returns error",
			counter: func() (int64, error) {
				return 0, fmt.Errorf("could not count records")
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			tt.wantErr(t, validateCount(tt.cfg, tt.counter))
		})
	}
}
