package commands

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_validateCount(t *testing.T) {
	tests := []struct {
		name    string
		cfg     cacheStatusConfig
		counter func() (int64, error)
		want    int64
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
			want: 13,
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
			count, err := validateCount(tt.cfg, tt.counter)
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.want, count)
		})
	}
}

func Test_validateRequestedProviders(t *testing.T) {
	tests := []struct {
		name               string
		providersOnDisk    []string
		requestedProviders []string
		want               []string
		wantErr            assert.ErrorAssertionFunc
	}{
		{
			name:            "no requested providers means on disk state is ok",
			providersOnDisk: []string{"alpine", "some-provider", "void-linux", "gentoo"},
			want:            []string{"alpine", "some-provider", "void-linux", "gentoo"},
		},
		{
			name:               "requesting subset of providers works",
			providersOnDisk:    []string{"alpine", "some-provider", "void-linux", "gentoo"},
			requestedProviders: []string{"alpine", "void-linux"},
			want:               []string{"alpine", "void-linux"},
		},
		{
			name:               "requesting missing provider result in error",
			providersOnDisk:    []string{"alpine", "some-provider", "void-linux", "gentoo"},
			requestedProviders: []string{"alpine", "void-linux", "missing"},
			wantErr:            assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateRequestedProviders(tt.providersOnDisk, tt.requestedProviders)
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			if !tt.wantErr(t, err, fmt.Sprintf("validateRequestedProviders(%v, %v)", tt.providersOnDisk, tt.requestedProviders)) {
				return
			}
			assert.Equalf(t, tt.want, got, "validateRequestedProviders(%v, %v)", tt.providersOnDisk, tt.requestedProviders)
		})
	}
}
