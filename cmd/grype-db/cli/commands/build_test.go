package commands

import (
	"reflect"
	"testing"
	"time"

	"github.com/anchore/grype-db/pkg/provider"
)

func Test_latestTimestamp(t *testing.T) {
	tests := []struct {
		name   string
		states []provider.State
		want   time.Time
	}{
		{
			name: "happy path",
			states: []provider.State{
				{
					Timestamp: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				{
					Timestamp: time.Date(2021, 1, 3, 0, 0, 0, 0, time.UTC),
				},
				{
					Timestamp: time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC),
				},
			},
			want: time.Date(2021, 1, 3, 0, 0, 0, 0, time.UTC),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := latestTimestamp(tt.states); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("latestTimestamp() = %v, want %v", got, tt.want)
			}
		})
	}
}
