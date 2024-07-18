package internal

import (
	"github.com/anchore/grype-db/internal/log"
	"strings"
	"time"
)

func MustParseTime(s string) *time.Time {
	// Try parsing with RFC3339 first
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return &t
	}

	// Check if the timezone information is missing and append UTC if needed
	if !strings.Contains(s, "Z") && !strings.Contains(s, "+") && !strings.Contains(s, "-") {
		s += "Z"
		t, err = time.Parse(time.RFC3339, s)
		if err == nil {
			return &t
		}
	}

	// Handle formats with milliseconds but no timezone
	formats := []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05.000Z",
	}

	for _, format := range formats {
		t, err = time.Parse(format, s)
		if err == nil {
			return &t
		}
	}

	log.WithFields("time", s).Warnf("could not parse time: %v", err)
	return nil
}
