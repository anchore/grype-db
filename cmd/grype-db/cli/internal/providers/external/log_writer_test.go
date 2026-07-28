package external

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/discard"
	"github.com/anchore/grype-db/internal/log"
)

func TestLogWriter_processLogLine(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		expectedLevel   string
		expectedMessage string
	}{
		{
			// processLogLine reports "no level in this line" as an empty string; the
			// writer is what turns that into the default level (or the level of the
			// record the line continues).
			name:            "no log level",
			line:            `\033[0maggregating vulnerability data providers=[rhel]`,
			expectedLevel:   "",
			expectedMessage: `\033[0maggregating vulnerability data providers=[rhel]`,
		},
		{
			name:            "info log level",
			line:            `\033[0m[INFO ] aggregating vulnerability data providers=[rhel]`,
			expectedLevel:   "INFO",
			expectedMessage: `\033[0maggregating vulnerability data providers=[rhel]`,
		},
		{
			name:            "warning log level",
			line:            `blah [WARNING] something could be going wrong`,
			expectedLevel:   "WARNING",
			expectedMessage: `blah something could be going wrong`,
		},
		{
			name:            "warn log level",
			line:            `blah [WARN ] something could be going wrong`,
			expectedLevel:   "WARN",
			expectedMessage: `blah something could be going wrong`,
		},
		{
			name:            "debug log level",
			line:            `abcdefg [DEBUG] jasdklfjlaksdjflksadj`,
			expectedLevel:   "DEBUG",
			expectedMessage: `abcdefg jasdklfjlaksdjflksadj`,
		},
		{
			name:            "trace log level",
			line:            `[TRACE] -----^^^^^`,
			expectedLevel:   "TRACE",
			expectedMessage: `-----^^^^^`,
		},
		{
			name:            "error log level",
			line:            `[ERROR] something bad happened`,
			expectedLevel:   "ERROR",
			expectedMessage: `something bad happened`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			level, message := processLogLine(test.line)
			assert.Equal(t, level, test.expectedLevel)
			assert.Equal(t, message, test.expectedMessage)
		})
	}
}

// captureLogger records the level each message was logged at.
type captureLogger struct {
	logger.Logger
	entries []loggedEntry
}

type loggedEntry struct {
	level   string
	message string
}

func (c *captureLogger) record(level string, args ...any) {
	c.entries = append(c.entries, loggedEntry{level: level, message: fmt.Sprint(args...)})
}

func (c *captureLogger) Error(args ...any) { c.record("ERROR", args...) }
func (c *captureLogger) Warn(args ...any)  { c.record("WARN", args...) }
func (c *captureLogger) Info(args ...any)  { c.record("INFO", args...) }
func (c *captureLogger) Debug(args ...any) { c.record("DEBUG", args...) }
func (c *captureLogger) Trace(args ...any) { c.record("TRACE", args...) }

// TestLogWriter_multiLineRecordKeepsLevel covers a python traceback coming from a
// provider: only its first line carries [ERROR], so the remaining lines used to
// be logged at the default info level and disappeared from an error-level view
// of the run.
func TestLogWriter_multiLineRecordKeepsLevel(t *testing.T) {
	capture := &captureLogger{Logger: discard.New()}
	log.Set(capture)

	lw := newLogWriter("nvd")

	output := `[ERROR] nvd: error during pull
Traceback (most recent call last):
  File "/src/vunnel/cli/cli.py", line 100, in run
    provider.run()
ConnectionError: HTTPSConnectionPool(host='services.nvd.nist.gov', port=443)
[INFO ] nvd: wrote 0 entries
`

	_, err := lw.Write([]byte(output))
	require.NoError(t, err)

	var levels []string
	for _, e := range capture.entries {
		levels = append(levels, e.level)
	}

	assert.Equal(t,
		[]string{"ERROR", "ERROR", "ERROR", "ERROR", "ERROR", "INFO"},
		levels,
		"every line of the traceback should stay at the level of the record it belongs to, and a later line with its own level should reset it",
	)
}
