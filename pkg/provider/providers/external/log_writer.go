package external

import (
	"fmt"
	"strings"

	"github.com/anchore/grype-db/internal/log"
)

type logWriter struct {
	name string
}

func newLogWriter(name string) *logWriter {
	return &logWriter{
		name: name,
	}
}

func (lw logWriter) Write(p []byte) (n int, err error) {
	for _, line := range strings.Split(string(p), "\n") {
		line = strings.TrimRight(line, "\n")
		if line != "" {
			log.Debug(fmt.Sprintf("[%s]", lw.name) + line)
		}
	}

	return len(p), nil
}
