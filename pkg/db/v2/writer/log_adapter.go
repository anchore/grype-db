package writer

import "github.com/anchore/grype-db/internal/log"

type logAdapter struct {
}

func (l *logAdapter) Print(v ...interface{}) {
	log.Error(v...)
}
