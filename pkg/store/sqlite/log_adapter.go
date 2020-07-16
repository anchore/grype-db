package sqlite

import "github.com/anchore/siren-db/internal/log"

type logAdapter struct {
}

func (l *logAdapter) Print(v ...interface{}) {
	log.Error(v...)
}
