package db

import (
	"github.com/anchore/siren-db/internal/log"
	"github.com/anchore/siren-db/pkg/logger"
)

func SetLogger(logger logger.Logger) {
	log.Log = logger
}
