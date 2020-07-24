package db

import (
	"github.com/anchore/grype-db/internal/log"
	"github.com/anchore/grype-db/pkg/logger"
)

func SetLogger(logger logger.Logger) {
	log.Log = logger
}
