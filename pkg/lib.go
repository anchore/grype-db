package pkg

import (
	"github.com/anchore/go-logger"
	"github.com/anchore/grype-db/internal/bus"
	"github.com/anchore/grype-db/internal/log"
	"github.com/wagoodman/go-partybus"
)

func SetLogger(l logger.Logger) {
	log.Set(l)
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
