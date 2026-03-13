package main

import (
	"flag"
	"log"

	"github.com/femto-server/femto/internal/config"
	femtomime "github.com/femto-server/femto/internal/mime"
	"github.com/femto-server/femto/internal/server"
)

func main() {
	cfgPath := flag.String("config", "femto.toml", "path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("femto: %v", err)
	}

	if err := femtomime.Init(cfg.Server.MimeTypesFile); err != nil {
		log.Fatalf("femto: %v", err)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("femto: %v", err)
	}

	if err := srv.Run(); err != nil {
		log.Fatalf("femto: %v", err)
	}
}
