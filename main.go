package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"server_torii/internal/config"
	"server_torii/internal/server"
	"syscall"
)

func main() {
	var basePath string
	flag.StringVar(&basePath, "prefix", "", "Config file base path")
	flag.Parse()

	// Load MainConfig
	cfg, err := config.LoadMainConfig(basePath)
	if err != nil {
		log.Fatalf("Load config failed: %v", err)
	}

	// Load rules
	ruleSet, err := config.LoadRules(cfg.RulePath)
	if err != nil {
		log.Fatalf("Load rules failed: %v", err)
	}

	log.Printf("Ready to start server on port %s", cfg.Port)

	// Start server
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.StartServer(cfg, ruleSet)
	}()

	select {
	case <-stop:
		log.Println("Stopping server...")
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}

	log.Println("Server stopped")
}
