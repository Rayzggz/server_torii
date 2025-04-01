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

	if basePath == "" {
		basePath, _ = os.Getwd()
	}

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

	//set log file
	logFile, err := os.OpenFile(cfg.LogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer func(logFile *os.File) {
		err := logFile.Close()
		if err != nil {
			log.Fatalf("Failed to close log file: %v", err)
		}
	}(logFile)
	log.SetOutput(logFile)

	//allocate shared memory

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
