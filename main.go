package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/server"
	"server_torii/internal/utils"
	"syscall"
	"time"
)

func main() {
	var inputConfigPath string
	flag.StringVar(&inputConfigPath, "config", "", "Config file base path")
	flag.Parse()

	// Load MainConfig
	cfg, err := config.LoadMainConfig(inputConfigPath)
	if err != nil {
		log.Printf("[WARNING] Load config failed: %v. Using default config.", err)
	}
	config.GlobalConfig = cfg

	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()

	sharedMem := &dataType.SharedMemory{
		ActionRuleEngine: engine,
	}

	err = config.InitManager(cfg, sharedMem)
	if err != nil {
		log.Fatalf("Failed to initialize config manager: %v", err)
	}

	if cfg.EnableGossip {
		sharedMem.GossipChan = make(chan dataType.GossipMessage, 1000)

		// Initialize GossipManager
		gossipManager := server.NewGossipManager(cfg, engine)
		sharedMem.GossipManager = gossipManager
		go gossipManager.Start(sharedMem.GossipChan)
	}

	//GC
	gcStopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if sharedMem != nil {
					if c := sharedMem.HTTPFloodSpeedLimitCounter.Load(); c != nil {
						c.GC()
					}
					if c := sharedMem.HTTPFloodSameURILimitCounter.Load(); c != nil {
						c.GC()
					}
					if c := sharedMem.HTTPFloodFailureLimitCounter.Load(); c != nil {
						c.GC()
					}
					if c := sharedMem.CaptchaFailureLimitCounter.Load(); c != nil {
						c.GC()
					}
				}
			case <-gcStopCh:
				return
			}
		}
	}()

	// Initialize log system
	utils.InitLogx(cfg.LogPath)

	log.Printf("Ready to start server on port %s", cfg.Port)

	//set default log file
	defaultLogPath := filepath.Join(cfg.LogPath + "server_torii.log")
	logFile, err := os.OpenFile(defaultLogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
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

	//log startup information and time
	log.Printf("%s - Server starting...", time.Now().Format(time.RFC3339))

	// Start server
ServeLoop:
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.StartServer(cfg, sharedMem)
	}()

	select {
	case sig := <-stop:
		if sig == syscall.SIGHUP {
			log.Println("Received SIGHUP, reloading configuration...")
			if err := config.Manager.Reload(cfg, sharedMem); err != nil {
				log.Printf("[ERROR] Reload failed: %v", err)
			}
			goto ServeLoop
		}
		log.Println("Stopping server...")
		close(gcStopCh)
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}

	log.Println("Server stopped")
}
