package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/server"
	"server_torii/internal/utils"
	"syscall"
	"time"
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
		log.Printf("[ERROR] Load config failed: %v. Using default config.", err)
	}

	// Load rules
	ruleSet, err := config.LoadRules(cfg.RulePath)
	if err != nil {
		log.Fatalf("Load rules failed: %v", err)
	}

	log.Printf("Ready to start server on port %s", cfg.Port)

	//set log file
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

	utils.InitLogx(cfg.LogPath)

	//allocate shared memory
	sharedMem := &dataType.SharedMemory{
		HTTPFloodSpeedLimitCounter:   dataType.NewCounter(max(runtime.NumCPU()*8, 16), utils.FindMaxRateTime(ruleSet.HTTPFloodRule.HTTPFloodSpeedLimit)),
		HTTPFloodSameURILimitCounter: dataType.NewCounter(max(runtime.NumCPU()*8, 16), utils.FindMaxRateTime(ruleSet.HTTPFloodRule.HTTPFloodSameURILimit)),
	}

	//GC
	gcStopCh := make(chan struct{})
	go dataType.StartCounterGC(sharedMem.HTTPFloodSpeedLimitCounter, time.Minute, gcStopCh)
	go dataType.StartCounterGC(sharedMem.HTTPFloodSameURILimitCounter, time.Minute, gcStopCh)

	// Start server
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.StartServer(cfg, ruleSet, sharedMem)
	}()

	select {
	case <-stop:
		log.Println("Stopping server...")
		close(gcStopCh)
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}

	log.Println("Server stopped")
}
