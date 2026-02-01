package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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

	// Load site-specific rules
	siteRules, err := config.LoadSiteRules(cfg)
	if err != nil {
		log.Fatalf("Load site rules failed: %v", err)
	}

	//allocate shared memory
	maxSpeedLimitTime := int64(0)
	maxSameURILimitTime := int64(0)
	maxFailureLimitTime := int64(0)
	maxCaptchaFailureLimitTime := int64(0)
	for _, rules := range siteRules {
		speedTime := utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodSpeedLimit)
		uriTime := utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodSameURILimit)
		failureTime := utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodFailureLimit)
		if speedTime > maxSpeedLimitTime {
			maxSpeedLimitTime = speedTime
		}
		if uriTime > maxSameURILimitTime {
			maxSameURILimitTime = uriTime
		}
		if failureTime > maxFailureLimitTime {
			maxFailureLimitTime = failureTime
		}
		captchaFailureTime := utils.FindMaxRateTime(rules.CAPTCHARule.CaptchaFailureLimit)
		if captchaFailureTime > maxCaptchaFailureLimitTime {
			maxCaptchaFailureLimitTime = captchaFailureTime
		}
	}

	sharedMem := &dataType.SharedMemory{
		HTTPFloodSpeedLimitCounter:   dataType.NewCounter(max(runtime.NumCPU()*8, 16), maxSpeedLimitTime),
		HTTPFloodSameURILimitCounter: dataType.NewCounter(max(runtime.NumCPU()*8, 16), maxSameURILimitTime),
		HTTPFloodFailureLimitCounter: dataType.NewCounter(max(runtime.NumCPU()*8, 16), maxFailureLimitTime),
		CaptchaFailureLimitCounter:   dataType.NewCounter(max(runtime.NumCPU()*8, 16), maxCaptchaFailureLimitTime),
		BlockList:                    dataType.NewBlockList(),
		ActionRuleEngine:             action.NewActionRuleEngine(time.Minute),
	}

	//GC
	gcStopCh := make(chan struct{})
	go dataType.StartCounterGC(sharedMem.HTTPFloodSpeedLimitCounter, time.Minute, gcStopCh)
	go dataType.StartCounterGC(sharedMem.HTTPFloodSameURILimitCounter, time.Minute, gcStopCh)
	go dataType.StartCounterGC(sharedMem.HTTPFloodFailureLimitCounter, time.Minute, gcStopCh)
	go dataType.StartCounterGC(sharedMem.CaptchaFailureLimitCounter, time.Minute, gcStopCh)
	go dataType.StartBlockListGC(sharedMem.BlockList, time.Minute, gcStopCh)

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
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.StartServer(cfg, siteRules, sharedMem)
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
