package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/geoip"
	"server_torii/internal/gossip"
	"server_torii/internal/logx"
	"server_torii/internal/server"
	"server_torii/internal/state"
	"strings"
	"syscall"
	"time"
)

func main() {
	// os.Exit skips deferred calls, so all real work lives in run() and its
	// defers (engine, GeoIP DB, log file, server shutdown) always execute.
	os.Exit(run())
}

func run() int {
	var inputConfigPath string
	var checkConfig bool
	flag.StringVar(&inputConfigPath, "config", "", "Config file base path")
	flag.BoolVar(&checkConfig, "check-config", false, "Check the configuration, report every problem and exit")
	flag.Parse()

	if checkConfig {
		return runCheckConfig(inputConfigPath)
	}

	// Load MainConfig
	cfg, err := config.LoadMainConfig(inputConfigPath)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return 1
	}

	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()

	countryDatabase := geoip.NewCountryDatabase(
		filepath.Join(cfg.ConfigDir, "data", "GeoLite2-Country.mmdb"),
	)
	defer countryDatabase.CloseOrWarn()

	rt := &state.Runtime{
		ActionRuleEngine: engine,
		CountryResolver:  countryDatabase,
		NodeName:         cfg.NodeName,
	}

	// The rate counters must cover the new limits before any request sees the new rules.
	configs := config.NewManager()
	reload := func() error {
		return configs.Reload(cfg, func(snap *config.SiteConfigSnapshot) {
			rt.ResizeSites(snap.CounterWindows())
		})
	}
	if err := reload(); err != nil {
		log.Printf("[ERROR] Failed to initialize config manager: %v", err)
		return 1
	}

	var gossipManager *gossip.Manager
	if cfg.EnableGossip {
		rt.GossipChan = make(chan gossip.Message, 1000)
		gossipManager = gossip.NewManager(cfg, engine)
		go gossipManager.Start(rt.GossipChan)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go rt.RunGC(ctx, time.Minute)

	// Initialize log system
	logx.Init(cfg.LogPath)

	log.Printf("Ready to start server on %s", strings.Join(cfg.Listen, ", "))

	closeLog, err := logToFile(filepath.Join(cfg.LogPath, "server_torii.log"))
	if err != nil {
		log.Printf("[ERROR] Failed to open log file: %v", err)
		return 1
	}
	defer closeLog()

	//log startup information and time
	log.Printf("%s - Server starting...", time.Now().Format(time.RFC3339))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(stop)

	srv := server.NewServer(cfg, configs, rt, gossipManager)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(ctx)
	}()

	for {
		select {
		case sig := <-stop:
			switch sig {
			case syscall.SIGHUP:
				log.Println("Reloading site rules...")
				countryDatabase.ReloadOrWarn()
				if err := reload(); err != nil {
					log.Printf("[ERROR] Reload failed: %v", err)
				}
				continue
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Received %v, stopping server...", sig)
				cancel()
				// Wait for Run to finish Shutdown and run its defers.
				if err := <-serverErr; err != nil {
					log.Printf("[ERROR] Server shutdown error: %v", err)
					return 1
				}
				log.Println("Server stopped")
				return 0
			}
		case err := <-serverErr:
			if err != nil {
				log.Printf("[ERROR] Failed to start server: %v", err)
				return 1
			}
			log.Println("Server stopped")
			return 0
		}
	}
}

// runCheckConfig loads the configuration the way the server does at start and on reload: the
// main file, the rules of every site with the list files they name, and the error pages. It
// starts nothing and writes nothing but its verdict.
func runCheckConfig(path string) int {
	cfg, err := config.LoadMainConfig(path)
	if err == nil {
		_, err = config.LoadSnapshot(cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("configuration OK: %d sites\n", len(cfg.Sites))
	return 0
}

// logToFile sends the standard logger to path. The returned function restores stderr and closes the file.
func logToFile(path string) (func(), error) {
	logFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return nil, err
	}
	log.SetOutput(logFile)
	return func() {
		log.SetOutput(os.Stderr)
		if err := logFile.Close(); err != nil {
			log.Printf("[WARNING] Failed to close log file: %v", err)
		}
	}, nil
}
