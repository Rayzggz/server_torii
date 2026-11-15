package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/geoip"
	"server_torii/internal/gossip"
	"server_torii/internal/logx"
	"server_torii/internal/server"
	"server_torii/internal/state"
	"server_torii/internal/version"
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

	// Until the log files are open, and for what stops the node from starting, stderr is the log.
	cfg, err := config.LoadMainConfig(inputConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logs, err := logx.Open(cfg.LogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open the log files: %v\n", err)
		return 1
	}
	defer func() { _ = logs.Close() }()
	logger := logs.Node()
	setLogLevel(logs, cfg)
	fatal := func(msg string, err error) int {
		logger.Error(msg, "error", err.Error())
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
		return 1
	}

	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()

	countryDatabase := geoip.NewCountryDatabase(
		filepath.Join(cfg.ConfigDir, "data", "GeoLite2-Country.mmdb"), logger,
	)
	defer countryDatabase.CloseOrWarn()

	rt := &state.Runtime{
		ActionRuleEngine: engine,
		CountryResolver:  countryDatabase,
		Crawlers:         check.NewCrawlerVerifier(logger),
		Logs:             logs,
	}

	// The rate counters must cover the new limits before any request sees the new rules.
	configs := config.NewManager()
	reload := func() error {
		err := configs.Reload(cfg, func(snap *config.SiteConfigSnapshot) {
			rt.ResizeSites(snap.CounterWindows())
			for _, warning := range snap.Warnings {
				logger.Warn(warning)
			}
		})
		if err == nil {
			logger.Info("site configuration loaded", "sites", len(cfg.Sites))
		}
		return err
	}
	if err := reload(); err != nil {
		return fatal("failed to load the site configuration", err)
	}

	var gossipManager *gossip.Manager
	if cfg.EnableGossip {
		gossipManager = gossip.NewManager(cfg, engine, logger)
		rt.Peers = gossipManager
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if gossipManager != nil {
		go gossipManager.Start(ctx)
		defer gossipManager.Stop()
	}

	go rt.RunGC(ctx, time.Minute)

	// Started and stopped are written at every level: a log that is otherwise empty, as it
	// should be at the error level, still says when the node ran.
	logs.Notice("started", "version", version.Version, "node", cfg.NodeName, "listen", strings.Join(cfg.Listen, ", "), "log_level", cfg.LogLevel)

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
				// Log rotation renames the files and sends SIGHUP: the log goes on in new ones.
				if err := logs.Reopen(); err != nil {
					logger.Error("log files not opened again", "error", err.Error())
				}
				logger.Info("reloading")
				// Of the main configuration only the log level is read again.
				if again, err := config.LoadMainConfig(inputConfigPath); err != nil {
					logger.Error("main configuration not read again; the log level stays as it is", "error", err.Error())
				} else if again.LogLevel != cfg.LogLevel {
					cfg.LogLevel = again.LogLevel
					setLogLevel(logs, cfg)
					logs.Notice("log level changed", "log_level", cfg.LogLevel)
				}
				countryDatabase.ReloadOrWarn()
				if err := reload(); err != nil {
					logger.Error("reload failed; the previous site configuration stays in use", "error", err.Error())
				}
				continue
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("stopping", "signal", sig.String())
				cancel()
				// Wait for Run to finish Shutdown and run its defers.
				if err := <-serverErr; err != nil {
					return fatal("server stopped with an error", err)
				}
				logs.Notice("stopped")
				return 0
			}
		case err := <-serverErr:
			if err != nil {
				return fatal("server failed", err)
			}
			logs.Notice("stopped")
			return 0
		}
	}
}

// setLogLevel applies the log level of the configuration, which validation has checked.
func setLogLevel(logs *logx.Logs, cfg *config.MainConfig) {
	if level, err := logx.ParseLevel(cfg.LogLevel); err == nil {
		logs.SetLevel(level)
	}
}

// runCheckConfig loads the configuration the way the server does at start and on reload: the
// main file, the rules of every site with the list files they name, and the error pages. It
// starts nothing and writes nothing but its verdict.
func runCheckConfig(path string) int {
	cfg, err := config.LoadMainConfig(path)
	var snap *config.SiteConfigSnapshot
	if err == nil {
		snap, err = config.LoadSnapshot(cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, warning := range snap.Warnings {
		fmt.Fprintln(os.Stderr, "warning: "+warning)
	}
	fmt.Printf("configuration OK: %d sites\n", len(cfg.Sites))
	return 0
}
