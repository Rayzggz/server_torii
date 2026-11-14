package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"server_torii/internal/analyzer"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/gossip"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"strings"
	"sync/atomic"
	"time"
)

// HTTP server limits. Torii sits behind a reverse proxy and serves small
// check requests, so these can be tight; they exist mainly to
// stop slow-connection attacks (slowloris) from exhausting goroutines/FDs.
const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 10 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 120 * time.Second
	httpMaxHeaderBytes    = 64 << 10 // 64 KiB

	// shutdownTimeout bounds how long in-flight requests may take to finish
	// after a stop signal before connections are forcibly closed.
	shutdownTimeout = 10 * time.Second
)

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

// Server speaks the connector protocol to nginx and serves the endpoints of the node itself.
type Server struct {
	cfg     *config.MainConfig
	configs *config.Manager
	rt      *state.Runtime
	gossip  *gossip.Manager // nil when gossip is disabled
	// reports is the running request report listener, for the counters of the health check.
	reports atomic.Pointer[analyzer.ReportListener]
}

// NewServer wires a server to its configuration and shared state; gossip may be nil.
func NewServer(cfg *config.MainConfig, configs *config.Manager, rt *state.Runtime, gossipManager *gossip.Manager) *Server {
	return &Server{cfg: cfg, configs: configs, rt: rt, gossip: gossipManager}
}

// ServeHTTP dispatches a request: the connector protocol, and the endpoints of the node itself.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == v1CheckPath:
		s.serveV1Check(w, r)
	case strings.HasPrefix(r.URL.Path, v1PublicPrefix):
		s.serveV1Public(w, r)
	case r.URL.Path == s.cfg.WebPath+"/gossip" && s.cfg.EnableGossip && s.gossip != nil:
		s.gossip.HandleGossip(w, r)
	case r.URL.Path == s.cfg.WebPath+"/health_check":
		// Reachable without the connector, for monitoring and readiness probes.
		s.handleHealthCheck(w, request.UserRequest{})
	default:
		http.NotFound(w, r)
	}
}

// Run starts the HTTP server and blocks until it stops. When ctx is
// cancelled the server is shut down gracefully (in-flight requests get up to
// shutdownTimeout to finish) and the analyzer / syslog listener are stopped.
// A graceful stop returns nil.
func (s *Server) Run(ctx context.Context) error {
	// Start AdaptiveTrafficAnalyzer
	ata := analyzer.NewAdaptiveTrafficAnalyzer(s.rt, s.configs)
	s.rt.SetAnalyzer(ata)
	ata.Start()
	defer ata.Stop()

	// Request reports from the connector feed the traffic analyzer.
	reports := analyzer.NewReportListener(s.cfg.LogListenAddrs(), s.cfg.SocketMode(), ata)
	if err := reports.Start(); err != nil {
		log.Printf("[ERROR] Failed to start the request report listener: %v", err)
	} else {
		s.reports.Store(reports)
		defer func() {
			s.reports.Store(nil)
			reports.Stop()
		}()
	}

	listeners, err := listenAll(s.cfg.ListenAddrs(), s.cfg.SocketMode())
	if err != nil {
		return err
	}

	srv := newHTTPServer("", s)
	serveErr := make(chan error, len(listeners))
	for _, ln := range listeners {
		log.Printf("HTTP Server listening on %s ...", ln.Addr())
		go func() { serveErr <- srv.Serve(ln) }()
	}

	select {
	case err := <-serveErr:
		// One listener failed before any shutdown was requested; stop the others too.
		_ = srv.Close()
		return err
	case <-ctx.Done():
	}

	log.Println("Shutting down HTTP server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[WARNING] Graceful shutdown did not complete: %v; forcing close", err)
		_ = srv.Close()
	}
	var firstErr error
	for range listeners {
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func getHeader(r *http.Request, headerName string) string {
	cookie, err := r.Cookie(headerName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// configFeatureBits returns the feature control bits the site configuration turns on.
func configFeatureBits(ruleSet *config.RuleSet) uint16 {
	var bits uint16
	for _, c := range feature.Pipeline() {
		if ruleSet.FeatureEnabled(c) {
			bits |= c.ControlMask()
		}
	}
	return bits
}
