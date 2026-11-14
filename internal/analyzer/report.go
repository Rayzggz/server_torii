package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"server_torii/internal/config"
	"server_torii/internal/sockfile"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Request reports.
//
// The connector tells Torii about every request it has finished serving, in one datagram per
// request holding one JSON object. Torii only sees a request before it is served; the report
// adds what happened to it. Fields that are empty or zero are left out by the sender.
//
//	v          format version, 1
//	ts         when the request ended, in milliseconds since the Unix epoch
//	site       ID of the site; empty means the default site
//	ip         client address
//	host       host the client asked for
//	method     request method
//	uri        request URI as the client sent it
//	status     response status
//	decision   Torii's decision for the request; empty when the request was not checked
//	reason     the check that ended the pipeline
//	ua         User-Agent
//	referer    Referer
//	proto      protocol, such as "HTTP/2.0"
//	conn_reqs  number of requests made over the connection so far
//	fetch      Sec-Fetch-Dest, -Mode and -Site joined by "/"
//	lang       whether the client sent Accept-Language
//	ctype      Content-Type of the response
//	rt         time taken to serve the request, in milliseconds
//	urt        time the upstream took, in milliseconds
//	ustatus    status the upstream answered with
//	cache      upstream cache status, such as "HIT"
//	bytes      size of the response body sent
//	req_len    size of the request
const reportVersion = 1

// report is the wire form of a request report.
type report struct {
	Version        int    `json:"v"`
	Timestamp      int64  `json:"ts"`
	Site           string `json:"site"`
	IP             string `json:"ip"`
	Host           string `json:"host"`
	Method         string `json:"method"`
	URI            string `json:"uri"`
	Status         int    `json:"status"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	UserAgent      string `json:"ua"`
	Referer        string `json:"referer"`
	Proto          string `json:"proto"`
	ConnRequests   int64  `json:"conn_reqs"`
	Fetch          string `json:"fetch"`
	Lang           bool   `json:"lang"`
	ContentType    string `json:"ctype"`
	RequestTime    int64  `json:"rt"`
	UpstreamTime   int64  `json:"urt"`
	UpstreamStatus int    `json:"ustatus"`
	Cache          string `json:"cache"`
	Bytes          int64  `json:"bytes"`
	RequestLength  int64  `json:"req_len"`
}

// parseReport decodes one datagram. Anything before the JSON object is ignored, so a sender may
// put a syslog header in front of it. The site is left as sent: resolving it needs the configuration.
func parseReport(data []byte) (LogEntry, error) {
	start := bytes.IndexByte(data, '{')
	if start < 0 {
		return LogEntry{}, fmt.Errorf("no JSON object")
	}
	var r report
	if err := json.Unmarshal(data[start:], &r); err != nil {
		return LogEntry{}, err
	}
	switch {
	case r.Version != reportVersion:
		return LogEntry{}, fmt.Errorf("unsupported version %d", r.Version)
	case r.IP == "":
		return LogEntry{}, fmt.Errorf("no client address")
	case r.Status < 0 || r.Status > 999:
		return LogEntry{}, fmt.Errorf("invalid status %d", r.Status)
	case r.Site != "" && !config.ValidSiteID(r.Site):
		return LogEntry{}, fmt.Errorf("invalid site")
	}
	return LogEntry{
		Site:           r.Site,
		IP:             r.IP,
		URI:            r.URI,
		Status:         r.Status,
		Timestamp:      r.Timestamp,
		Host:           r.Host,
		Method:         r.Method,
		Decision:       r.Decision,
		Reason:         r.Reason,
		UserAgent:      r.UserAgent,
		Referer:        r.Referer,
		Proto:          r.Proto,
		ConnRequests:   r.ConnRequests,
		Fetch:          r.Fetch,
		HasLanguage:    r.Lang,
		ContentType:    r.ContentType,
		RequestTime:    time.Duration(r.RequestTime) * time.Millisecond,
		UpstreamTime:   time.Duration(r.UpstreamTime) * time.Millisecond,
		UpstreamStatus: r.UpstreamStatus,
		Cache:          r.Cache,
		Bytes:          r.Bytes,
		RequestLength:  r.RequestLength,
	}, nil
}

const (
	reportBufferSize = 10000
	reportWorkers    = 20
	// reportMaxSize bounds one datagram. The connector keeps a report well below it.
	reportMaxSize = 64 * 1024
)

// ReportStats counts what happened to the datagrams a ReportListener received.
type ReportStats struct {
	Received  uint64 // datagrams read
	Accepted  uint64 // reports handed to the analyzer
	Malformed uint64 // not a valid report
	Unknown   uint64 // for a site that does not exist or has traffic analysis switched off
	Dropped   uint64 // discarded because the queue was full
}

// ReportListener receives request reports on UDP and Unix datagram sockets.
type ReportListener struct {
	addrs      []string
	socketMode os.FileMode
	analyzer   *AdaptiveTrafficAnalyzer

	conns    []net.PacketConn
	stopChan chan struct{}
	readers  sync.WaitGroup
	workers  sync.WaitGroup
	queue    chan []byte

	received, accepted, malformed, unknown, dropped atomic.Uint64
}

// NewReportListener creates a listener for the given addresses: "host:port" for UDP, or
// "unix:/path" for a Unix datagram socket, which is given socketMode.
func NewReportListener(addrs []string, socketMode os.FileMode, analyzer *AdaptiveTrafficAnalyzer) *ReportListener {
	return &ReportListener{
		addrs:      addrs,
		socketMode: socketMode,
		analyzer:   analyzer,
		stopChan:   make(chan struct{}),
		queue:      make(chan []byte, reportBufferSize),
	}
}

// Stats returns how many datagrams were received and what became of them.
func (l *ReportListener) Stats() ReportStats {
	if l == nil {
		return ReportStats{}
	}
	return ReportStats{
		Received:  l.received.Load(),
		Accepted:  l.accepted.Load(),
		Malformed: l.malformed.Load(),
		Unknown:   l.unknown.Load(),
		Dropped:   l.dropped.Load(),
	}
}

func (l *ReportListener) listen(addr string) (net.PacketConn, error) {
	path, isUnix := strings.CutPrefix(addr, config.UnixListenPrefix)
	if !isUnix {
		return net.ListenPacket("udp", addr)
	}
	if path == "" {
		return nil, fmt.Errorf("listen address %q has no socket path", addr)
	}
	if err := sockfile.RemoveStale("unixgram", path); err != nil {
		return nil, err
	}
	conn, err := net.ListenPacket("unixgram", path)
	if err != nil {
		return nil, err
	}
	// The connector usually runs as another user (the nginx worker).
	if err := os.Chmod(path, l.socketMode); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set mode of socket %s: %w", path, err)
	}
	return conn, nil
}

// Start opens every address and starts receiving. On failure nothing is left open.
func (l *ReportListener) Start() error {
	for _, addr := range l.addrs {
		conn, err := l.listen(addr)
		if err != nil {
			l.closeConns()
			return fmt.Errorf("listen for request reports on %s: %w", addr, err)
		}
		l.conns = append(l.conns, conn)
		log.Printf("Request report listener started on %s", conn.LocalAddr())
	}

	for i := 0; i < reportWorkers; i++ {
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			for data := range l.queue {
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("[Recovered] Request report worker panic: %v", r)
						}
					}()
					l.handle(data)
				}()
			}
		}()
	}

	for _, conn := range l.conns {
		l.readers.Add(1)
		go l.read(conn)
	}
	return nil
}

func (l *ReportListener) read(conn net.PacketConn) {
	defer l.readers.Done()
	buf := make([]byte, reportMaxSize)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-l.stopChan:
				return
			default:
				log.Printf("Error reading request report: %v", err)
				continue
			}
		}
		l.received.Add(1)
		select {
		case l.queue <- append([]byte(nil), buf[:n]...):
		default:
			l.dropped.Add(1)
		}
	}
}

func (l *ReportListener) handle(data []byte) {
	entry, err := parseReport(data)
	if err != nil {
		l.malformed.Add(1)
		return
	}
	if !l.analyzer.submit(entry) {
		l.unknown.Add(1)
		return
	}
	l.accepted.Add(1)
}

func (l *ReportListener) closeConns() {
	for _, conn := range l.conns {
		addr, isUnix := conn.LocalAddr().(*net.UnixAddr)
		_ = conn.Close()
		// A Unix socket file is not removed when its connection is closed.
		if isUnix && addr.Name != "" {
			_ = os.Remove(addr.Name)
		}
	}
	l.conns = nil
}

// Stop closes the sockets and waits for the reports already received to be handled.
func (l *ReportListener) Stop() {
	close(l.stopChan)
	l.closeConns()
	l.readers.Wait()
	close(l.queue)
	l.workers.Wait()
}
