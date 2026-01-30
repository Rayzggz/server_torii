package server

import (
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Regex for Nginx Combined Log Format
// Format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
// Example: 127.0.0.1 - - [28/Jan/2026:19:50:24 -0500] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0..."
var nginxLogRegex = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[[^]]+]\s+"([^"]*)"\s+(\d{3})\s+`)

const (
	syslogBufferSize = 10000
	syslogWorkers    = 20
)

// StartSyslogUDPListener starts a UDP listener for Syslog messages
func StartSyslogUDPListener(port string, analyzer *AdaptiveTrafficAnalyzer) error {
	udpAddr, err := net.ResolveUDPAddr("udp", ":"+port)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	// defer conn.Close() // Should run until server resumes
	// Note: Not closing the connection to allow the server to continue running

	log.Printf("Syslog UDP Listener started on port %s", port)

	// Create a buffered channel to hold incoming messages
	logChan := make(chan string, syslogBufferSize)

	// Start worker pool
	for i := 0; i < syslogWorkers; i++ {
		go func() {
			for msg := range logChan {
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("[Recovered] Syslog worker panic: %v", r)
						}
					}()
					parseAndSubmitLog(msg, analyzer)
				}()
			}
		}()
	}

	buf := make([]byte, 64*1024) // 64KB buffer for UDP packets
	for {
		// ReadFromUDP can read a packet
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		message := string(buf[:n])

		// Non-blocking send to channel
		select {
		case logChan <- message:
			// Message queued successfully
		default:
			// Channel is full, drop the message
		}
	}
}

// parseAndSubmitLog parses the raw log message and submits it to the analyzer
// Supports standard Nginx Syslog format (RFC 3164) with Combined Log Format body.
// Example: <190>Jan 28 19:50:24 hostname tag[123]: 1.2.3.4 - - ...
func parseAndSubmitLog(message string, analyzer *AdaptiveTrafficAnalyzer) {
	// 1. Parse Syslog Header to extract Tag
	// Syslog content usually ends with ": " before the message body begins.
	// We look for the last occurrence of ": " before the IP address starts, or just first ": ".
	// A robust heuristic for Nginx syslog is looking for the "tag[" or "tag:" pattern.

	// Find the start of the actual log message (Nginx Combined format starts with IP)
	// We scan for the first part that looks like an IP address, but regex does this too.

	// Split logic: explicitly find the "tag: " or "tag[pid]: " terminator.
	// Standard Nginx syslog: "... tag: content"

	splitIdx := strings.Index(message, ": ")
	if splitIdx == -1 {
		return
	}

	header := message[:splitIdx]
	body := strings.TrimSpace(message[splitIdx+2:])

	// Extract Tag from header (last word before colon)
	// Header example: "<190>Jan 28 19:50:24 hostname my-tag"
	// We take the last field.
	headerFields := strings.Fields(header)
	if len(headerFields) == 0 {
		return
	}
	rawTag := headerFields[len(headerFields)-1]

	// Clean tag (remove [pid] if present) e.g., "nginx[1234]" -> "nginx"
	tag := rawTag
	if bracketIdx := strings.Index(tag, "["); bracketIdx != -1 {
		tag = tag[:bracketIdx]
	}

	// 2. Validate Tag - Discard if no rule exists
	if analyzer.findRuleByTag(tag) == nil {
		return
	}

	// 3. Parse Message Body (Nginx Combined Log) for IP and Status
	matches := nginxLogRegex.FindStringSubmatch(body)
	if len(matches) < 4 {
		return
	}

	ip := matches[1]
	request := matches[2]
	statusStr := matches[3]

	// Extract URI from Request Line (e.g., "GET /foo HTTP/1.1")
	uri := ""
	reqFields := strings.Fields(request)
	if len(reqFields) >= 2 {
		uri = reqFields[1]
	}

	status, err := strconv.Atoi(statusStr)
	if err != nil {
		return
	}

	logEntry := LogEntry{
		Tag:       tag,
		IP:        ip,
		URI:       uri,
		Status:    status,
		Timestamp: time.Now().Unix(),
	}

	analyzer.AddLog(logEntry)
}
