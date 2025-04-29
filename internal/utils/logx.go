package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"server_torii/internal/dataType"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type LogxManager struct {
	basePath string
	loggers  map[string]*zap.Logger
	mu       sync.RWMutex
}

func NewManager(base string) *LogxManager {
	m := &LogxManager{basePath: base, loggers: make(map[string]*zap.Logger)}

	if err := os.MkdirAll(m.basePath, 0744); err != nil {
		log.Printf("failed to create base log dir %s: %v", m.basePath, err)
	}
	return m
}

func (m *LogxManager) getLogger(host string) *zap.Logger {
	m.mu.RLock()
	if lg, ok := m.loggers[host]; ok {
		m.mu.RUnlock()
		return lg
	}
	m.mu.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	dir := filepath.Join(m.basePath, host)
	if err := os.MkdirAll(dir, 0744); err != nil {
		log.Printf("failed to create log dir %s: %v", dir, err)
	}

	encCfg := zapcore.EncoderConfig{MessageKey: "msg", LineEnding: zapcore.DefaultLineEnding}
	encoder := zapcore.NewConsoleEncoder(encCfg)

	infoOut := zapcore.AddSync(m.openLogFile(filepath.Join(dir, "info.log")))
	errorOut := zapcore.AddSync(m.openLogFile(filepath.Join(dir, "error.log")))
	dbgOut := zapcore.AddSync(m.openLogFile(filepath.Join(dir, "debug.log")))

	infoLv := zap.LevelEnablerFunc(func(l zapcore.Level) bool { return l == zapcore.InfoLevel })
	errLv := zap.LevelEnablerFunc(func(l zapcore.Level) bool { return l >= zapcore.ErrorLevel })
	dbgLv := zap.LevelEnablerFunc(func(l zapcore.Level) bool { return l == zapcore.DebugLevel })

	tee := zapcore.NewTee(
		zapcore.NewCore(encoder, infoOut, infoLv),
		zapcore.NewCore(encoder, errorOut, errLv),
		zapcore.NewCore(encoder, dbgOut, dbgLv),
	)
	lg := zap.New(tee)
	m.loggers[host] = lg
	return lg
}

func (m *LogxManager) openLogFile(path string) *os.File {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open log file %s: %v", path, err)
		return os.Stdout
	}
	return f
}

func (m *LogxManager) LogInfo(reqData dataType.UserRequest, msg, msg2 string) {
	lg := m.getLogger(reqData.Host)
	line := fmt.Sprintf("%s - - [%s] %s %s %s %s %s",
		reqData.RemoteIP,
		time.Now().Format("02/Jan/2006:15:04:05 -0700"),
		msg,
		reqData.Host,
		reqData.Uri,
		reqData.UserAgent,
		msg2,
	)
	lg.Info(line)
}

func (m *LogxManager) LogError(reqData dataType.UserRequest, msg, msg2 string) {
	lg := m.getLogger(reqData.Host)
	line := fmt.Sprintf("%s - - [%s] %s %s %s %s %s",
		reqData.RemoteIP,
		time.Now().Format("02/Jan/2006:15:04:05 -0700"),
		msg,
		reqData.Host,
		reqData.Uri,
		reqData.UserAgent,
		msg2,
	)
	lg.Error(line)
}

func (m *LogxManager) LogDebug(reqData dataType.UserRequest, msg, msg2 string) {
	lg := m.getLogger(reqData.Host)
	line := fmt.Sprintf("%s - - [%s] %s %s %s %s %s",
		reqData.RemoteIP,
		time.Now().Format("02/Jan/2006:15:04:05 -0700"),
		msg,
		reqData.Host,
		reqData.Uri,
		reqData.UserAgent,
		msg2,
	)
	lg.Debug(line)
}
