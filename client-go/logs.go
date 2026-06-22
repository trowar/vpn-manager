package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

func appendLog(line string) {
	clean := strings.TrimRight(line, "\r\n")
	if clean == "" {
		return
	}
	entry := time.Now().Format("2006-01-02 15:04:05") + "  " + simplifyLogLineTime(clean)
	runtimeState.mu.Lock()
	runtimeState.logs = append(runtimeState.logs, entry)
	if len(runtimeState.logs) > 400 {
		runtimeState.logs = runtimeState.logs[len(runtimeState.logs)-400:]
	}
	runtimeState.mu.Unlock()
	writeClientLogFile(entry)
}

func writeClientLogFile(entry string) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	logDir := filepath.Join(filepath.Dir(exePath), "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return
	}
	logPath := filepath.Join(logDir, time.Now().Format("2006-0102")+".log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(entry + "\r\n")
}

func simplifyLogLineTime(line string) string {
	if !strings.Contains(line, `time="`) {
		return line
	}
	clean := complexLogTimePattern.ReplaceAllString(line, "")
	clean = strings.TrimSpace(clean)
	return strings.Join(strings.Fields(clean), " ")
}
