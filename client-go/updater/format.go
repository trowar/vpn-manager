package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func downloadSpeed(received int64, startedAt time.Time) int64 {
	elapsed := time.Since(startedAt).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return int64(float64(received) / elapsed)
}

func formatBytes(value int64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KB", "MB", "GB"}
	size := float64(value)
	for _, unit := range units {
		size /= 1024
		if size < 1024 || unit == "GB" {
			return fmt.Sprintf("%.1f %s", size, unit)
		}
	}
	return fmt.Sprintf("%d B", value)
}

func shortName(value string) string {
	value = filepath.Base(strings.TrimSpace(value))
	runes := []rune(value)
	if len(runes) <= 28 {
		return value
	}
	return string(runes[:10]) + "..." + string(runes[len(runes)-14:])
}

func safePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "latest"
	}
	replacer := strings.NewReplacer("\\", "-", "/", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-")
	return replacer.Replace(value)
}

func utf16Ptr(value string) *uint16 {
	ptr, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		ptr, _ = syscall.UTF16PtrFromString(strings.ReplaceAll(value, "\x00", ""))
	}
	return ptr
}
