package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func findExecutable(name string, extraPaths []string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	exePath, _ := os.Executable()
	base := filepath.Dir(exePath)
	candidates := []string{
		filepath.Join(base, name),
		filepath.Join(base, "cores", name),
	}
	candidates = append(candidates, extraPaths...)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func normalizeType(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "ovpn":
		return "openvpn"
	case "ss", "shadowsocks", "ss-kcptun", "kcptun", "mihomo":
		return "clash"
	case "ssh", "ssh-tunnel", "tunnel":
		return "ssh-tunnel"
	default:
		return v
	}
}

func safeName(value string) string {
	var buf bytes.Buffer
	for _, r := range strings.TrimSpace(value) {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			buf.WriteRune(r)
		} else {
			buf.WriteRune('_')
		}
	}
	clean := strings.Trim(buf.String(), "._")
	if clean == "" {
		return "profile"
	}
	return clean
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstServerInfo(values ...ServerInfo) ServerInfo {
	for _, value := range values {
		if !isEmptyServerInfo(value) {
			return value
		}
	}
	return ServerInfo{}
}

func isEmptyServerInfo(server ServerInfo) bool {
	return server.ID == 0 &&
		strings.TrimSpace(server.DisplayName) == "" &&
		strings.TrimSpace(server.ServerName) == "" &&
		strings.TrimSpace(server.EndpointHost) == "" &&
		strings.TrimSpace(server.Host) == ""
}

func formatServerInfo(server ServerInfo) string {
	if isEmptyServerInfo(server) {
		return "-"
	}
	name := firstNonEmpty(server.DisplayName, server.ServerName, server.EndpointHost, server.Host)
	host := firstNonEmpty(server.EndpointHost, server.Host)
	region := firstNonEmpty(server.ServerRegionDisplay, server.ServerRegion)
	parts := []string{name}
	if host != "" && host != name {
		parts = append(parts, host)
	}
	if region != "" && region != "未识别" && !strings.Contains(name, region) {
		parts = append(parts, region)
	}
	return strings.Join(parts, " / ")
}

func formatBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	n := float64(value)
	for _, suffix := range units {
		n = n / unit
		if n < unit {
			return fmt.Sprintf("%.2f %s", n, suffix)
		}
	}
	return fmt.Sprintf("%.2f EB", n/unit)
}

func deploymentLabel(profile Profile, server ServerInfo) string {
	switch normalizeType(profile.Type) {
	case "openvpn":
		return "OpenVPN"
	case "clash":
		if server.ShadowsocksEnabled && server.KcptunEnabled {
			return "SS+KCPTUN"
		}
		return "SS"
	case "ssh-tunnel":
		return "SSH Tunnel"
	default:
		return firstNonEmpty(profile.Type, "-")
	}
}

func displayProfileLabel(bundle Bootstrap, profile Profile) string {
	server := firstServerInfo(profile.Server, bundle.Server)
	return strings.Join([]string{
		firstNonEmpty(bundle.Account, bundle.Name, "-"),
		formatServerInfo(server),
		deploymentLabel(profile, server),
	}, " / ")
}
