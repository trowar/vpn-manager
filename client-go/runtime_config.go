package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ensureLocalProxyPortFree(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("本地代理端口 %s 已被占用，请关闭其它代理软件后重试", address)
	}
	return listener.Close()
}

func isLocalProxyPortListening(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 800*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func waitForLocalProxyPort(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isLocalProxyPortListening(address) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("SSH SOCKS 出口 %s 未启动", address)
}

func fetchConfig(profile Profile) (ConfigResult, error) {
	if strings.TrimSpace(profile.UpdateURL) == "" {
		return ConfigResult{Text: profile.Config, Server: profile.Server}, nil
	}
	req, err := http.NewRequest(http.MethodGet, profile.UpdateURL, nil)
	if err != nil {
		return ConfigResult{}, err
	}
	req.Header.Set("User-Agent", appName+"/1.0")
	req.Header.Set("Accept", "application/json,text/plain,*/*")
	for key, value := range profile.Headers {
		req.Header.Set(key, value)
	}
	applyClientRequestAuth(req, profile.UpdateToken)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ConfigResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ConfigResult{}, err
	}
	if decoded, err := decryptClientAPIResponse(body, profile.UpdateToken); err == nil {
		body = decoded
	} else {
		return ConfigResult{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ConfigResult{}, fmt.Errorf("服务器返回 %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	text := string(body)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") || strings.HasPrefix(strings.TrimSpace(text), "{") {
		var payload ConfigResponse
		if err := json.Unmarshal(body, &payload); err == nil {
			if !payload.OK && payload.Error != "" {
				return ConfigResult{}, errors.New(payload.Error)
			}
			config := firstNonEmpty(payload.Config, payload.Profile, payload.Content)
			if strings.TrimSpace(config) != "" {
				return ConfigResult{Text: config, Server: firstServerInfo(payload.Server, profile.Server)}, nil
			}
		}
	}
	if strings.TrimSpace(text) == "" {
		return ConfigResult{}, errors.New("服务器返回了空配置")
	}
	return ConfigResult{Text: text, Server: profile.Server}, nil
}

func writeRuntimeConfig(bundle Bootstrap, profile Profile, configText string) (string, error) {
	dir, err := appDir()
	if err != nil {
		return "", err
	}
	ext := ".yaml"
	if profile.Type == "openvpn" {
		ext = ".ovpn"
	} else if normalizeType(profile.Type) == "ssh-tunnel" {
		ext = ".json"
	}
	path := filepath.Join(dir, ".company-vpn-runtime-"+safeName(bundle.ID+"-"+profile.ID)+ext)
	if err := os.WriteFile(path, []byte(configText), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func runtimeConfigFiles(configPath string, profile Profile) []string {
	return []string{configPath}
}

func cleanupRuntimeFiles(paths []string) {
	for _, path := range paths {
		clean := strings.TrimSpace(path)
		if clean == "" {
			continue
		}
		if err := os.Remove(clean); err != nil && !os.IsNotExist(err) {
			appendLog("删除临时配置失败: " + err.Error())
		}
	}
}

func systemProxyServerForProfile(profile Profile) string {
	if normalizeType(profile.Type) == "ssh-tunnel" {
		return "socks=127.0.0.1:7890"
	}
	return "127.0.0.1:7890"
}
