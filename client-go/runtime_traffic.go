package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func refreshTrafficCounters() TrafficCounters {
	current, err := readNetworkTrafficCounters()
	if err != nil {
		return currentTrafficSnapshot()
	}
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	if (runtimeState.process == nil || runtimeState.process.Process == nil) && runtimeState.sshTunnel == nil && runtimeState.virtualTunnel == nil {
		return runtimeState.trafficNow
	}
	start := runtimeState.trafficStart
	runtimeState.trafficNow = TrafficCounters{
		RxBytes: subtractCounter(current.RxBytes, start.RxBytes),
		TxBytes: subtractCounter(current.TxBytes, start.TxBytes),
	}
	return runtimeState.trafficNow
}

func startClientOnlineHeartbeat(bundle Bootstrap, profile Profile, server ServerInfo) context.CancelFunc {
	onlineURL := profileOnlineURL(profile)
	if strings.TrimSpace(onlineURL) == "" || strings.TrimSpace(profile.UpdateToken) == "" {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sendClientOnlineHeartbeat(ctx, bundle, profile, server, "online")
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendClientOnlineHeartbeat(ctx, bundle, profile, server, "online")
			case <-ctx.Done():
				offlineCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				sendClientOnlineHeartbeat(offlineCtx, bundle, profile, server, "offline")
				stop()
				return
			}
		}
	}()
	return cancel
}

func sendClientOnlineHeartbeat(ctx context.Context, bundle Bootstrap, profile Profile, server ServerInfo, status string) {
	onlineURL := profileOnlineURL(profile)
	if strings.TrimSpace(onlineURL) == "" || strings.TrimSpace(profile.UpdateToken) == "" {
		return
	}
	traffic := currentTrafficSnapshot()
	if status == "online" {
		traffic = refreshTrafficCounters()
	}
	serverInfo := firstServerInfo(server, profile.Server, bundle.Server)
	payload := map[string]any{
		"status":       status,
		"profile_type": normalizeType(profile.Type),
		"profile_id":   profile.ID,
		"profile_name": profile.Name,
		"server_id":    serverInfo.ID,
		"server_host":  firstNonEmpty(serverInfo.EndpointHost, serverInfo.Host, serverInfo.DisplayName),
		"rx_bytes":     traffic.RxBytes,
		"tx_bytes":     traffic.TxBytes,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, onlineURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", appName+"/1.0")
	applyClientRequestAuth(req, profile.UpdateToken)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if status == "online" && !errors.Is(err, context.Canceled) {
			appendLog("上报在线状态失败: " + err.Error())
		}
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if status == "online" && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		appendLog(fmt.Sprintf("上报在线状态失败: HTTP %d", resp.StatusCode))
	}
}

func profileOnlineURL(profile Profile) string {
	if strings.TrimSpace(profile.OnlineURL) != "" {
		return strings.TrimSpace(profile.OnlineURL)
	}
	raw := strings.TrimSpace(profile.UpdateURL)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "client-api" && parts[i+1] == "profiles" {
			username := parts[i+2]
			parsed.Path = "/client-api/online/" + username
			parsed.RawQuery = ""
			return parsed.String()
		}
	}
	return ""
}

func currentTrafficSnapshot() TrafficCounters {
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	return runtimeState.trafficNow
}

func subtractCounter(current, start uint64) uint64 {
	if current < start {
		return 0
	}
	return current - start
}
