package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
)

func launchWebUI() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/api/import", handleImport)
	mux.HandleFunc("/api/profiles", handleProfiles)
	mux.HandleFunc("/api/connect", handleConnect)
	mux.HandleFunc("/api/disconnect", handleDisconnect)
	mux.HandleFunc("/api/status", handleStatus)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	url := "http://" + listener.Addr().String() + "/"
	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	_ = openBrowser(url)
	fmt.Println("客户端界面:", url)
	select {}
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	file, header, err := r.FormFile("bundle")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请选择配置包"})
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	bundle, err := parseBootstrap(raw, header.Filename)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := storeBootstrap(bundle); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": bundle.Name})
}

func handleProfiles(w http.ResponseWriter, r *http.Request) {
	_ = refreshStoredBootstraps()
	type item struct {
		Key     string `json:"key"`
		Label   string `json:"label"`
		Type    string `json:"type"`
		Account string `json:"account"`
	}
	items := []item{}
	for _, bundle := range getRuntimeBundles() {
		for _, profile := range bundle.Profiles {
			label := displayProfileLabel(bundle, profile)
			key := bundle.Name + "/" + profile.Name
			items = append(items, item{
				Key:     key,
				Label:   label,
				Type:    profile.Type,
				Account: firstNonEmpty(bundle.Account, "-"),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "profiles": items})
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	target := strings.TrimSpace(r.FormValue("target"))
	if err := startProfileAsync(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	disconnectActiveConnection()
	appendLog("已发送断开命令")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func disconnectActiveConnection() {
	runtimeState.mu.Lock()
	cmd := runtimeState.process
	sshTunnel := runtimeState.sshTunnel
	virtualTunnel := runtimeState.virtualTunnel
	cancelHeartbeat := runtimeState.heartbeatCancel
	hasActiveRuntime := cmd != nil || sshTunnel != nil || virtualTunnel != nil
	runtimeState.heartbeatCancel = nil
	runtimeState.process = nil
	runtimeState.sshTunnel = nil
	runtimeState.virtualTunnel = nil
	if hasActiveRuntime {
		runtimeState.status = "正在断开"
	} else {
		runtimeState.status = "已断开"
	}
	runtimeState.runtimeFiles = nil
	runtimeState.trafficStart = TrafficCounters{}
	runtimeState.trafficNow = TrafficCounters{}
	runtimeState.mu.Unlock()
	ensureUIRefreshState()
	if cancelHeartbeat != nil {
		cancelHeartbeat()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if sshTunnel != nil {
		sshTunnel.Close()
	}
	if virtualTunnel != nil {
		virtualTunnel.Close()
	}
	closeSystemProxyIfEnabled()
}

func closeSystemProxyIfEnabled() {
	runtimeState.mu.Lock()
	enabled := runtimeState.systemProxy
	runtimeState.systemProxy = false
	runtimeState.mu.Unlock()
	if !enabled {
		return
	}
	if err := disableSystemProxy(); err != nil {
		appendLog("关闭系统代理失败: " + err.Error())
		return
	}
	appendLog("已关闭系统代理")
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	traffic := refreshTrafficCounters()
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	logs := append([]string{}, runtimeState.logs...)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"status":   runtimeState.status,
		"running":  (runtimeState.process != nil && runtimeState.process.Process != nil) || runtimeState.sshTunnel != nil || runtimeState.virtualTunnel != nil,
		"logs":     logs,
		"rx_bytes": traffic.RxBytes,
		"tx_bytes": traffic.TxBytes,
		"rx_human": formatBytes(traffic.RxBytes),
		"tx_human": formatBytes(traffic.TxBytes),
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
