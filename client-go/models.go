package main

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"sync"

	"golang.org/x/crypto/ssh"
)

const appName = "CompanyVPN"
const hiddenStateFileName = ".company-vpn.json"

var embeddedDefaultWebURL = ""
var embeddedClientCryptoKey = "company-vpn-global-client-key-v1-20260621"
var embeddedClientVersion = "client-dev"

type Bootstrap struct {
	Schema      string     `json:"schema"`
	Name        string     `json:"name"`
	Account     string     `json:"account"`
	WebURL      string     `json:"web_url,omitempty"`
	ImportedAt  int64      `json:"imported_at,omitempty"`
	ID          string     `json:"id,omitempty"`
	UpdateURL   string     `json:"bootstrap_update_url,omitempty"`
	UpdateToken string     `json:"update_token,omitempty"`
	Server      ServerInfo `json:"server,omitempty"`
	Profiles    []Profile  `json:"profiles"`
}

type Profile struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Config      string            `json:"config,omitempty"`
	UpdateURL   string            `json:"update_url,omitempty"`
	OnlineURL   string            `json:"online_url,omitempty"`
	UpdateToken string            `json:"update_token,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Server      ServerInfo        `json:"server,omitempty"`
}

type ServerInfo struct {
	ID                  int    `json:"id,omitempty"`
	ServerName          string `json:"server_name,omitempty"`
	ServerRegion        string `json:"server_region,omitempty"`
	ServerRegionDisplay string `json:"server_region_display,omitempty"`
	Host                string `json:"host,omitempty"`
	EndpointHost        string `json:"endpoint_host,omitempty"`
	DisplayName         string `json:"display_name,omitempty"`
	OpenVPNEnabled      bool   `json:"openvpn_enabled,omitempty"`
	ShadowsocksEnabled  bool   `json:"shadowsocks_enabled,omitempty"`
	KcptunEnabled       bool   `json:"kcptun_enabled,omitempty"`
	SSHTunnelEnabled    bool   `json:"ssh_tunnel_enabled,omitempty"`
}

type State struct {
	SavedLogin SavedLogin `json:"saved_login,omitempty"`
}

type SavedLogin struct {
	WebURL            string `json:"web_url,omitempty"`
	Username          string `json:"username,omitempty"`
	EncryptedPassword string `json:"encrypted_password,omitempty"`
	RememberPassword  bool   `json:"remember_password,omitempty"`
}

type LatestClientResponse struct {
	OK          bool   `json:"ok"`
	Version     string `json:"version"`
	Filename    string `json:"filename"`
	DownloadURL string `json:"download_url"`
}

type ConfigResponse struct {
	OK        bool       `json:"ok"`
	Error     string     `json:"error"`
	Encrypted string     `json:"encrypted"`
	Nonce     string     `json:"nonce"`
	Payload   string     `json:"payload"`
	Type      string     `json:"type"`
	Filename  string     `json:"filename"`
	Config    string     `json:"config"`
	Profile   string     `json:"profile"`
	Content   string     `json:"content"`
	Server    ServerInfo `json:"server,omitempty"`
}

type LoginRequest struct {
	WebURL   string `json:"web_url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type TimeResponse struct {
	OK         bool   `json:"ok"`
	ServerTime int64  `json:"server_time"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
}

type ConfigResult struct {
	Text   string
	Server ServerInfo
}

type TrafficCounters struct {
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

type SSHTunnelConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	PrivateKey   string `json:"private_key"`
	LocalSocks   string `json:"local_socks"`
	CleanupURL   string `json:"cleanup_url"`
	CleanupToken string `json:"cleanup_token"`
}

type webRuntime struct {
	mu              sync.Mutex
	process         *exec.Cmd
	sshTunnel       *sshTunnelRuntime
	virtualTunnel   *virtualTunnelRuntime
	logs            []string
	status          string
	systemProxy     bool
	runtimeFiles    []string
	heartbeatCancel context.CancelFunc
	trafficStart    TrafficCounters
	trafficNow      TrafficCounters
}

type sshTunnelRuntime struct {
	client   *ssh.Client
	listener net.Listener
	done     chan struct{}
	once     sync.Once
}

var (
	runtimeState          = &webRuntime{status: "未连接"}
	complexLogTimePattern = regexp.MustCompile(`time="[0-9]{4}-[0-9]{2}-[0-9]{2}T[^"]+"`)
	runtimeBundlesMu      sync.RWMutex
	runtimeBundles        []Bootstrap
)
