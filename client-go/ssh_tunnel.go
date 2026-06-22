package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func parseSSHTunnelConfigText(configText string) (SSHTunnelConfig, error) {
	var cfg SSHTunnelConfig
	if err := json.Unmarshal([]byte(configText), &cfg); err != nil {
		return SSHTunnelConfig{}, fmt.Errorf("SSH Tunnel 配置格式无效: %w", err)
	}
	if strings.TrimSpace(cfg.LocalSocks) == "" {
		cfg.LocalSocks = "127.0.0.1:7890"
	}
	return cfg, nil
}

func startMemorySSHTunnel(cfg SSHTunnelConfig) (*sshTunnelRuntime, error) {
	host := strings.TrimSpace(cfg.Host)
	username := strings.TrimSpace(cfg.Username)
	privateKey := strings.TrimSpace(cfg.PrivateKey)
	localSocks := strings.TrimSpace(cfg.LocalSocks)
	if localSocks == "" {
		localSocks = "127.0.0.1:7890"
	}
	port := cfg.Port
	if port <= 0 || port > 65535 {
		port = 22
	}
	if host == "" || username == "" || privateKey == "" {
		return nil, errors.New("SSH Tunnel 配置不完整")
	}
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("SSH 私钥无效: %w", err)
	}
	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), sshConfig)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", localSocks)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	tunnel := &sshTunnelRuntime{
		client:   client,
		listener: listener,
		done:     make(chan struct{}),
	}
	go tunnel.acceptLoop()
	appendLog("内存 SSH SOCKS 已监听: " + localSocks)
	return tunnel, nil
}

func logSSHTunnelDiagnostics(tunnel *sshTunnelRuntime, cfg SSHTunnelConfig) {
	if tunnel == nil {
		return
	}
	if err := testSSHDirectTCP(tunnel, "www.baidu.com:443"); err != nil {
		appendLog("SSH 出口自检失败：www.baidu.com:443 " + err.Error())
	} else {
		appendLog("SSH 出口自检成功：www.baidu.com:443")
	}
	localSocks := strings.TrimSpace(cfg.LocalSocks)
	if localSocks == "" {
		localSocks = "127.0.0.1:7890"
	}
	if err := testLocalSOCKS5(localSocks, "www.baidu.com", 443); err != nil {
		appendLog("本地 SOCKS5 自检失败：" + err.Error())
	} else {
		appendLog("本地 SOCKS5 自检成功：www.baidu.com:443")
	}
}

func testSSHDirectTCP(tunnel *sshTunnelRuntime, target string) error {
	conn, err := tunnel.client.Dial("tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

func testLocalSOCKS5(address, host string, port uint16) error {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadlineErr := conn.SetDeadline(time.Now().Add(8 * time.Second)); deadlineErr != nil {
		return deadlineErr
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("握手失败: %v", reply)
	}
	hostBytes := []byte(host)
	if len(hostBytes) > 255 {
		return errors.New("目标域名过长")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hostBytes))}
	req = append(req, hostBytes...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("CONNECT 失败，状态码 %d", resp[1])
	}
	if err := discardSOCKSBindAddress(conn, resp[3]); err != nil {
		return err
	}
	return nil
}

func discardSOCKSBindAddress(conn net.Conn, addressType byte) error {
	switch addressType {
	case 0x01:
		buf := make([]byte, 4+2)
		_, err := io.ReadFull(conn, buf)
		return err
	case 0x03:
		size := make([]byte, 1)
		if _, err := io.ReadFull(conn, size); err != nil {
			return err
		}
		buf := make([]byte, int(size[0])+2)
		_, err := io.ReadFull(conn, buf)
		return err
	case 0x04:
		buf := make([]byte, 16+2)
		_, err := io.ReadFull(conn, buf)
		return err
	default:
		return fmt.Errorf("未知地址类型 %d", addressType)
	}
}

func (t *sshTunnelRuntime) Close() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		if t.listener != nil {
			_ = t.listener.Close()
		}
		if t.client != nil {
			_ = t.client.Close()
		}
		close(t.done)
	})
}

func (t *sshTunnelRuntime) acceptLoop() {
	defer t.Close()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}
		go t.handleSOCKSConn(conn)
	}
}

func (t *sshTunnelRuntime) handleSOCKSConn(conn net.Conn) {
	defer conn.Close()
	dest, err := readSOCKS5ConnectRequest(conn)
	if err != nil {
		return
	}
	remote, err := t.client.Dial("tcp", dest)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, remote)
		errCh <- err
	}()
	<-errCh
}

func readSOCKS5ConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != 0x05 {
		return "", errors.New("unsupported SOCKS version")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", err
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		return "", errors.New("only SOCKS5 CONNECT is supported")
	}
	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 0x03:
		size := make([]byte, 1)
		if _, err := io.ReadFull(conn, size); err != nil {
			return "", err
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	default:
		return "", errors.New("unsupported SOCKS address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func buildCommand(profile Profile, configPath string) (string, []string, error) {
	if strings.TrimSpace(profile.Command) != "" {
		return profile.Command, append([]string{}, profile.Args...), nil
	}
	if profile.Type == "openvpn" {
		command := findExecutable("openvpn.exe", []string{
			filepath.Join("C:\\", "Program Files", "OpenVPN", "bin", "openvpn.exe"),
		})
		if command == "" {
			return "", nil, errors.New("没有找到 openvpn.exe，请点击窗口里的“安装 OpenVPN 组件”完成安装")
		}
		return command, []string{"--config", configPath}, nil
	}
	command := findExecutable("mihomo.exe", nil)
	if command == "" {
		command = findExecutable("clash.exe", nil)
	}
	if command == "" {
		return "", nil, errors.New("没有找到 mihomo.exe 或 clash.exe，请把核心程序放到客户端同目录/cores 目录")
	}
	return command, []string{"-f", configPath}, nil
}

func cleanupSSHTunnelConfig(cfg SSHTunnelConfig) {
	cleanupURL := strings.TrimSpace(cfg.CleanupURL)
	cleanupToken := strings.TrimSpace(cfg.CleanupToken)
	if cleanupURL == "" || cleanupToken == "" {
		return
	}
	appendLog("正在清理 SSH 临时用户")
	req, err := http.NewRequest(http.MethodPost, cleanupURL, strings.NewReader(""))
	if err != nil {
		appendLog("创建 SSH 清理请求失败: " + err.Error())
		return
	}
	req.Header.Set("User-Agent", appName+"/1.0")
	req.Header.Set("Authorization", "Bearer "+cleanupToken)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		appendLog("清理 SSH 临时用户失败: " + err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		appendLog(fmt.Sprintf("清理 SSH 临时用户失败: %s %s", resp.Status, strings.TrimSpace(string(body))))
		return
	}
	appendLog("已清理 SSH 临时用户和 authorized_keys")
}
