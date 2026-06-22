//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	tunDeviceName = "CompanyVPN-TUN"
	tunAddress    = "198.18.0.1"
	tunMask       = "255.255.255.0"
	tunMTU        = 1500
)

type defaultRouteInfo struct {
	gateway        string
	interfaceIndex string
}

func runTun2SocksChild(args []string) error {
	deviceName := tunDeviceName
	proxyURL := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--device":
			if i+1 < len(args) {
				deviceName = args[i+1]
				i++
			}
		case "--proxy":
			if i+1 < len(args) {
				proxyURL = args[i+1]
				i++
			}
		}
	}
	if strings.TrimSpace(proxyURL) == "" {
		return errors.New("tun2socks-child 缺少 --proxy")
	}
	engine.Insert(&engine.Key{
		MTU:                      tunMTU,
		Proxy:                    proxyURL,
		Device:                   "tun://" + deviceName,
		LogLevel:                 "silent",
		TCPModerateReceiveBuffer: true,
	})
	engine.Start()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() {
		<-ctx.Done()
		engine.Stop()
	}()
	select {}
}

func startVirtualTunnelOverSocks(localSocks string, protectedHosts []string) (*virtualTunnelRuntime, error) {
	localSocks = strings.TrimSpace(localSocks)
	if localSocks == "" {
		localSocks = "127.0.0.1:7890"
	}
	appendLog("检查 TUN 驱动文件")
	if err := ensureWintunDLLAvailable(); err != nil {
		return nil, err
	}
	appendLog("读取当前默认网关")
	routeInfo, err := getDefaultIPv4Route()
	if err != nil {
		return nil, err
	}
	appendLog("默认网关: " + routeInfo.gateway + " ifIndex=" + routeInfo.interfaceIndex)
	appendLog("解析直连保护地址")
	protectedIPs := resolveProtectedIPv4Hosts(protectedHosts)
	dnsIPs := getSystemDNSServers()
	for dnsIP := range dnsIPs {
		protectedIPs[dnsIP] = true
	}
	cleanupVirtualTunnelRoutes(routeInfo, protectedIPs)

	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exePath, "tun2socks-child", "--device", tunDeviceName, "--proxy", "socks5://"+localSocks)
	configureCoreProcess(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := attachCoreProcess(cmd); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("绑定 TUN 子进程生命周期失败: %w", err)
	}
	appendLog(fmt.Sprintf("TUN 子进程已启动: pid=%d", cmd.Process.Pid))

	done := make(chan struct{})
	var childErr error
	go func() {
		childErr = cmd.Wait()
		close(done)
	}()

	tunIndex, err := waitForInterfaceIndex(tunDeviceName, 12*time.Second, done, &childErr)
	if err != nil {
		_ = cmd.Process.Kill()
		<-done
		return nil, err
	}
	appendLog("虚拟网卡已创建: " + tunDeviceName + " ifIndex=" + tunIndex)
	appendLog("配置虚拟网卡地址")
	if err := configureTUNInterface(tunIndex); err != nil {
		_ = cmd.Process.Kill()
		<-done
		return nil, err
	}
	appendLog("添加全局路由")
	if err := addVirtualTunnelRoutes(routeInfo, tunIndex, protectedIPs); err != nil {
		cleanupVirtualTunnelRoutes(routeInfo, protectedIPs)
		_ = cmd.Process.Kill()
		<-done
		return nil, err
	}
	appendLog("虚拟网卡: " + tunDeviceName + " ifIndex=" + tunIndex)
	if len(protectedIPs) > 0 {
		appendLog("直连保护路由: " + strings.Join(mapKeys(protectedIPs), ", "))
	}

	return &virtualTunnelRuntime{
		done: done,
		closeFunc: func() {
			cleanupVirtualTunnelRoutes(routeInfo, protectedIPs)
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
			cleanupVirtualTunnelRoutes(routeInfo, protectedIPs)
			appendLog("虚拟网卡全局模式已关闭")
		},
	}, nil
}

func ensureWintunDLLAvailable() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	target := filepath.Join(filepath.Dir(exePath), "wintun.dll")
	if _, err := os.Stat(target); err == nil {
		return nil
	}
	return fmt.Errorf("缺少 wintun.dll，请重新下载最新客户端包")
}

func getDefaultIPv4Route() (defaultRouteInfo, error) {
	script := `$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; if ($r) { Write-Output ($r.NextHop + '|' + $r.InterfaceIndex) }`
	output, err := runPowerShellOutput(script)
	if err != nil {
		return defaultRouteInfo{}, fmt.Errorf("读取默认网关失败: %w", err)
	}
	parts := strings.Split(strings.TrimSpace(output), "|")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return defaultRouteInfo{}, errors.New("未找到可用 IPv4 默认网关")
	}
	return defaultRouteInfo{gateway: strings.TrimSpace(parts[0]), interfaceIndex: strings.TrimSpace(parts[1])}, nil
}

func waitForInterfaceIndex(name string, timeout time.Duration, done <-chan struct{}, childErr *error) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			if childErr != nil && *childErr != nil {
				return "", fmt.Errorf("TUN 子进程提前退出: %w，请确认程序以管理员权限运行且 wintun.dll 可用", *childErr)
			}
			return "", errors.New("TUN 子进程提前退出，请确认程序以管理员权限运行且 wintun.dll 可用")
		default:
		}
		index, err := getInterfaceIndex(name)
		if err == nil && index != "" {
			return index, nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "", errors.New("等待虚拟网卡创建超时，请确认程序以管理员权限运行且 wintun.dll 可用")
}

func getInterfaceIndex(name string) (string, error) {
	script := fmt.Sprintf(`$a = Get-NetAdapter -Name %s -ErrorAction SilentlyContinue; if ($a) { Write-Output $a.ifIndex }`, powerShellQuote(name))
	output, err := runPowerShellOutput(script)
	if err != nil {
		return "", err
	}
	index := strings.TrimSpace(output)
	if index == "" {
		return "", errors.New("interface not found")
	}
	if _, err := strconv.Atoi(index); err != nil {
		return "", err
	}
	return index, nil
}

func configureTUNInterface(interfaceIndex string) error {
	commands := [][]string{
		{"netsh", "interface", "ipv4", "set", "address", "name=" + tunDeviceName, "static", tunAddress, tunMask},
		{"netsh", "interface", "ipv4", "set", "interface", tunDeviceName, "metric=1"},
	}
	for _, cmd := range commands {
		if output, err := runHiddenCombined(cmd[0], cmd[1:]...); err != nil {
			return fmt.Errorf("%s: %s", err, strings.TrimSpace(output))
		}
	}
	return nil
}

func addVirtualTunnelRoutes(routeInfo defaultRouteInfo, tunIndex string, protectedIPs map[string]bool) error {
	for ip := range protectedIPs {
		if err := runRoute("add", ip, "255.255.255.255", routeInfo.gateway, "1", routeInfo.interfaceIndex); err != nil {
			return err
		}
	}
	if err := runRoute("add", "0.0.0.0", "128.0.0.0", tunAddress, "3", tunIndex); err != nil {
		return err
	}
	if err := runRoute("add", "128.0.0.0", "128.0.0.0", tunAddress, "3", tunIndex); err != nil {
		return err
	}
	return nil
}

func cleanupVirtualTunnelRoutes(routeInfo defaultRouteInfo, protectedIPs map[string]bool) {
	_ = runRoute("delete", "0.0.0.0", "128.0.0.0", tunAddress, "", "")
	_ = runRoute("delete", "128.0.0.0", "128.0.0.0", tunAddress, "", "")
	for ip := range protectedIPs {
		_ = runRoute("delete", ip, "255.255.255.255", routeInfo.gateway, "", "")
	}
}

func runRoute(action, destination, mask, gateway, metric, interfaceIndex string) error {
	args := []string{action, destination, "mask", mask, gateway}
	if metric != "" {
		args = append(args, "metric", metric)
	}
	if interfaceIndex != "" {
		args = append(args, "if", interfaceIndex)
	}
	output, err := runHiddenCombined("route", args...)
	if err != nil {
		text := strings.TrimSpace(output)
		if action == "delete" && (strings.Contains(text, "not found") || strings.Contains(text, "找不到")) {
			return nil
		}
		return fmt.Errorf("route %s %s 失败: %s", action, destination, text)
	}
	return nil
}

func protectedTunnelHosts(profile Profile, server ServerInfo, sshHost string) []string {
	hosts := []string{sshHost}
	serverInfo := firstServerInfo(server, profile.Server)
	hosts = append(hosts, serverInfo.Host, serverInfo.EndpointHost)
	if parsed, err := url.Parse(profile.UpdateURL); err == nil {
		hosts = append(hosts, parsed.Hostname())
	}
	if parsed, err := url.Parse(profile.OnlineURL); err == nil {
		hosts = append(hosts, parsed.Hostname())
	}
	return hosts
}

func resolveProtectedIPv4Hosts(hosts []string) map[string]bool {
	result := map[string]bool{}
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
		if ip := net.ParseIP(host); ip != nil {
			if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() {
				result[v4.String()] = true
			}
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() {
				result[v4.String()] = true
			}
		}
	}
	return result
}

func getSystemDNSServers() map[string]bool {
	result := map[string]bool{}
	script := `Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Sort-Object -Unique`
	output, err := runPowerShellOutput(script)
	if err != nil {
		return result
	}
	for _, line := range strings.Fields(output) {
		if ip := net.ParseIP(strings.TrimSpace(line)); ip != nil {
			if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() {
				result[v4.String()] = true
			}
		}
	}
	return result
}

func runPowerShellOutput(script string) (string, error) {
	return runHiddenCombined("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

func runHiddenCombined(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	configureCoreProcess(cmd)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func powerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func mapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
