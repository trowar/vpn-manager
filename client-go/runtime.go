package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
)

func findProfile(target string) (Bootstrap, Profile, error) {
	_ = refreshStoredBootstraps()
	needle := strings.ToLower(strings.TrimSpace(target))
	for _, bundle := range getRuntimeBundles() {
		for _, profile := range bundle.Profiles {
			if needle == "" ||
				needle == strings.ToLower(profile.ID) ||
				needle == strings.ToLower(profile.Name) ||
				needle == strings.ToLower(bundle.Name+"/"+profile.Name) ||
				needle == strings.ToLower(displayProfileLabel(bundle, profile)) {
				return bundle, profile, nil
			}
		}
	}
	return Bootstrap{}, Profile{}, errors.New("没有找到配置")
}

func connectProfile(target string) error {
	bundle, profile, err := findProfile(target)
	if err != nil {
		return err
	}
	fmt.Println("账号:", firstNonEmpty(bundle.Account, "-"))
	fmt.Printf("连接方式: %s (%s)\n", profile.Name, profile.Type)
	fmt.Println("服务器:", formatServerInfo(firstServerInfo(profile.Server, bundle.Server)))
	fmt.Println("正在获取最新配置...")
	configResult, err := fetchConfig(profile)
	if err != nil {
		return err
	}
	if !isEmptyServerInfo(configResult.Server) {
		fmt.Println("实际服务器:", formatServerInfo(configResult.Server))
	}
	if normalizeType(profile.Type) == "ssh-tunnel" {
		cfg, err := parseSSHTunnelConfigText(configResult.Text)
		if err != nil {
			return err
		}
		tunnel, err := startMemorySSHTunnel(cfg)
		if err != nil {
			return err
		}
		defer tunnel.Close()
		virtualTunnel, err := startVirtualTunnelOverSocks(cfg.LocalSocks, protectedTunnelHosts(profile, configResult.Server, cfg.Host))
		if err != nil {
			return err
		}
		defer virtualTunnel.Close()
		fmt.Println("SSH Tunnel 全局模式已连接:", cfg.LocalSocks)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		<-ctx.Done()
		cleanupSSHTunnelConfig(cfg)
		return nil
	}
	configPath, err := writeRuntimeConfig(bundle, profile, configResult.Text)
	if err != nil {
		return err
	}
	defer cleanupRuntimeFiles(runtimeConfigFiles(configPath, profile))
	command, args, err := buildCommand(profile, configPath)
	if err != nil {
		return err
	}
	fmt.Println("配置文件:", configPath)
	fmt.Println("启动命令:", command, strings.Join(args, " "))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd := exec.CommandContext(ctx, command, args...)
	configureCoreProcess(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return err
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func startProfileAsync(target string) error {
	runtimeState.mu.Lock()
	if runtimeState.status == "正在断开" {
		runtimeState.mu.Unlock()
		return errors.New("正在断开并清理临时账号，请稍候")
	}
	if (runtimeState.process != nil && runtimeState.process.Process != nil) || runtimeState.sshTunnel != nil || runtimeState.virtualTunnel != nil {
		runtimeState.mu.Unlock()
		return errors.New("当前已有连接在运行")
	}
	runtimeState.status = "准备连接"
	runtimeState.logs = nil
	runtimeState.runtimeFiles = nil
	runtimeState.heartbeatCancel = nil
	runtimeState.trafficStart = TrafficCounters{}
	runtimeState.trafficNow = TrafficCounters{}
	runtimeState.mu.Unlock()
	ensureUIRefreshState()

	bundle, profile, err := findProfile(target)
	if err != nil {
		return err
	}
	appendLog("账号: " + firstNonEmpty(bundle.Account, "-"))
	appendLog(fmt.Sprintf("连接方式: %s (%s)", profile.Name, profile.Type))
	appendLog("服务器: " + formatServerInfo(firstServerInfo(profile.Server, bundle.Server)))
	appendLog("正在获取最新配置...")
	configResult, err := fetchConfig(profile)
	if err != nil {
		appendLog("获取配置失败: " + err.Error())
		return err
	}
	if !isEmptyServerInfo(configResult.Server) {
		appendLog("实际服务器: " + formatServerInfo(configResult.Server))
	}
	if normalizeType(profile.Type) == "ssh-tunnel" {
		return startSSHTunnelProfileAsync(bundle, profile, configResult)
	}
	configPath, err := writeRuntimeConfig(bundle, profile, configResult.Text)
	if err != nil {
		appendLog("写入配置失败: " + err.Error())
		return err
	}
	runtimeFiles := runtimeConfigFiles(configPath, profile)
	command, args, err := buildCommand(profile, configPath)
	if err != nil {
		appendLog("启动失败: " + err.Error())
		cleanupRuntimeFiles(runtimeFiles)
		return err
	}
	if profile.Type != "openvpn" {
		cleanupCoreBeforeStart(profile)
		if err := ensureLocalProxyPortFree("127.0.0.1:7890"); err != nil {
			appendLog("启动失败: " + err.Error())
			cleanupRuntimeFiles(runtimeFiles)
			return err
		}
	}
	appendLog("配置文件: " + configPath)
	appendLog("启动命令: " + command + " " + strings.Join(args, " "))

	cmd := exec.Command(command, args...)
	configureCoreProcess(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		cleanupRuntimeFiles(runtimeFiles)
		return err
	}
	if err := attachCoreProcess(cmd); err != nil {
		appendLog("绑定进程生命周期失败: " + err.Error())
		_ = cmd.Process.Kill()
		cleanupRuntimeFiles(runtimeFiles)
		return err
	}
	startTraffic, trafficErr := readNetworkTrafficCounters()
	if trafficErr != nil {
		appendLog("读取流量计数失败: " + trafficErr.Error())
	}
	proxyEnabled := false
	if profile.Type != "openvpn" && normalizeType(profile.Type) != "ssh-tunnel" && shouldEnableSystemProxy() {
		proxyServer := systemProxyServerForProfile(profile)
		if err := enableSystemProxy(proxyServer); err != nil {
			appendLog("开启系统代理失败: " + err.Error())
		} else {
			proxyEnabled = true
			appendLog("已开启系统代理: " + proxyServer)
		}
	}
	heartbeatCancel := startClientOnlineHeartbeat(bundle, profile, configResult.Server)
	runtimeState.mu.Lock()
	runtimeState.process = cmd
	runtimeState.status = "已连接"
	runtimeState.systemProxy = proxyEnabled
	runtimeState.runtimeFiles = runtimeFiles
	runtimeState.heartbeatCancel = heartbeatCancel
	runtimeState.trafficStart = startTraffic
	runtimeState.trafficNow = TrafficCounters{}
	runtimeState.mu.Unlock()
	ensureUIRefreshState()

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			appendLog(scanner.Text())
		}
	}()
	go func() {
		err := cmd.Wait()
		runtimeState.mu.Lock()
		files := append([]string{}, runtimeFiles...)
		cancelHeartbeat := runtimeState.heartbeatCancel
		if runtimeState.process == cmd {
			runtimeState.process = nil
			runtimeState.runtimeFiles = nil
			runtimeState.heartbeatCancel = nil
		}
		shouldDisableProxy := runtimeState.systemProxy
		runtimeState.systemProxy = false
		runtimeState.trafficStart = TrafficCounters{}
		if err != nil {
			runtimeState.status = "已断开"
		} else {
			runtimeState.status = "已断开"
		}
		runtimeState.mu.Unlock()
		ensureUIRefreshState()
		if cancelHeartbeat != nil {
			cancelHeartbeat()
		}
		if normalizeType(profile.Type) == "ssh-tunnel" && err != nil {
			appendLog("SSH Tunnel 进程退出: " + err.Error())
		}
		if shouldDisableProxy {
			if err := disableSystemProxy(); err != nil {
				appendLog("关闭系统代理失败: " + err.Error())
			} else {
				appendLog("已关闭系统代理")
			}
		}
		cleanupRuntimeFiles(files)
		appendLog("连接进程已退出")
	}()
	return nil
}
