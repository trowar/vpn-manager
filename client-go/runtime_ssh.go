package main

func startSSHTunnelProfileAsync(bundle Bootstrap, profile Profile, configResult ConfigResult) error {
	cfg, err := parseSSHTunnelConfigText(configResult.Text)
	if err != nil {
		appendLog("SSH Tunnel 配置解析失败: " + err.Error())
		return err
	}
	cleanupCoreBeforeStart(profile)
	if err := ensureLocalProxyPortFree(cfg.LocalSocks); err != nil {
		appendLog("启动失败: " + err.Error())
		return err
	}
	appendLog("正在建立内存 SSH Tunnel")
	tunnel, err := startMemorySSHTunnel(cfg)
	if err != nil {
		appendLog("启动 SSH Tunnel 失败: " + err.Error())
		return err
	}
	logSSHTunnelDiagnostics(tunnel, cfg)
	startTraffic, trafficErr := readNetworkTrafficCounters()
	if trafficErr != nil {
		appendLog("读取流量计数失败: " + trafficErr.Error())
	}
	appendLog("正在启动虚拟网卡全局模式")
	virtualTunnel, err := startVirtualTunnelOverSocks(cfg.LocalSocks, protectedTunnelHosts(profile, configResult.Server, cfg.Host))
	if err != nil {
		tunnel.Close()
		appendLog("启动虚拟网卡失败: " + err.Error())
		return err
	}
	appendLog("虚拟网卡全局模式已启动")
	heartbeatCancel := startClientOnlineHeartbeat(bundle, profile, configResult.Server)
	runtimeState.mu.Lock()
	runtimeState.sshTunnel = tunnel
	runtimeState.virtualTunnel = virtualTunnel
	runtimeState.status = "已连接"
	runtimeState.systemProxy = false
	runtimeState.runtimeFiles = nil
	runtimeState.heartbeatCancel = heartbeatCancel
	runtimeState.trafficStart = startTraffic
	runtimeState.trafficNow = TrafficCounters{}
	runtimeState.mu.Unlock()
	ensureUIRefreshState()

	go func() {
		<-virtualTunnel.done
		tunnel.Close()
	}()

	go func() {
		<-tunnel.done
		runtimeState.mu.Lock()
		cancelHeartbeat := runtimeState.heartbeatCancel
		runningVirtualTunnel := runtimeState.virtualTunnel
		if runtimeState.sshTunnel == tunnel {
			runtimeState.sshTunnel = nil
			runtimeState.heartbeatCancel = nil
		}
		if runtimeState.virtualTunnel == runningVirtualTunnel {
			runtimeState.virtualTunnel = nil
		}
		shouldDisableProxy := runtimeState.systemProxy
		runtimeState.systemProxy = false
		runtimeState.trafficStart = TrafficCounters{}
		runtimeState.status = "正在断开"
		runtimeState.mu.Unlock()
		ensureUIRefreshState()
		if cancelHeartbeat != nil {
			cancelHeartbeat()
		}
		if runningVirtualTunnel != nil {
			runningVirtualTunnel.Close()
		}
		if shouldDisableProxy {
			if err := disableSystemProxy(); err != nil {
				appendLog("关闭系统代理失败: " + err.Error())
			} else {
				appendLog("已关闭系统代理")
			}
		}
		cleanupSSHTunnelConfig(cfg)
		runtimeState.mu.Lock()
		if runtimeState.status == "正在断开" {
			runtimeState.status = "已断开"
		}
		runtimeState.mu.Unlock()
		ensureUIRefreshState()
		appendLog("SSH Tunnel 已断开")
	}()
	return nil
}
