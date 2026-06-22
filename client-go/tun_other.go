//go:build !windows

package main

import "errors"

func runTun2SocksChild(args []string) error {
	return errors.New("当前系统暂不支持内置 TUN 全局模式")
}

func startVirtualTunnelOverSocks(localSocks string, protectedHosts []string) (*virtualTunnelRuntime, error) {
	return nil, errors.New("当前系统暂不支持内置 TUN 全局模式")
}
