//go:build !windows

package main

func enableSystemProxy(proxyServer string) error {
	return nil
}

func disableSystemProxy() error {
	return nil
}
