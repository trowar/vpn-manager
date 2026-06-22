//go:build !windows

package main

func launchClientUI() error {
	return interactive()
}

func shouldEnableSystemProxy() bool {
	return false
}
