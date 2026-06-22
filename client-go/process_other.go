//go:build !windows

package main

import "os/exec"

func configureCoreProcess(cmd *exec.Cmd) {
}

func attachCoreProcess(cmd *exec.Cmd) error {
	return nil
}

func cleanupCoreBeforeStart(profile Profile) {
}
