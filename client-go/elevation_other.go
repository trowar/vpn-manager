//go:build !windows

package main

func ensureElevatedOrRelaunch(args []string) (bool, error) {
	return false, nil
}
