package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func appDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("COMPANY_VPN_HOME")); override != "" {
		return ensureDirs(override)
	}
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exePath)
	if runtime.GOOS != "windows" && dir == "." {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	return ensureDirs(dir)
}

func ensureDirs(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func statePath() (string, error) {
	dir, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, hiddenStateFileName), nil
}

func loadState() (State, error) {
	path, err := statePath()
	if err != nil {
		return State{}, err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func saveState(state State) error {
	path, err := statePath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	return markHidden(path)
}

func getRuntimeBundles() []Bootstrap {
	runtimeBundlesMu.RLock()
	defer runtimeBundlesMu.RUnlock()
	return append([]Bootstrap{}, runtimeBundles...)
}

func setRuntimeBundles(bundles []Bootstrap) {
	runtimeBundlesMu.Lock()
	defer runtimeBundlesMu.Unlock()
	runtimeBundles = append([]Bootstrap{}, bundles...)
}
