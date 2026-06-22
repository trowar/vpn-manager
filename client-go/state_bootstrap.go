package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func loadBootstrap(path string) (Bootstrap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Bootstrap{}, err
	}
	return parseBootstrap(raw, path)
}

func parseBootstrap(raw []byte, sourceName string) (Bootstrap, error) {
	var bundle Bootstrap
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return Bootstrap{}, err
	}
	if len(bundle.Profiles) == 0 {
		return Bootstrap{}, errors.New("配置包里没有 profiles")
	}
	if bundle.Name == "" {
		bundle.Name = strings.TrimSuffix(filepath.Base(sourceName), filepath.Ext(sourceName))
	}
	if bundle.ImportedAt == 0 {
		bundle.ImportedAt = time.Now().Unix()
	}
	bundle.WebURL = strings.TrimRight(strings.TrimSpace(bundle.WebURL), "/")
	if bundle.ID == "" {
		bundle.ID = safeName(firstNonEmpty(bundle.Account, bundle.Name, sourceName))
	}
	for i := range bundle.Profiles {
		p := &bundle.Profiles[i]
		p.Type = normalizeType(p.Type)
		if p.Type == "" {
			return Bootstrap{}, fmt.Errorf("配置 %d 缺少 type", i+1)
		}
		if p.Name == "" {
			p.Name = p.Type
		}
		if p.ID == "" {
			p.ID = safeName(p.Name)
		}
		if p.UpdateURL == "" && strings.TrimSpace(p.Config) == "" {
			return Bootstrap{}, fmt.Errorf("配置 %s 没有 update_url 或 config", p.Name)
		}
	}
	return bundle, nil
}

func autoImportAdjacentBootstraps() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exePath)
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	for _, path := range matches {
		bundle, err := loadBootstrap(path)
		if err != nil {
			continue
		}
		if err := storeBootstrap(bundle); err != nil {
			continue
		}
		appendLog("已自动读取配置包: " + filepath.Base(path))
	}
	return nil
}

func storeBootstrap(bundle Bootstrap) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	current := getRuntimeBundles()
	next := make([]Bootstrap, 0, len(current)+1)
	for _, item := range current {
		sameID := item.ID != "" && item.ID == bundle.ID
		sameAccount := bundle.Account != "" && item.Account == bundle.Account
		sameName := bundle.Name != "" && item.Name == bundle.Name
		if !sameID && !sameAccount && !sameName {
			next = append(next, item)
		}
	}
	next = append(next, bundle)
	setRuntimeBundles(next)
	if strings.TrimSpace(state.SavedLogin.WebURL) == "" && strings.TrimSpace(bundle.WebURL) != "" {
		state.SavedLogin.WebURL = strings.TrimSpace(bundle.WebURL)
	}
	if strings.TrimSpace(state.SavedLogin.Username) == "" && strings.TrimSpace(bundle.Account) != "" {
		state.SavedLogin.Username = strings.TrimSpace(bundle.Account)
	}
	return saveState(state)
}

func storeCurrentBootstrap(bundle Bootstrap) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	setRuntimeBundles([]Bootstrap{bundle})
	if strings.TrimSpace(bundle.WebURL) != "" {
		state.SavedLogin.WebURL = strings.TrimSpace(bundle.WebURL)
	}
	if strings.TrimSpace(bundle.Account) != "" {
		state.SavedLogin.Username = strings.TrimSpace(bundle.Account)
	}
	return saveState(state)
}
