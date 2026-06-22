package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func refreshStoredBootstraps() error {
	bundles := getRuntimeBundles()
	changed := false
	for index, bundle := range bundles {
		if strings.TrimSpace(bundle.UpdateURL) == "" {
			continue
		}
		refreshed, err := fetchBootstrap(bundle)
		if err != nil {
			appendLog("刷新配置包失败: " + err.Error())
			continue
		}
		if refreshed.ImportedAt == 0 {
			refreshed.ImportedAt = bundle.ImportedAt
		}
		if refreshed.ID == "" {
			refreshed.ID = bundle.ID
		}
		if refreshed.Name == "" {
			refreshed.Name = bundle.Name
		}
		if refreshed.Account == "" {
			refreshed.Account = bundle.Account
		}
		bundles[index] = refreshed
		changed = true
	}
	if !changed {
		return nil
	}
	setRuntimeBundles(bundles)
	return nil
}

func fetchBootstrap(bundle Bootstrap) (Bootstrap, error) {
	req, err := http.NewRequest(http.MethodGet, bundle.UpdateURL, nil)
	if err != nil {
		return Bootstrap{}, err
	}
	req.Header.Set("User-Agent", appName+"/1.0")
	req.Header.Set("Accept", "application/json")
	applyClientRequestAuth(req, bundle.UpdateToken)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Bootstrap{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Bootstrap{}, err
	}
	if decoded, err := decryptClientAPIResponse(body, bundle.UpdateToken); err == nil {
		body = decoded
	} else {
		return Bootstrap{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Bootstrap{}, fmt.Errorf("服务器返回 %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return parseBootstrap(body, bundle.Name)
}

func listProfiles() error {
	_ = refreshStoredBootstraps()
	count := 0
	for _, bundle := range getRuntimeBundles() {
		for _, profile := range bundle.Profiles {
			count++
			fmt.Printf("%s/%s  type=%s  account=%s\n", bundle.Name, profile.Name, profile.Type, firstNonEmpty(bundle.Account, "-"))
		}
	}
	if count == 0 {
		fmt.Println("还没有导入配置")
	}
	return nil
}
