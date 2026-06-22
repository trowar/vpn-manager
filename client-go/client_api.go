package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func applyClientRequestAuth(req *http.Request, token string) {
	cleanToken := strings.TrimSpace(token)
	if cleanToken == "" {
		return
	}
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	message := strings.Join([]string{req.Method, req.URL.EscapedPath(), timestamp}, "\n")
	mac := hmac.New(sha256.New, []byte(cleanToken))
	_, _ = mac.Write([]byte(message))
	req.Header.Set("X-CompanyVPN-Auth-Time", timestamp)
	req.Header.Set("X-CompanyVPN-Auth-Signature", base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-CompanyVPN-Encrypted", "v1")
}

func globalClientKey() [32]byte {
	return sha256.Sum256([]byte(strings.TrimSpace(embeddedClientCryptoKey)))
}

func loginSlugForTime(serverTime int64) string {
	window := serverTime / 60
	mac := hmac.New(sha256.New, []byte(strings.TrimSpace(embeddedClientCryptoKey)))
	_, _ = mac.Write([]byte(fmt.Sprintf("login:%d", window)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
}

func fetchServerTime(baseURL string) (int64, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/client-api/time", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", appName+"/1.0")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("服务器时间接口返回 %s", resp.Status)
	}
	var payload TimeResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, err
	}
	if !payload.OK || payload.ServerTime <= 0 || strings.TrimSpace(payload.Nonce) == "" || strings.TrimSpace(payload.Signature) == "" {
		return 0, errors.New("服务器时间响应无效")
	}
	mac := hmac.New(sha256.New, []byte(strings.TrimSpace(embeddedClientCryptoKey)))
	_, _ = mac.Write([]byte(fmt.Sprintf("time:%d:%s", payload.ServerTime, payload.Nonce)))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(payload.Signature)) {
		return 0, errors.New("服务器时间签名校验失败")
	}
	return payload.ServerTime, nil
}

func decryptClientAPIResponse(body []byte, token string) ([]byte, error) {
	_ = token
	trimmed := bytes.TrimSpace(body)
	if !bytes.HasPrefix(trimmed, []byte("{")) {
		return body, nil
	}
	var envelope ConfigResponse
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return body, nil
	}
	if strings.TrimSpace(envelope.Encrypted) == "" {
		return body, nil
	}
	if envelope.Encrypted != "v1" {
		return nil, fmt.Errorf("服务器返回了不支持的加密格式: %s", envelope.Encrypted)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("加密响应 nonce 无效: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("加密响应内容无效: %w", err)
	}
	key := globalClientKey()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密服务器响应失败: %w", err)
	}
	return plaintext, nil
}

func decryptLoginAPIResponse(body []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	var envelope ConfigResponse
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return body, nil
	}
	if strings.TrimSpace(envelope.Encrypted) == "" {
		return body, nil
	}
	if envelope.Encrypted != "login-v1" {
		return nil, fmt.Errorf("服务器返回了不支持的登录加密格式: %s", envelope.Encrypted)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, err
	}
	key := globalClientKey()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func loginWithPassword(webURL, username, password string) (Bootstrap, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(webURL), "/")
	if baseURL == "" {
		return Bootstrap{}, errors.New("请填写 Web 服务地址")
	}
	if !strings.HasPrefix(strings.ToLower(baseURL), "http://") && !strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		baseURL = "http://" + baseURL
	}
	requestBody, _ := json.Marshal(LoginRequest{
		Username: strings.TrimSpace(username),
		Password: strings.TrimSpace(password),
	})
	serverTime, err := fetchServerTime(baseURL)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("获取服务器时间失败: %w", err)
	}
	appendLog("已使用服务器时间校准登录窗口")
	loginPath := "/client-api/session/" + loginSlugForTime(serverTime)
	req, err := http.NewRequest(http.MethodPost, baseURL+loginPath, bytes.NewReader(requestBody))
	if err != nil {
		return Bootstrap{}, err
	}
	req.Header.Set("User-Agent", appName+"/1.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Bootstrap{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Bootstrap{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Bootstrap{}, fmt.Errorf("服务器返回 %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	body, err = decryptLoginAPIResponse(body)
	if err != nil {
		return Bootstrap{}, err
	}
	return parseBootstrap(body, baseURL)
}

func currentClientVersion() string {
	version := strings.TrimSpace(embeddedClientVersion)
	if version == "" || version == "client-dev" {
		return ""
	}
	return version
}

func checkLatestClientVersion(webURL string) (LatestClientResponse, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(webURL), "/")
	if baseURL == "" {
		return LatestClientResponse{}, errors.New("Web 服务地址为空")
	}
	if !strings.HasPrefix(strings.ToLower(baseURL), "http://") && !strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		baseURL = "http://" + baseURL
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/client/latest", nil)
	if err != nil {
		return LatestClientResponse{}, err
	}
	req.Header.Set("User-Agent", appName+"/"+firstNonEmpty(currentClientVersion(), "dev"))
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return LatestClientResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return LatestClientResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return LatestClientResponse{}, fmt.Errorf("更新接口返回 %s", resp.Status)
	}
	var payload LatestClientResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return LatestClientResponse{}, err
	}
	if !payload.OK || strings.TrimSpace(payload.Version) == "" || strings.TrimSpace(payload.DownloadURL) == "" {
		return LatestClientResponse{}, errors.New("更新接口响应无效")
	}
	return payload, nil
}

func isNewerClientVersion(remoteVersion, localVersion string) bool {
	remote := strings.TrimSpace(remoteVersion)
	local := strings.TrimSpace(localVersion)
	if remote == "" {
		return false
	}
	if local == "" || local == "client-dev" {
		return true
	}
	return remote > local
}
