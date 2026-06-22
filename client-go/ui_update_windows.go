//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"
)

func checkUpdateOnLaunch() {
	time.Sleep(1200 * time.Millisecond)
	saved := loadSavedLogin()
	webURL := firstNonEmpty(saved.WebURL, defaultWebURLFromState(), strings.TrimSpace(embeddedDefaultWebURL))
	if strings.TrimSpace(webURL) == "" {
		return
	}
	latest, err := checkLatestClientVersion(webURL)
	if err != nil {
		appendLog("检查客户端更新失败: " + err.Error())
		return
	}
	localVersion := currentClientVersion()
	if !isNewerClientVersion(latest.Version, localVersion) {
		appendLog("客户端已是最新版本")
		return
	}
	message := fmt.Sprintf("发现新版：版本号-%s\n当前版本：版本号-%s\n\n是否自动更新并重启客户端？", latest.Version, firstNonEmpty(localVersion, "dev"))
	ret, _, _ := procMessageBox.Call(
		mainWindow,
		uintptr(unsafe.Pointer(utf16Ptr(message))),
		uintptr(unsafe.Pointer(utf16Ptr("客户端更新"))),
		uintptr(mbYesNo|mbIconQuestion),
	)
	if ret == idYes {
		appendLog("准备更新，正在断开当前 VPN...")
		disconnectActiveConnection()
		if err := startUpdater(latest.DownloadURL, latest.Version); err != nil {
			appendLog("启动更新程序失败: " + err.Error())
			showMessage("更新失败", err.Error())
			return
		}
		procShowWindow.Call(mainWindow, swHide)
		procDestroyWindow.Call(mainWindow)
		os.Exit(0)
	}
}

func startUpdater(downloadURL, version string) error {
	cleanURL := strings.TrimSpace(downloadURL)
	if cleanURL == "" {
		return fmt.Errorf("下载地址为空")
	}
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	baseDir := filepath.Dir(exePath)
	sourceUpdater := filepath.Join(baseDir, "Updater.exe")
	if _, err := os.Stat(sourceUpdater); err != nil {
		return fmt.Errorf("没有找到更新程序 Updater.exe")
	}
	tempUpdater := filepath.Join(os.TempDir(), "CompanyVPN-Updater-"+safeUpdatePart(version)+".exe")
	if err := copyLocalFile(sourceUpdater, tempUpdater); err != nil {
		return err
	}
	params := fmt.Sprintf(
		`--url "%s" --target "%s" --exe "CompanyVPN.exe" --version "%s" --wait-pid "%d"`,
		cleanURL,
		baseDir,
		strings.TrimSpace(version),
		os.Getpid(),
	)
	appendLog("正在启动更新程序: " + tempUpdater)
	ret, _, err := procShellExecute.Call(
		mainWindow,
		uintptr(unsafe.Pointer(utf16Ptr("open"))),
		uintptr(unsafe.Pointer(utf16Ptr(tempUpdater))),
		uintptr(unsafe.Pointer(utf16Ptr(params))),
		0,
		1,
	)
	if ret <= 32 {
		return err
	}
	return nil
}

func copyLocalFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func safeUpdatePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "latest"
	}
	replacer := strings.NewReplacer("\\", "-", "/", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-")
	return replacer.Replace(value)
}
