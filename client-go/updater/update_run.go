package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func run(downloadURL, targetDir, exeName, version, waitPID string) error {
	downloadURL = strings.TrimSpace(downloadURL)
	targetDir = strings.TrimSpace(targetDir)
	if downloadURL == "" {
		return fmt.Errorf("missing download URL")
	}
	if targetDir == "" {
		return fmt.Errorf("missing target directory")
	}
	if exeName == "" {
		exeName = "CompanyVPN.exe"
	}
	workDir := filepath.Join(os.TempDir(), "CompanyVPN-update-"+safePart(version))
	_ = os.RemoveAll(workDir)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return err
	}

	zipPath := filepath.Join(workDir, "client.zip")
	updateStatus("正在下载更新包...")
	updateDetail("正在连接服务器...")
	if err := downloadFile(downloadURL, zipPath); err != nil {
		return err
	}

	extractDir := filepath.Join(workDir, "extract")
	updateStatus("正在解压更新包...")
	updateDetail("下载完成，正在解压文件...")
	setProgress(72)
	if err := unzip(zipPath, extractDir); err != nil {
		return err
	}

	updateStatus("正在关闭旧版本并替换文件...")
	updateDetail("正在等待旧客户端进程关闭...")
	setProgress(84)
	if killed := waitForOldProcess(waitPID, 8*time.Second); killed {
		updateDetail("旧客户端未退出，已强制结束，正在替换文件...")
	} else {
		updateDetail("旧客户端已关闭，正在替换文件...")
	}
	if err := copyTreeWithRetry(extractDir, targetDir, 60*time.Second); err != nil {
		return err
	}

	updateStatus("正在启动新版本...")
	updateDetail("替换完成，正在启动客户端...")
	setProgress(96)
	if err := startClientDetached(filepath.Join(targetDir, exeName), targetDir); err != nil {
		return err
	}
	setProgress(100)
	updateStatus("更新完成。")
	updateDetail("已启动新版本，正在关闭更新程序...")
	go exitUpdaterSoon()
	time.Sleep(300 * time.Millisecond)
	return nil
}

func startClientDetached(exePath, workDir string) error {
	ret, _, err := procShellExecute.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr("open"))),
		uintptr(unsafe.Pointer(utf16Ptr(exePath))),
		0,
		uintptr(unsafe.Pointer(utf16Ptr(workDir))),
		swShow,
	)
	if ret <= 32 {
		if err != syscall.Errno(0) {
			return err
		}
		return fmt.Errorf("启动新客户端失败，ShellExecute=%d", ret)
	}
	return nil
}

func exitUpdaterSoon() {
	time.Sleep(500 * time.Millisecond)
	if mainWindow != 0 {
		procPostMessage.Call(mainWindow, wmClose, 0, 0)
	}
	time.Sleep(800 * time.Millisecond)
	os.Exit(0)
}
