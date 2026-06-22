//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func switchProfileClicked() {
	if comboBox == 0 {
		return
	}
	count, _, _ := procSendMessage.Call(comboBox, cbGetCount, 0, 0)
	if int32(count) <= 0 {
		showMessage("没有配置", "请先导入配置包。")
		return
	}
	current, _, _ := procSendMessage.Call(comboBox, cbGetCurSel, 0, 0)
	next := uintptr(0)
	if int32(current) >= 0 {
		next = (current + 1) % count
	}
	procSendMessage.Call(comboBox, cbSetCurSel, next, 0)
	updateSelectedProfileText()
	updateStatusControls()
}

func toggleConnectionClicked() {
	if connectBusy.Load() {
		return
	}
	if isRuntimeDisconnecting() {
		return
	}
	if isRuntimeConnected() {
		disconnectActiveConnection()
		activeProfile = ""
		appendLog("已发送断开命令")
		ensureUIRefreshState()
		updateStatusControls()
		return
	}
	target := selectedProfile()
	activeProfile = target
	connectBusy.Store(true)
	appendLog("正在连接，请稍候...")
	updateStatusControls()
	ensureUIRefreshState()
	go func() {
		err := startProfileAsync(target)
		connectBusy.Store(false)
		ensureUIRefreshState()
		if err != nil {
			activeProfile = ""
			appendLog("连接失败: " + err.Error())
			updateStatusControls()
			if isOpenVPNInstallError(err) && askInstallOpenVPN() {
				installOpenVPNClicked()
				return
			}
			showMessage("连接失败", err.Error())
			return
		}
		updateStatusControls()
	}()
}

func isOpenVPNInstallError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "openvpn.exe") || strings.Contains(message, "openvpn")
}

func askInstallOpenVPN() bool {
	message := "当前电脑没有安装 OpenVPN 组件，是否现在安装？\n\n安装会弹出 Windows 管理员授权。"
	ret, _, _ := procMessageBox.Call(
		mainWindow,
		uintptr(unsafe.Pointer(utf16Ptr(message))),
		uintptr(unsafe.Pointer(utf16Ptr("需要安装 OpenVPN"))),
		uintptr(mbYesNo|mbIconQuestion),
	)
	return ret == idYes
}

func shouldEnableSystemProxy() bool {
	return true
}

func installOpenVPNClicked() {
	installer := bundledOpenVPNInstaller()
	if installer == "" {
		showMessage("未找到安装器", "没有找到 installers 目录里的 OpenVPN x86_64 安装器。")
		return
	}
	appendLog("正在启动 OpenVPN 安装器: " + installer)
	cmd := syscall.StringToUTF16Ptr("msiexec.exe")
	params := syscall.StringToUTF16Ptr(`/i "` + installer + `"`)
	ret, _, err := procShellExecute.Call(
		mainWindow,
		uintptr(unsafe.Pointer(utf16Ptr("runas"))),
		uintptr(unsafe.Pointer(cmd)),
		uintptr(unsafe.Pointer(params)),
		0,
		1,
	)
	if ret <= 32 {
		showMessage("启动失败", err.Error())
		return
	}
	showMessage("已启动安装器", "请在 Windows 弹出的安装向导里完成 OpenVPN 组件安装。")
}

func bundledOpenVPNInstaller() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	base := filepath.Dir(exePath)
	candidates := []string{
		filepath.Join(base, "installers", "OpenVPN-2.7.4-I002-amd64.msi"),
		filepath.Join(base, "OpenVPN-2.7.4-I002-amd64.msi"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}
