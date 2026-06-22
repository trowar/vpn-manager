//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	wininet               = syscall.NewLazyDLL("wininet.dll")
	proxyUser32           = syscall.NewLazyDLL("user32.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")
	procSendNotifyMessage = proxyUser32.NewProc("SendNotifyMessageW")
)

func enableSystemProxy(proxyServer string) error {
	if err := runHidden("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "AutoDetect", "/t", "REG_DWORD", "/d", "0", "/f"); err != nil {
		return err
	}
	if err := runHidden("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"); err != nil {
		return err
	}
	if err := runHidden("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyServer, "/f"); err != nil {
		return err
	}
	if err := runHidden("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "<local>", "/f"); err != nil {
		return err
	}
	notifyProxySettingsChanged()
	return nil
}

func disableSystemProxy() error {
	if err := runHidden("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"); err != nil {
		return err
	}
	notifyProxySettingsChanged()
	return nil
}

func runHidden(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	configureCoreProcess(cmd)
	return cmd.Run()
}

func notifyProxySettingsChanged() {
	const internetOptionRefresh = 37
	const internetOptionSettingsChanged = 39
	const hwndBroadcast = 0xffff
	const wmSettingChange = 0x001a
	procInternetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOption.Call(0, internetOptionRefresh, 0, 0)
	procSendNotifyMessage.Call(
		hwndBroadcast,
		wmSettingChange,
		0,
		uintptr(unsafe.Pointer(utf16Ptr(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`))),
	)
}
