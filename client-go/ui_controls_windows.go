//go:build windows

package main

import (
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func showControls(handles []uintptr, visible bool) {
	flag := uintptr(swHide)
	if visible {
		flag = uintptr(swShow)
	}
	for _, handle := range handles {
		if handle != 0 {
			procShowWindow.Call(handle, flag)
		}
	}
}

func showLoginScreen() {
	vpnScreenVisible = false
	showControls(loginControls, true)
	showControls(vpnControls, false)
	destroyProfileRowButtons()
	procSetWindowPos.Call(mainWindow, 0, 0, 0, uintptr(vpnWindowWidth), uintptr(loginWindowHeight), swpNoMove|swpNoZOrder)
	stopUIRefreshTimer()
	invalidateMainWindow()
}

func showVPNScreen() {
	vpnScreenVisible = true
	showControls(loginControls, false)
	showControls(vpnControls, false)
	for i := 0; i < maxProfileRows; i++ {
		profileRowButtonShown[i] = false
	}
	procSetWindowPos.Call(mainWindow, 0, 0, 0, uintptr(vpnWindowWidth), uintptr(vpnWindowHeight()), swpNoMove|swpNoZOrder)
	updateStatusControls()
	ensureUIRefreshState()
	invalidateMainWindow()
}

func invalidateMainWindow() {
	if mainWindow != 0 {
		procInvalidateRect.Call(mainWindow, 0, 1)
	}
}

func getControlText(hwnd uintptr) string {
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, 1024)
	procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return strings.TrimRight(string(utf16.Decode(buf)), "\x00")
}

func showMessage(title, text string) {
	showAppMessage(title, text)
}

func loword(value uintptr) int {
	return int(value & 0xffff)
}

func utf16Ptr(value string) *uint16 {
	ptr, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		ptr, _ = syscall.UTF16PtrFromString(strings.ReplaceAll(value, "\x00", ""))
	}
	return ptr
}

func utf16WithNul(value string) []uint16 {
	encoded := utf16.Encode([]rune(value))
	return append(encoded, 0)
}
