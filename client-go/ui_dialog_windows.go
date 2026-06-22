//go:build windows

package main

import (
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	appDialogWidth  = 440
	appDialogHeight = 210
)

var (
	appDialogDone   bool
	appDialogResult int
)

func showAppMessage(title, text string) {
	runAppDialog(title, text, false)
}

func confirmAppMessage(title, text string) bool {
	return runAppDialog(title, text, true) == idDialogYes
}

func runAppDialog(title, text string, confirm bool) int {
	appDialogDone = false
	appDialogResult = idDialogNo
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInstance, _, _ := procGetModuleHandle.Call(0)
	className := utf16Ptr("CompanyVPNAppDialog")
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   syscall.NewCallback(appDialogProc),
		hInstance:     hInstance,
		hbrBackground: 6,
		lpszClassName: className,
	}
	procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
	hwnd, _, _ := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16Ptr(strings.TrimSpace(title)))),
		uintptr(wsOverlapped|wsCaption|wsSysMenu|wsVisible),
		uintptr(cwUseDefault),
		uintptr(cwUseDefault),
		appDialogWidth,
		appDialogHeight,
		mainWindow,
		0,
		hInstance,
		0,
	)
	if hwnd == 0 {
		return appDialogResult
	}
	createAppDialogControls(hwnd, text, confirm)
	var m msg
	for !appDialogDone {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	return appDialogResult
}

func createAppDialogControls(hwnd uintptr, text string, confirm bool) {
	message := create("STATIC", strings.TrimSpace(text), wsChild|wsVisible|ssLeft, 26, 26, 382, 90, hwnd, 0)
	setUIFont(message, false)
	if confirm {
		yes := create("BUTTON", "是(Y)", wsVisible|ownerDrawButtonStyle(true), 82, 134, 126, 42, hwnd, idDialogYes)
		no := create("BUTTON", "否(N)", wsVisible|ownerDrawButtonStyle(false), 232, 134, 126, 42, hwnd, idDialogNo)
		setUIButtonFont(yes)
		setUIButtonFont(no)
		return
	}
	ok := create("BUTTON", "确定", wsVisible|ownerDrawButtonStyle(true), 157, 134, 126, 42, hwnd, idDialogOK)
	setUIButtonFont(ok)
}

func appDialogProc(hwnd uintptr, message uint32, wParam uintptr, lParam uintptr) uintptr {
	switch message {
	case wmCommand:
		switch loword(wParam) {
		case idDialogOK:
			appDialogResult = idDialogOK
		case idDialogYes:
			appDialogResult = idDialogYes
		case idDialogNo:
			appDialogResult = idDialogNo
		default:
			break
		}
		appDialogDone = true
		procDestroyWindow.Call(hwnd)
		return 0
	case wmClose:
		appDialogDone = true
		appDialogResult = idDialogNo
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		appDialogDone = true
		return 0
	}
	ret, _, _ := procDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
	return ret
}
