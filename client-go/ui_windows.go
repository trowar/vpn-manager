//go:build windows

package main

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func launchClientUI() error {
	runtime.LockOSThread()
	hInstance, _, _ := procGetModuleHandle.Call(0)
	className := utf16Ptr("CompanyVPNWindow")
	icon := loadAppIcon(hInstance)
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   syscall.NewCallback(windowProc),
		hInstance:     hInstance,
		hIcon:         icon,
		hbrBackground: 6,
		lpszClassName: className,
		hIconSm:       icon,
	}
	if ret, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); ret == 0 {
		return fmt.Errorf("注册窗口失败: %v", err)
	}
	style := uintptr(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsVisible)
	hwnd, _, err := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16Ptr("Company VPN"))),
		style,
		uintptr(cwUseDefault),
		uintptr(cwUseDefault),
		430,
		560,
		0,
		0,
		hInstance,
		0,
	)
	if hwnd == 0 {
		return fmt.Errorf("创建窗口失败: %v", err)
	}
	if icon != 0 {
		procSendMessage.Call(hwnd, wmSetIcon, iconBig, icon)
		procSendMessage.Call(hwnd, wmSetIcon, iconSmall, icon)
	}
	mainWindow = hwnd
	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		if mainWindow != 0 {
			handled, _, _ := procIsDialogMessage.Call(mainWindow, uintptr(unsafe.Pointer(&m)))
			if handled != 0 {
				continue
			}
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}

func loadAppIcon(hInstance uintptr) uintptr {
	for _, id := range []uintptr{3, 2, 1} {
		icon, _, _ := procLoadIcon.Call(hInstance, id)
		if icon != 0 {
			return icon
		}
	}
	icon, _, _ := procLoadIcon.Call(0, uintptr(32512))
	return icon
}

func windowProc(hwnd uintptr, msg uint32, wParam uintptr, lParam uintptr) uintptr {
	switch msg {
	case wmCreate:
		createControls(hwnd)
		refreshProfileCombo()
		updateStatusControls()
		ensureUIRefreshState()
		go checkUpdateOnLaunch()
		return 0
	case wmCommand:
		commandID := loword(wParam)
		if commandID >= idProfileConnectBase && commandID < idProfileConnectBase+maxProfileRows {
			connectProfileRowClicked(commandID - idProfileConnectBase)
			return 0
		}
		switch commandID {
		case idImport:
			importClicked(hwnd)
		case idLogin:
			loginClicked(hwnd)
		case idConnect:
			toggleConnectionClicked()
		}
		return 0
	case wmTimer:
		if int(wParam) != uiStatusRefreshTimerID {
			ret, _, _ := procDefWindowProc.Call(hwnd, uintptr(msg), wParam, lParam)
			return ret
		}
		updateTrafficControls()
		if !uiRefreshNeeded() {
			stopUIRefreshTimer()
		}
		return 0
	case wmDrawItem:
		return paintOwnerDrawButton(lParam)
	case wmPaint:
		paintClientWindow(hwnd)
		return 0
	case wmDestroy:
		stopUIRefreshTimer()
		disconnectActiveConnection()
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProc.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func createControls(hwnd uintptr) {
	saved := loadSavedLogin()
	defaultWebURL := firstNonEmpty(saved.WebURL, defaultWebURLFromState(), strings.TrimSpace(embeddedDefaultWebURL), "http://172.16.188.135:8080")
	defaultPassword := decryptSavedPassword(saved)
	lastVersion = "版本号-" + strings.TrimSpace(embeddedClientVersion)
	loginControls = nil
	vpnControls = nil

	webURLEdit = create("EDIT", defaultWebURL, wsChild|wsBorder|ssLeft, -1000, -1000, 10, 10, hwnd, idWebURL)
	usernameEdit = create("EDIT", saved.Username, wsChild|wsVisible|wsTabStop|wsBorder|ssLeft, 128, 156, 150, 24, hwnd, idUsername)
	setUIFont(usernameEdit, false)
	loginControls = append(loginControls, usernameEdit)
	passwordEdit = create("EDIT", defaultPassword, wsChild|wsVisible|wsTabStop|wsBorder|ssLeft|esPassword, 128, 214, 150, 24, hwnd, idPassword)
	setUIFont(passwordEdit, false)
	loginControls = append(loginControls, passwordEdit)
	rememberCheck = create("BUTTON", "保存密码", wsChild|wsVisible|wsTabStop|bsAutoCheckBox, 290, 212, 86, 28, hwnd, idRemember)
	setUIFont(rememberCheck, false)
	if saved.RememberPassword {
		procSendMessage.Call(rememberCheck, bmSetCheck, bstChecked, 0)
	}
	loginControls = append(loginControls, rememberCheck)
	loginButton := create("BUTTON", "登录", wsVisible|ownerDrawButtonStyle(true), 128, 276, 178, 34, hwnd, idLogin)
	setUIFont(loginButton, false)
	loginControls = append(loginControls, loginButton)

	comboBox = create("COMBOBOX", "", wsChild|cbsDropDownList, -1000, -1000, 10, 10, hwnd, idCombo)
	showLoginScreen()
}

func createCenteredMeasuredLabel(parent uintptr, title string, y, paddingX, paddingY int) measuredTextControl {
	textSize := measureText(parent, title)
	width := int(textSize.cx) + paddingX*2
	height := int(textSize.cy) + paddingY*2
	if width < paddingX*2+1 {
		width = len([]rune(title))*9 + paddingX*2
	}
	if height < paddingY*2+1 {
		height = 24 + paddingY*2
	}
	x := (430 - width) / 2
	hwnd := create("STATIC", title, wsChild|wsVisible|ssCenter|ssCenterImage, x, y, width, height, parent, 0)
	return measuredTextControl{hwnd: hwnd, x: x, y: y, paddingX: paddingX, paddingY: paddingY, centered: true}
}

func createMeasuredTextLabel(parent uintptr, title string, x, y, paddingX, paddingY int, centered bool) measuredTextControl {
	textSize := measureText(parent, title)
	width := int(textSize.cx) + paddingX*2
	height := int(textSize.cy) + paddingY*2
	if width < paddingX*2+1 {
		width = len([]rune(title))*9 + paddingX*2
	}
	if height < paddingY*2+1 {
		height = 24 + paddingY*2
	}
	style := wsChild | wsVisible | ssLeft | ssCenterImage
	if centered {
		style = wsChild | wsVisible | ssCenter | ssCenterImage
	}
	hwnd := create("STATIC", title, style, x, y, width, height, parent, 0)
	return measuredTextControl{hwnd: hwnd, x: x, y: y, paddingX: paddingX, paddingY: paddingY, centered: centered}
}

func resizeMeasuredTextLabel(parent uintptr, control measuredTextControl, title string) {
	if control.hwnd == 0 {
		return
	}
	textSize := measureText(parent, title)
	width := int(textSize.cx) + control.paddingX*2
	height := int(textSize.cy) + control.paddingY*2
	if width < control.paddingX*2+1 {
		width = len([]rune(title))*9 + control.paddingX*2
	}
	if height < control.paddingY*2+1 {
		height = 24 + control.paddingY*2
	}
	x := control.x
	if control.centered {
		x = (430 - width) / 2
	}
	procSetWindowPos.Call(control.hwnd, 0, uintptr(x), uintptr(control.y), uintptr(width), uintptr(height), swpNoZOrder)
}

func createLoginLabel(parent uintptr, title string, inputX, y int) measuredControl {
	paddingX := 12
	paddingY := 4
	textSize := measureText(parent, title)
	width := int(textSize.cx) + paddingX*2
	height := int(textSize.cy) + paddingY*2
	if width < paddingX*2+1 {
		width = len([]rune(title))*14 + paddingX*2
	}
	if height < paddingY*2+1 {
		height = 24 + paddingY*2
	}
	gap := 8
	x := inputX - gap - width
	hwnd := create("STATIC", title, wsChild|wsVisible|ssCenter|ssCenterImage, x, y, width, height, parent, 0)
	return measuredControl{hwnd: hwnd, x: x, y: y, width: width, height: height}
}

func measureText(parent uintptr, title string) textSize {
	hdc, _, _ := procGetDC.Call(parent)
	if hdc == 0 {
		return textSize{}
	}
	defer procReleaseDC.Call(parent, hdc)
	var size textSize
	utf16Title := utf16.Encode([]rune(title))
	if len(utf16Title) == 0 {
		return textSize{}
	}
	ret, _, _ := procGetTextExtent.Call(
		hdc,
		uintptr(unsafe.Pointer(&utf16Title[0])),
		uintptr(len(utf16Title)),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 || size.cx <= 0 {
		return textSize{}
	}
	return size
}

func create(className, title string, style int, x, y, width, height int, parent uintptr, id int) uintptr {
	hwnd, _, _ := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr(className))),
		uintptr(unsafe.Pointer(utf16Ptr(title))),
		uintptr(style),
		uintptr(x),
		uintptr(y),
		uintptr(width),
		uintptr(height),
		parent,
		uintptr(id),
		0,
		0,
	)
	return hwnd
}
