//go:build windows

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

func defaultWebURLFromState() string {
	bundles := getRuntimeBundles()
	for i := len(bundles) - 1; i >= 0; i-- {
		if strings.TrimSpace(bundles[i].WebURL) != "" {
			return strings.TrimSpace(bundles[i].WebURL)
		}
	}
	return ""
}

func isChecked(hwnd uintptr) bool {
	if hwnd == 0 {
		return false
	}
	checked, _, _ := procSendMessage.Call(hwnd, bmGetCheck, 0, 0)
	return checked == bstChecked
}

func refreshProfileCombo() {
	if comboBox == 0 {
		return
	}
	procSendMessage.Call(comboBox, cbResetContent, 0, 0)
	destroyProfileRowButtons()
	for i := 0; i < maxProfileRows; i++ {
		profileRowTarget[i] = ""
		profileRowTitle[i] = ""
		profileRowUsername[i] = ""
		profileRowBtn[i] = ""
	}
	_ = refreshStoredBootstraps()
	count := 0
	row := 0
	for _, bundle := range getRuntimeBundles() {
		for _, profile := range bundle.Profiles {
			label := displayProfileLabel(bundle, profile)
			procSendMessage.Call(comboBox, cbAddString, 0, uintptr(unsafe.Pointer(utf16Ptr(label))))
			if row < maxProfileRows {
				profileRowTarget[row] = label
				profileRowTitle[row], profileRowUsername[row] = profileListParts(bundle, profile)
				if profileRowLabel[row] != 0 {
					procSendMessage.Call(profileRowLabel[row], wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(profileRowTitle[row]))))
					procShowWindow.Call(profileRowLabel[row], swShow)
				}
				if profileRowUser[row] != 0 {
					procSendMessage.Call(profileRowUser[row], wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(profileRowUsername[row]))))
					procShowWindow.Call(profileRowUser[row], swShow)
				}
				createProfileRowButton(row)
				row++
			}
			count++
		}
	}
	for i := row; i < maxProfileRows; i++ {
		if profileRowLabel[i] != 0 {
			procSendMessage.Call(profileRowLabel[i], wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(""))))
			procShowWindow.Call(profileRowLabel[i], swHide)
		}
		if profileRowUser[i] != 0 {
			procSendMessage.Call(profileRowUser[i], wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(""))))
			procShowWindow.Call(profileRowUser[i], swHide)
		}
	}
	if count > 0 {
		procSendMessage.Call(comboBox, cbSetCurSel, 0, 0)
		selectedProfileTarget = profileRowTarget[0]
	} else {
		selectedProfileTarget = ""
	}
	updateSelectedProfileText()
	if vpnScreenVisible && mainWindow != 0 {
		procSetWindowPos.Call(mainWindow, 0, 0, 0, uintptr(vpnWindowWidth), uintptr(vpnWindowHeight()), swpNoMove|swpNoZOrder)
	}
	invalidateMainWindow()
}

func destroyProfileRowButtons() {
	for i := 0; i < maxProfileRows; i++ {
		if profileRowButton[i] != 0 {
			procDestroyWindow.Call(profileRowButton[i])
		}
		profileRowButton[i] = 0
		profileRowButtonShown[i] = false
		profileRowButtonEnabled[i] = false
		profileRowBtn[i] = ""
	}
}

func createProfileRowButton(row int) {
	if mainWindow == 0 || row < 0 || row >= maxProfileRows {
		return
	}
	if strings.TrimSpace(profileRowTarget[row]) == "" {
		return
	}
	style := ownerDrawButtonStyle(false)
	if vpnScreenVisible {
		style |= wsVisible
	}
	button := create("BUTTON", "连接", style, vpnRowButtonX, vpnRowTop+row*vpnRowHeight+8, vpnRowButtonWidth, 36, mainWindow, idProfileConnectBase+row)
	setUIButtonFont(button)
	profileRowButton[row] = button
	profileRowButtonShown[row] = vpnScreenVisible
	profileRowButtonEnabled[row] = true
	profileRowBtn[row] = "连接"
}

func selectedProfile() string {
	if strings.TrimSpace(selectedProfileTarget) != "" {
		return selectedProfileTarget
	}
	if comboBox == 0 {
		return ""
	}
	ret, _, _ := procSendMessage.Call(comboBox, cbGetCurSel, 0, 0)
	if int32(ret) < 0 {
		return ""
	}
	buffer := make([]uint16, 512)
	procSendMessage.Call(comboBox, cbGetLbText, ret, uintptr(unsafe.Pointer(&buffer[0])))
	return syscall.UTF16ToString(buffer)
}

func connectProfileRowClicked(index int) {
	if index < 0 || index >= maxProfileRows {
		return
	}
	target := strings.TrimSpace(profileRowTarget[index])
	if target == "" {
		return
	}
	selectedProfileTarget = target
	if comboBox != 0 {
		procSendMessage.Call(comboBox, cbSetCurSel, uintptr(index), 0)
	}
	updateSelectedProfileText()
	toggleConnectionClicked()
}

func updateSelectedProfileText() {
	label := selectedProfile()
	title, info := profileDisplayParts(label)
	if profileText != 0 && title != lastProfile {
		procSendMessage.Call(profileText, wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(title))))
		lastProfile = title
	}
	if profileInfoText != 0 && info != lastProfileInfo {
		procSendMessage.Call(profileInfoText, wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(info))))
		lastProfileInfo = info
	}
}

func profileDisplayParts(label string) (string, string) {
	if strings.TrimSpace(label) == "" {
		return "未导入配置", "-"
	}
	parts := strings.Split(label, " / ")
	if len(parts) >= 3 {
		account := strings.TrimSpace(parts[0])
		server := strings.TrimSpace(parts[1])
		mode := strings.TrimSpace(parts[2])
		if server != "" && server != "-" {
			return server + " [" + account + "]", mode
		}
		return account, mode
	}
	return label, ""
}

func profileListParts(bundle Bootstrap, profile Profile) (string, string) {
	server := firstServerInfo(profile.Server, bundle.Server)
	host := firstNonEmpty(server.EndpointHost, server.Host, server.DisplayName, server.ServerName, profile.Name)
	account := firstNonEmpty(bundle.Account, bundle.Name, "-")
	if strings.TrimSpace(host) == "" || host == "-" {
		host = "默认"
	}
	return host, account
}

func updateStatusControls() {
	runtimeState.mu.Lock()
	status := runtimeState.status
	running := (runtimeState.process != nil && runtimeState.process.Process != nil) || runtimeState.sshTunnel != nil || runtimeState.virtualTunnel != nil
	runtimeState.mu.Unlock()
	busy := connectBusy.Load()
	disconnecting := status == "正在断开"
	statusChanged := false
	if statusText != 0 {
		if busy && !running {
			status = "正在连接"
		} else if !running && status == "未连接" {
			status = "准备连接"
		}
		if status != lastStatus {
			resizeMeasuredTextLabel(mainWindow, statusMeasure, status)
			procSendMessage.Call(statusText, wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(status))))
			lastStatus = status
			statusChanged = true
		}
	}
	if statusText == 0 && status != lastStatus {
		lastStatus = status
		statusChanged = true
	}
	updateSelectedProfileText()
	dirtyButtons := updateProfileRowButtons(busy, running, disconnecting)
	if vpnScreenVisible && (dirtyButtons || statusChanged) {
		invalidateMainWindow()
	}
}

func updateTrafficControls() {
	if !vpnScreenVisible {
		return
	}
	traffic := refreshTrafficCounters()
	trafficStatus := fmt.Sprintf("流量：接收 %s / 发送 %s", formatBytes(traffic.RxBytes), formatBytes(traffic.TxBytes))
	if trafficStatus == lastTraffic {
		return
	}
	lastTraffic = trafficStatus
	trafficTop := vpnTrafficTop()
	trafficRect := rect{left: 56, top: int32(trafficTop), right: 374, bottom: int32(trafficTop + vpnTrafficHeight)}
	procInvalidateRect.Call(mainWindow, uintptr(unsafe.Pointer(&trafficRect)), 1)
}

func updateProfileRowButtons(busy bool, running bool, disconnecting bool) bool {
	changed := false
	for i := 0; i < maxProfileRows; i++ {
		button := profileRowButton[i]
		if button == 0 {
			continue
		}
		if !vpnScreenVisible {
			if profileRowButtonShown[i] {
				procShowWindow.Call(button, swHide)
				profileRowButtonShown[i] = false
				changed = true
			}
			continue
		}
		target := strings.TrimSpace(profileRowTarget[i])
		if target == "" {
			if profileRowButtonShown[i] {
				procShowWindow.Call(button, swHide)
				profileRowButtonShown[i] = false
				changed = true
			}
			if profileRowButtonEnabled[i] {
				procEnableWindow.Call(button, 0)
				profileRowButtonEnabled[i] = false
				changed = true
			}
			continue
		}
		if !profileRowButtonShown[i] {
			procShowWindow.Call(button, swShow)
			profileRowButtonShown[i] = true
			changed = true
		}
		label := "连接"
		enabled := true
		if busy && !running {
			if target == activeProfile {
				label = "连接中..."
			}
			enabled = false
		} else if disconnecting {
			label = "断开中..."
			enabled = false
		} else if running {
			if target == activeProfile {
				label = "断开"
			} else {
				enabled = false
			}
		}
		if profileRowButtonEnabled[i] != enabled {
			var enableParam uintptr
			if enabled {
				enableParam = 1
			}
			procEnableWindow.Call(button, enableParam)
			profileRowButtonEnabled[i] = enabled
			changed = true
		}
		if profileRowBtn[i] != label {
			procSendMessage.Call(button, wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(label))))
			profileRowBtn[i] = label
			changed = true
		}
	}
	return changed
}

func isRuntimeConnected() bool {
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	return (runtimeState.process != nil && runtimeState.process.Process != nil) || runtimeState.sshTunnel != nil || runtimeState.virtualTunnel != nil
}

func isRuntimeDisconnecting() bool {
	runtimeState.mu.Lock()
	defer runtimeState.mu.Unlock()
	return runtimeState.status == "正在断开"
}

func chooseJSONFile(hwnd uintptr) string {
	fileBuffer := make([]uint16, 1024)
	filterBuffer := utf16WithNul("JSON 配置包 (*.json)\x00*.json\x00所有文件 (*.*)\x00*.*\x00")
	title := utf16Ptr("选择客户端配置包")
	ofn := openFileName{
		lStructSize: uint32(unsafe.Sizeof(openFileName{})),
		hwndOwner:   hwnd,
		lpstrFilter: &filterBuffer[0],
		lpstrFile:   &fileBuffer[0],
		nMaxFile:    uint32(len(fileBuffer)),
		lpstrTitle:  title,
		flags:       ofnExplorer | ofnFileMustExist | ofnPathMustExist,
	}
	ret, _, _ := procGetOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(fileBuffer)
}
