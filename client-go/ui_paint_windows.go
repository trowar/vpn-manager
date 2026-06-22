//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"
)

func paintClientWindow(hwnd uintptr) {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	if hdc == 0 {
		return
	}
	defer procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	fillRect(hdc, 0, 0, vpnWindowWidth, vpnWindowHeight(), rgb(247, 249, 253))
	if vpnScreenVisible {
		paintVPNScreen(hdc)
		return
	}
	paintLoginHeader(hdc)
}

func paintLoginHeader(hdc uintptr) {
	drawRoundedRect(hdc, 48, 84, 382, 356, 22, rgb(255, 255, 255), rgb(224, 229, 238))
	drawTextInRect(hdc, "账户", 70, 156, 112, 180, rgb(38, 51, 79), uiRegularFont(), dtLeft|dtVCenter|dtSingleLine)
	drawTextInRect(hdc, "密码", 70, 214, 112, 238, rgb(38, 51, 79), uiRegularFont(), dtLeft|dtVCenter|dtSingleLine)
	drawRoundedRect(hdc, 24, 462, 404, 496, 10, rgb(238, 242, 247), 0)
	version := strings.TrimSpace(embeddedClientVersion)
	if version == "" {
		version = "client-dev"
	}
	drawTextInRect(hdc, "版本号 "+shortClientVersion(version), 34, 462, 404, 496, rgb(82, 96, 120), uiSmallFont(), dtLeft|dtVCenter|dtSingleLine)
}

func paintVPNScreen(hdc uintptr) {
	status := currentPaintStatus()
	statusColor := rgb(129, 144, 173)
	if status == "已连接" {
		statusColor = rgb(23, 107, 96)
	}
	drawTextInRect(hdc, status, 0, vpnStatusTop, vpnWindowWidth, vpnStatusTop+vpnStatusHeight, statusColor, uiBoldFont(), dtCenter|dtVCenter|dtSingleLine)

	panelBottom := vpnPanelBottom()
	drawRoundedRect(hdc, vpnPanelLeft, vpnPanelTop, vpnPanelRight, panelBottom, 24, rgb(255, 255, 255), rgb(224, 229, 238))
	drawServerIcon(hdc, 56, vpnPanelTop+28)
	drawTextInRect(hdc, "可用服务器", 124, vpnPanelTop+28, 260, vpnPanelTop+48, rgb(137, 151, 175), uiSmallFont(), dtLeft|dtVCenter|dtSingleLine)
	count := visibleProfileCount()
	drawTextInRect(hdc, fmt.Sprintf("%d 条线路", count), 124, vpnPanelTop+50, 260, vpnPanelTop+80, rgb(38, 51, 79), uiBoldFont(), dtLeft|dtVCenter|dtSingleLine)

	for i := 0; i < maxProfileRows; i++ {
		if strings.TrimSpace(profileRowTarget[i]) == "" {
			continue
		}
		y := vpnRowTop + i*vpnRowHeight
		active := profileRowTarget[i] == activeProfile && isRuntimeConnected()
		bg := rgb(248, 251, 255)
		border := rgb(238, 242, 248)
		dot := rgb(225, 29, 72)
		if active {
			bg = rgb(244, 255, 251)
			border = rgb(182, 231, 220)
			dot = rgb(27, 191, 137)
		}
		drawRoundedRect(hdc, vpnRowLeft, y, vpnRowRight, y+vpnRowCardHeight, 16, bg, border)
		drawCircle(hdc, vpnRowLeft+20, y+24, 5, dot)
		drawTextInRect(hdc, profileRowTitle[i], vpnRowLeft+36, y+8, vpnRowButtonX-12, y+26, rgb(38, 51, 79), uiRegularFont(), dtLeft|dtVCenter|dtSingleLine|dtEndEllipsis)
		drawTextInRect(hdc, profileRowUsername[i], vpnRowLeft+36, y+26, vpnRowButtonX-12, y+43, rgb(121, 134, 159), uiSmallFont(), dtLeft|dtVCenter|dtSingleLine|dtEndEllipsis)
	}

	traffic := refreshTrafficCounters()
	trafficTop := vpnTrafficTop()
	drawRoundedRect(hdc, 56, trafficTop, 206, trafficTop+vpnTrafficHeight, 16, rgb(237, 244, 255), 0)
	drawRoundedRect(hdc, 224, trafficTop, 374, trafficTop+vpnTrafficHeight, 16, rgb(236, 253, 246), 0)
	drawTextInRect(hdc, "接收", 74, trafficTop+9, 180, trafficTop+25, rgb(114, 128, 154), uiSmallFont(), dtLeft|dtVCenter|dtSingleLine)
	drawTextInRect(hdc, formatBytes(traffic.RxBytes), 74, trafficTop+25, 190, trafficTop+43, rgb(36, 49, 79), uiRegularFont(), dtLeft|dtVCenter|dtSingleLine)
	drawTextInRect(hdc, "发送", 242, trafficTop+9, 348, trafficTop+25, rgb(114, 128, 154), uiSmallFont(), dtLeft|dtVCenter|dtSingleLine)
	drawTextInRect(hdc, formatBytes(traffic.TxBytes), 242, trafficTop+25, 358, trafficTop+43, rgb(36, 49, 79), uiRegularFont(), dtLeft|dtVCenter|dtSingleLine)

	version := strings.TrimSpace(embeddedClientVersion)
	if version == "" {
		version = "client-dev"
	}
	versionTop := vpnVersionTop()
	drawRoundedRect(hdc, 24, versionTop, 404, versionTop+vpnVersionHeight, 10, rgb(238, 242, 247), 0)
	drawTextInRect(hdc, "版本号 "+shortClientVersion(version), 34, versionTop, 404, versionTop+vpnVersionHeight, rgb(82, 96, 120), uiSmallFont(), dtLeft|dtVCenter|dtSingleLine)
}

func currentPaintStatus() string {
	runtimeState.mu.Lock()
	status := runtimeState.status
	running := (runtimeState.process != nil && runtimeState.process.Process != nil) || runtimeState.sshTunnel != nil || runtimeState.virtualTunnel != nil
	runtimeState.mu.Unlock()
	if connectBusy.Load() && !running {
		return "正在连接"
	}
	if !running && (status == "" || status == "未连接" || status == "已断开") {
		return "准备连接"
	}
	return status
}

func visibleProfileCount() int {
	count := 0
	for i := 0; i < maxProfileRows; i++ {
		if strings.TrimSpace(profileRowTarget[i]) != "" {
			count++
		}
	}
	return count
}

func shortClientVersion(version string) string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "client-")
	parts := strings.Split(version, "-")
	if len(parts) >= 5 {
		return fmt.Sprintf("%s-%s-%s-%s%s", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3]), strings.TrimSpace(parts[4]))
	}
	if len(parts) == 4 {
		return fmt.Sprintf("%s-%s-%s-%s", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3]))
	}
	if len(parts) >= 3 {
		datePart := strings.TrimSpace(parts[0])
		timePart := strings.TrimSpace(parts[1])
		msPart := strings.TrimSpace(parts[2])
		if len(datePart) == 8 && len(timePart) >= 4 {
			year := datePart[0:4]
			monthDay := datePart[4:8]
			hm := timePart[0:4]
			sec := "00"
			if len(timePart) >= 6 {
				sec = timePart[4:6]
			}
			if len(msPart) == 1 {
				msPart = "0" + msPart
			}
			if len(msPart) > 2 {
				msPart = msPart[0:2]
			}
			if len(msPart) < 2 {
				msPart = msPart + strings.Repeat("0", 2-len(msPart))
			}
			return fmt.Sprintf("%s-%s-%s-%s", year, monthDay, hm, sec+msPart)
		}
		if len(parts) >= 4 {
			return parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3]
		}
		return parts[0] + "-" + parts[1] + "-" + parts[2]
	}
	return version
}

func drawServerIcon(hdc uintptr, x, y int) {
	drawRoundedRect(hdc, x, y, x+54, y+54, 16, rgb(68, 80, 116), 0)
	drawRoundedRect(hdc, x+15, y+14, x+39, y+24, 5, rgb(255, 255, 255), 0)
	drawRoundedRect(hdc, x+15, y+29, x+39, y+39, 5, rgb(255, 255, 255), 0)
}

func drawPillText(hdc uintptr, text string, x, y, w, h int, bg, fg uint32, font uintptr) {
	drawRoundedRect(hdc, x, y, x+w, y+h, h/2, bg, 0)
	drawTextInRect(hdc, text, x+34, y, x+w-12, y+h, fg, font, dtLeft|dtVCenter|dtSingleLine)
}

func drawTextInRect(hdc uintptr, text string, left, top, right, bottom int, color uint32, font uintptr, flags uint32) {
	if text == "" {
		return
	}
	oldFont, _, _ := procSelectObject.Call(hdc, font)
	defer procSelectObject.Call(hdc, oldFont)
	procSetBkMode.Call(hdc, bkTransparent)
	procSetTextColor.Call(hdc, uintptr(color))
	r := rect{left: int32(left), top: int32(top), right: int32(right), bottom: int32(bottom)}
	procDrawText.Call(hdc, uintptr(unsafe.Pointer(utf16Ptr(text))), ^uintptr(0), uintptr(unsafe.Pointer(&r)), uintptr(flags))
}

func drawRoundedRect(hdc uintptr, left, top, right, bottom, radius int, fill uint32, outline uint32) {
	brush := createBrush(fill)
	penColor := outline
	if penColor == 0 {
		penColor = fill
	}
	pen, _, _ := procCreatePen.Call(psSolid, 1, uintptr(penColor))
	oldBrush, _, _ := procSelectObject.Call(hdc, brush)
	oldPen, _, _ := procSelectObject.Call(hdc, pen)
	defer func() {
		procSelectObject.Call(hdc, oldBrush)
		procSelectObject.Call(hdc, oldPen)
		procDeleteObject.Call(brush)
		procDeleteObject.Call(pen)
	}()
	procRoundRect.Call(hdc, uintptr(left), uintptr(top), uintptr(right), uintptr(bottom), uintptr(radius), uintptr(radius))
}

func drawCircle(hdc uintptr, cx, cy, r int, fill uint32) {
	brush := createBrush(fill)
	pen, _, _ := procCreatePen.Call(psSolid, 1, uintptr(fill))
	oldBrush, _, _ := procSelectObject.Call(hdc, brush)
	oldPen, _, _ := procSelectObject.Call(hdc, pen)
	defer func() {
		procSelectObject.Call(hdc, oldBrush)
		procSelectObject.Call(hdc, oldPen)
		procDeleteObject.Call(brush)
		procDeleteObject.Call(pen)
	}()
	procEllipse.Call(hdc, uintptr(cx-r), uintptr(cy-r), uintptr(cx+r), uintptr(cy+r))
}

func fillRect(hdc uintptr, left, top, right, bottom int, color uint32) {
	brush := createBrush(color)
	defer procDeleteObject.Call(brush)
	r := rect{left: int32(left), top: int32(top), right: int32(right), bottom: int32(bottom)}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), brush)
}

func createBrush(color uint32) uintptr {
	brush, _, _ := procCreateSolidBrush.Call(uintptr(color))
	return brush
}

func rgb(r, g, b byte) uint32 {
	return uint32(r) | uint32(g)<<8 | uint32(b)<<16
}

func uiRegularFont() uintptr {
	if uiFontRegular == 0 {
		uiFontRegular = createUIFont(14, 400)
	}
	return uiFontRegular
}

func uiBoldFont() uintptr {
	if uiFontBold == 0 {
		uiFontBold = createUIFont(16, 600)
	}
	return uiFontBold
}

func uiSmallFont() uintptr {
	if uiFontSmall == 0 {
		uiFontSmall = createUIFont(14, 400)
	}
	return uiFontSmall
}

func uiButtonFont() uintptr {
	if uiFontButton == 0 {
		uiFontButton = createUIFont(14, 400)
	}
	return uiFontButton
}

func createUIFont(size int, weight int) uintptr {
	font, _, _ := procCreateFont.Call(
		uintptr(-size),
		0, 0, 0,
		uintptr(weight),
		0, 0, 0,
		1,
		0, 0, 5, 0,
		uintptr(unsafe.Pointer(utf16Ptr("FangSong"))),
	)
	return font
}

func setUIFont(hwnd uintptr, bold bool) {
	if hwnd == 0 {
		return
	}
	font := uiRegularFont()
	if bold {
		font = uiBoldFont()
	}
	procSendMessage.Call(hwnd, wmSetFont, font, 1)
}

func setUIButtonFont(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	procSendMessage.Call(hwnd, wmSetFont, uiButtonFont(), 1)
}
