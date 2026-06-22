//go:build windows

package main

import "unsafe"

func ownerDrawButtonStyle(defaultButton bool) int {
	style := wsChild | wsTabStop | bsOwnerDraw
	if defaultButton {
		style |= bsDefPushButton
	}
	return style
}

func paintOwnerDrawButton(lParam uintptr) uintptr {
	item := (*drawItemStruct)(unsafe.Pointer(lParam))
	if item == nil || item.hdc == 0 {
		return 0
	}
	text := buttonTextByID(int(item.ctlID))
	bg := rgb(17, 126, 118)
	border := rgb(13, 96, 90)
	fg := rgb(255, 255, 255)
	if item.itemState&odsDisabled != 0 {
		bg = rgb(218, 226, 237)
		border = rgb(190, 200, 214)
		fg = rgb(102, 116, 139)
	} else if item.itemState&odsSelected != 0 {
		bg = rgb(12, 93, 87)
		border = rgb(9, 76, 72)
	}
	drawRoundedRect(item.hdc, int(item.rcItem.left), int(item.rcItem.top), int(item.rcItem.right), int(item.rcItem.bottom), 8, bg, border)
	drawTextInRect(
		item.hdc,
		text,
		int(item.rcItem.left),
		int(item.rcItem.top),
		int(item.rcItem.right),
		int(item.rcItem.bottom),
		fg,
		uiButtonFont(),
		dtCenter|dtVCenter|dtSingleLine,
	)
	return 1
}

func buttonTextByID(id int) string {
	if id >= idProfileConnectBase && id < idProfileConnectBase+maxProfileRows {
		index := id - idProfileConnectBase
		if index >= 0 && index < maxProfileRows && profileRowBtn[index] != "" {
			return profileRowBtn[index]
		}
		return "连接"
	}
	switch id {
	case idLogin:
		return "登录"
	case idDialogOK:
		return "确定"
	case idDialogYes:
		return "是(Y)"
	case idDialogNo:
		return "否(N)"
	default:
		return ""
	}
}
