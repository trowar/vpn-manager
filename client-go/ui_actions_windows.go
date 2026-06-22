//go:build windows

package main

import (
	"fmt"
	"strings"
)

func importClicked(hwnd uintptr) {
	path := chooseJSONFile(hwnd)
	if path == "" {
		return
	}
	bundle, err := loadBootstrap(path)
	if err != nil {
		showMessage("导入失败", err.Error())
		return
	}
	if err := storeCurrentBootstrap(bundle); err != nil {
		showMessage("保存失败", err.Error())
		return
	}
	appendLog("已导入配置包: " + bundle.Name)
	refreshProfileCombo()
	updateSelectedProfileText()
	showVPNScreen()
	showMessage("导入成功", "已导入："+bundle.Name)
}

func loginClicked(hwnd uintptr) {
	webURL := getControlText(webURLEdit)
	username := getControlText(usernameEdit)
	password := getControlText(passwordEdit)
	rememberPassword := isChecked(rememberCheck)
	if strings.TrimSpace(webURL) == "" || strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		showMessage("登录失败", "请填写 Web 地址、账号和密码。")
		return
	}
	appendLog("正在登录并获取服务器权限...")
	bundle, err := loginWithPassword(webURL, username, password)
	if err != nil {
		appendLog("登录失败: " + err.Error())
		showMessage("登录失败", err.Error())
		return
	}
	if err := storeCurrentBootstrap(bundle); err != nil {
		appendLog("保存登录配置失败: " + err.Error())
		showMessage("保存失败", err.Error())
		return
	}
	if err := saveLoginCredentials(webURL, username, password, rememberPassword); err != nil {
		appendLog("保存账号密码失败: " + err.Error())
	} else if rememberPassword {
		appendLog("已保存账号密码到本机加密配置")
	} else {
		appendLog("未勾选保存密码，仅保存用户名")
	}
	appendLog(fmt.Sprintf("登录成功: %s，可用线路 %d 个", bundle.Account, len(bundle.Profiles)))
	refreshProfileCombo()
	updateSelectedProfileText()
	showVPNScreen()
}
