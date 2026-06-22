package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func waitForOldProcess(rawPID string, timeout time.Duration) bool {
	rawPID = strings.TrimSpace(rawPID)
	if rawPID == "" {
		time.Sleep(800 * time.Millisecond)
		return false
	}
	pid, err := strconv.Atoi(rawPID)
	if err != nil || pid <= 0 {
		time.Sleep(800 * time.Millisecond)
		return false
	}
	handle, _, _ := procOpenProcess.Call(synchronize|processTerminate, 0, uintptr(pid))
	if handle == 0 {
		return false
	}
	defer procCloseHandle.Call(handle)
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			updateDetail("旧客户端未响应，正在强制结束进程...")
			procTerminateProcess.Call(handle, 0)
			waitAfterKill(handle, 5*time.Second)
			return true
		}
		waitMS := uintptr(250)
		if remaining < 250*time.Millisecond {
			waitMS = uintptr(remaining / time.Millisecond)
		}
		ret, _, _ := procWaitForSingle.Call(handle, waitMS)
		if ret != waitTimeout {
			return false
		}
		updateDetail(fmt.Sprintf("正在等待旧客户端进程关闭...%d 秒", int(remaining.Seconds())+1))
	}
}

func waitAfterKill(handle uintptr, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ret, _, _ := procWaitForSingle.Call(handle, 250)
		if ret != waitTimeout {
			return
		}
	}
}

func waitForWindow() {
	for i := 0; i < 100; i++ {
		if mainWindow != 0 && statusText != 0 && detailText != 0 && progress != 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
