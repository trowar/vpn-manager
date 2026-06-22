//go:build windows

package main

const (
	uiStatusRefreshTimerID       = 2
	uiStatusRefreshIntervalMilli = 1500
)

func uiRefreshNeeded() bool {
	if !vpnScreenVisible {
		return false
	}
	if connectBusy.Load() {
		return true
	}
	if isRuntimeDisconnecting() {
		return true
	}
	return isRuntimeConnected()
}

func ensureUIRefreshState() {
	if uiRefreshNeeded() {
		startUIRefreshTimer()
		return
	}
	stopUIRefreshTimer()
}

func startUIRefreshTimer() {
	if mainWindow == 0 {
		return
	}
	if uiRefreshTimerRunning.Load() {
		return
	}
	procSetTimer.Call(mainWindow, uiStatusRefreshTimerID, uiStatusRefreshIntervalMilli, 0)
	uiRefreshTimerRunning.Store(true)
}

func stopUIRefreshTimer() {
	if mainWindow == 0 {
		return
	}
	if !uiRefreshTimerRunning.Load() {
		return
	}
	procKillTimer.Call(mainWindow, uiStatusRefreshTimerID)
	uiRefreshTimerRunning.Store(false)
}
