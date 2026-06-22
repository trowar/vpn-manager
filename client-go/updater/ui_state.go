package main

import "unsafe"

func updateStatus(text string) {
	stateMu.Lock()
	pendingStatus = text
	stateMu.Unlock()
}

func updateDetail(text string) {
	stateMu.Lock()
	pendingDetail = text
	stateMu.Unlock()
}

func setProgress(value int) {
	if value < 0 {
		value = 0
	}
	if value > 100 {
		value = 100
	}
	stateMu.Lock()
	pendingProgress = value
	stateMu.Unlock()
}

func flushUIState() {
	stateMu.Lock()
	status := pendingStatus
	detail := pendingDetail
	progressValue := pendingProgress
	stateMu.Unlock()
	if statusText != 0 && status != renderedStatus {
		procSendMessage.Call(statusText, wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(status))))
		renderedStatus = status
	}
	if detailText != 0 && detail != renderedDetail {
		procSendMessage.Call(detailText, wmSetText, 0, uintptr(unsafe.Pointer(utf16Ptr(detail))))
		renderedDetail = detail
	}
	if progress != 0 && progressValue != renderedProgress {
		procSendMessage.Call(progress, pbmSetPos, uintptr(progressValue), 0)
		renderedProgress = progressValue
	}
}
