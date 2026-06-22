//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var (
	elevationShell32          = syscall.NewLazyDLL("shell32.dll")
	elevationAdvapi32         = syscall.NewLazyDLL("advapi32.dll")
	procShellExecuteElevated  = elevationShell32.NewProc("ShellExecuteW")
	procAllocateInitializeSid = elevationAdvapi32.NewProc("AllocateAndInitializeSid")
	procCheckTokenMembership  = elevationAdvapi32.NewProc("CheckTokenMembership")
	procFreeSid               = elevationAdvapi32.NewProc("FreeSid")
)

func ensureElevatedOrRelaunch(args []string) (bool, error) {
	elevated, err := isProcessElevated()
	if err != nil || elevated {
		return false, nil
	}
	exePath, err := os.Executable()
	if err != nil {
		return false, err
	}
	ret, _, callErr := procShellExecuteElevated.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr("runas"))),
		uintptr(unsafe.Pointer(utf16Ptr(exePath))),
		0,
		0,
		swShow,
	)
	if ret <= 32 {
		if callErr != syscall.Errno(0) {
			return false, callErr
		}
		return false, errors.New("需要管理员权限创建虚拟网卡，请允许 Windows 权限确认")
	}
	return true, nil
}

func isProcessElevated() (bool, error) {
	var ntAuthority = [6]byte{0, 0, 0, 0, 0, 5}
	var adminGroup uintptr
	ret, _, err := procAllocateInitializeSid.Call(
		uintptr(unsafe.Pointer(&ntAuthority[0])),
		2,
		32,
		544,
		0,
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&adminGroup)),
	)
	if ret == 0 {
		return false, err
	}
	defer procFreeSid.Call(adminGroup)
	var isMember int32
	ret, _, err = procCheckTokenMembership.Call(
		0,
		adminGroup,
		uintptr(unsafe.Pointer(&isMember)),
	)
	if ret == 0 {
		return false, err
	}
	return isMember != 0, nil
}
