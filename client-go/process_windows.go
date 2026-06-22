//go:build windows

package main

import (
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x00002000
	processSetQuota                   = 0x0100
	processTerminate                  = 0x0001
)

var (
	jobKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObject         = jobKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject = jobKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJob      = jobKernel32.NewProc("AssignProcessToJobObject")
	childJobOnce                sync.Once
	childJobHandle              syscall.Handle
	childJobErr                 error
)

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

func configureCoreProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
}

func attachCoreProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	job, err := ensureChildJob()
	if err != nil {
		return err
	}
	handle, err := syscall.OpenProcess(processSetQuota|processTerminate, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(handle)
	ret, _, callErr := procAssignProcessToJob.Call(uintptr(job), uintptr(handle))
	if ret == 0 {
		return callErr
	}
	return nil
}

func ensureChildJob() (syscall.Handle, error) {
	childJobOnce.Do(func() {
		ret, _, err := procCreateJobObject.Call(0, 0)
		if ret == 0 {
			childJobErr = err
			return
		}
		childJobHandle = syscall.Handle(ret)
		info := jobObjectExtendedLimitInfo{}
		info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
		ret, _, err = procSetInformationJobObject.Call(
			uintptr(childJobHandle),
			uintptr(jobObjectExtendedLimitInformation),
			uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info),
		)
		if ret == 0 {
			childJobErr = err
		}
	})
	return childJobHandle, childJobErr
}

func cleanupCoreBeforeStart(profile Profile) {
	if profile.Type == "openvpn" {
		return
	}
	for _, name := range []string{"mihomo.exe", "clash.exe"} {
		cmd := exec.Command("taskkill", "/IM", name, "/F")
		configureCoreProcess(cmd)
		_ = cmd.Run()
	}
}
