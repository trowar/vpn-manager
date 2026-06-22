package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsBorder      = 0x00800000
	ssLeft        = 0x00000000
	ssCenterImage = 0x00000200

	wmCreate  = 0x0001
	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmTimer   = 0x0113
	wmSetText = 0x000C

	synchronize      = 0x00100000
	processTerminate = 0x00000001
	waitTimeout      = 0x00000102

	pbmSetRange = 0x0401
	pbmSetPos   = 0x0402
	swShow      = 5
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procPostMessage      = user32.NewProc("PostMessageW")
	procSendMessage      = user32.NewProc("SendMessageW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetTimer         = user32.NewProc("SetTimer")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	procOpenProcess      = kernel32.NewProc("OpenProcess")
	procWaitForSingle    = kernel32.NewProc("WaitForSingleObject")
	procTerminateProcess = kernel32.NewProc("TerminateProcess")
	procCloseHandle      = kernel32.NewProc("CloseHandle")
	procInitCommonCtl    = comctl32.NewProc("InitCommonControls")
	procShellExecute     = shell32.NewProc("ShellExecuteW")

	mainWindow uintptr
	statusText uintptr
	detailText uintptr
	progress   uintptr

	stateMu          sync.Mutex
	pendingStatus    = "准备更新..."
	pendingDetail    = ""
	pendingProgress  = 0
	renderedStatus   string
	renderedDetail   string
	renderedProgress = -1
)

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type point struct {
	x int32
	y int32
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

func main() {
	downloadURL := flag.String("url", "", "client package download URL")
	targetDir := flag.String("target", "", "target install directory")
	exeName := flag.String("exe", "CompanyVPN.exe", "main executable name")
	version := flag.String("version", "", "target version")
	waitPID := flag.String("wait-pid", "", "old client process id")
	flag.Parse()

	go func() {
		waitForWindow()
		if err := run(*downloadURL, *targetDir, *exeName, *version, *waitPID); err != nil {
			updateStatus("更新失败: " + err.Error())
			_ = os.WriteFile(filepath.Join(os.TempDir(), "CompanyVPN-updater-error.log"), []byte(err.Error()), 0644)
			time.Sleep(5 * time.Second)
		}
		if mainWindow != 0 {
			procPostMessage.Call(mainWindow, wmClose, 0, 0)
		} else {
			procPostQuitMessage.Call(0)
		}
	}()
	_ = launchUI()
}

func launchUI() error {
	procInitCommonCtl.Call()
	hInstance, _, _ := procGetModuleHandle.Call(0)
	className := utf16Ptr("CompanyVPNUpdaterWindow")
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   syscall.NewCallback(windowProc),
		hInstance:     hInstance,
		hbrBackground: 6,
		lpszClassName: className,
	}
	if ret, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); ret == 0 {
		return fmt.Errorf("register window failed: %v", err)
	}
	hwnd, _, err := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16Ptr("Company VPN Updater"))),
		uintptr(wsOverlapped|wsCaption|wsSysMenu|wsVisible),
		300,
		220,
		440,
		210,
		0,
		0,
		hInstance,
		0,
	)
	if hwnd == 0 {
		return fmt.Errorf("create window failed: %v", err)
	}
	mainWindow = hwnd
	procShowWindow.Call(hwnd, swShow)
	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}

func windowProc(hwnd uintptr, msg uint32, wParam uintptr, lParam uintptr) uintptr {
	switch msg {
	case wmCreate:
		statusText = create("STATIC", "准备更新...", wsChild|wsVisible|ssLeft|ssCenterImage, 26, 22, 372, 34, hwnd, 0)
		detailText = create("STATIC", "", wsChild|wsVisible|ssLeft|ssCenterImage, 26, 62, 372, 24, hwnd, 0)
		progress = create("msctls_progress32", "", wsChild|wsVisible|wsBorder, 26, 98, 372, 28, hwnd, 0)
		procSendMessage.Call(progress, pbmSetRange, 0, uintptr(100<<16))
		flushUIState()
		procSetTimer.Call(hwnd, 1, 100, 0)
		return 0
	case wmTimer:
		flushUIState()
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProc.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
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
