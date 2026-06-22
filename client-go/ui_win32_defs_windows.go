//go:build windows

package main

import (
	"sync/atomic"
	"syscall"
)

const (
	cwUseDefault    = 0x80000000
	wsOverlapped    = 0x00000000
	wsCaption       = 0x00C00000
	wsSysMenu       = 0x00080000
	wsThickFrame    = 0x00040000
	wsMinimizeBox   = 0x00020000
	wsMaximizeBox   = 0x00010000
	wsVisible       = 0x10000000
	wsChild         = 0x40000000
	wsVScroll       = 0x00200000
	wsBorder        = 0x00800000
	wsTabStop       = 0x00010000
	swpNoMove       = 0x0002
	swpNoZOrder     = 0x0004
	esMultiline     = 0x0004
	esPassword      = 0x0020
	esReadOnly      = 0x0800
	cbsDropDownList = 0x0003
	bsPushButton    = 0x00000000
	bsDefPushButton = 0x00000001
	bsAutoCheckBox  = 0x00000003
	bsOwnerDraw     = 0x0000000B
	bsFlat          = 0x00008000
	ssLeft          = 0x00000000
	ssCenter        = 0x00000001
	ssCenterImage   = 0x00000200

	wmCreate   = 0x0001
	wmDestroy  = 0x0002
	wmPaint    = 0x000F
	wmClose    = 0x0010
	wmCommand  = 0x0111
	wmDrawItem = 0x002B
	wmTimer    = 0x0113
	wmSetIcon  = 0x0080
	wmSetFont  = 0x0030
	iconSmall  = 0
	iconBig    = 1
	swHide     = 0
	swShow     = 5

	cbAddString    = 0x0143
	cbGetCount     = 0x0146
	cbResetContent = 0x014B
	cbGetCurSel    = 0x0147
	cbGetLbText    = 0x0148
	cbSetCurSel    = 0x014E
	wmSetText      = 0x000C
	wmGetTextLen   = 0x000E
	emSetSel       = 0x00B1
	emReplaceSel   = 0x00C2
	emScrollCaret  = 0x00B7
	bmGetCheck     = 0x00F0
	bmSetCheck     = 0x00F1
	bstChecked     = 1
	bkTransparent  = 1
	psSolid        = 0

	dtLeft        = 0x00000000
	dtCenter      = 0x00000001
	dtRight       = 0x00000002
	dtVCenter     = 0x00000004
	dtSingleLine  = 0x00000020
	dtEndEllipsis = 0x00008000

	odsSelected = 0x0001
	odsDisabled = 0x0004

	ofnFileMustExist = 0x00001000
	ofnPathMustExist = 0x00000800
	ofnExplorer      = 0x00080000
	mbYesNo          = 0x00000004
	mbIconQuestion   = 0x00000020
	idYes            = 6

	idImport      = 1001
	idConnect     = 1003
	idCombo       = 2001
	idStatus      = 2003
	idTraffic     = 2004
	idProfile     = 2006
	idProfileInfo = 2007
	idWebURL      = 2008
	idUsername    = 2009
	idPassword    = 2010
	idLogin       = 2011
	idRemember    = 2012
	idDialogOK    = 2401
	idDialogYes   = 2402
	idDialogNo    = 2403

	maxProfileRows       = 5
	idProfileConnectBase = 2100
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	comdlg32 = syscall.NewLazyDLL("comdlg32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procIsDialogMessage  = user32.NewProc("IsDialogMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procGetFocus         = user32.NewProc("GetFocus")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procSendMessage      = user32.NewProc("SendMessageW")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procGetWindowText    = user32.NewProc("GetWindowTextW")
	procSetWindowPos     = user32.NewProc("SetWindowPos")
	procShowWindow       = user32.NewProc("ShowWindow")
	procInvalidateRect   = user32.NewProc("InvalidateRect")
	procBeginPaint       = user32.NewProc("BeginPaint")
	procEndPaint         = user32.NewProc("EndPaint")
	procSetTimer         = user32.NewProc("SetTimer")
	procKillTimer        = user32.NewProc("KillTimer")
	procMessageBox       = user32.NewProc("MessageBoxW")
	procLoadIcon         = user32.NewProc("LoadIconW")
	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procCreateFont       = gdi32.NewProc("CreateFontW")
	procCreatePen        = gdi32.NewProc("CreatePen")
	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procSetBkMode        = gdi32.NewProc("SetBkMode")
	procSetTextColor     = gdi32.NewProc("SetTextColor")
	procFillRect         = user32.NewProc("FillRect")
	procRoundRect        = gdi32.NewProc("RoundRect")
	procEllipse          = gdi32.NewProc("Ellipse")
	procDrawText         = user32.NewProc("DrawTextW")
	procShellExecute     = shell32.NewProc("ShellExecuteW")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	procGetOpenFileName  = comdlg32.NewProc("GetOpenFileNameW")
	procGetTextExtent    = gdi32.NewProc("GetTextExtentPoint32W")

	mainWindow              uintptr
	comboBox                uintptr
	connectBtn              uintptr
	uiRefreshTimerRunning   atomic.Bool
	profileRowBox           uintptr
	profileRowLabel         [maxProfileRows]uintptr
	profileRowUser          [maxProfileRows]uintptr
	profileRowButton        [maxProfileRows]uintptr
	profileRowButtonShown   [maxProfileRows]bool
	profileRowButtonEnabled [maxProfileRows]bool
	statusText              uintptr
	trafficText             uintptr
	profileText             uintptr
	profileInfoText         uintptr
	webURLEdit              uintptr
	usernameEdit            uintptr
	passwordEdit            uintptr
	rememberCheck           uintptr
	versionText             uintptr
	statusMeasure           measuredTextControl
	trafficMeasure          measuredTextControl
	versionMeasure          measuredTextControl
	lastStatus              string
	lastTraffic             string
	lastConnect             string
	lastProfile             string
	lastProfileInfo         string
	lastVersion             string
	profileRowTarget        [maxProfileRows]string
	profileRowTitle         [maxProfileRows]string
	profileRowUsername      [maxProfileRows]string
	profileRowBtn           [maxProfileRows]string
	activeProfile           string
	selectedProfileTarget   string
	loginControls           []uintptr
	vpnControls             []uintptr
	vpnScreenVisible        bool
	uiFontRegular           uintptr
	uiFontBold              uintptr
	uiFontSmall             uintptr
	uiFontButton            uintptr
	connectBusy             atomic.Bool
)

type rect struct {
	left   int32
	top    int32
	right  int32
	bottom int32
}

type paintStruct struct {
	hdc         uintptr
	fErase      int32
	rcPaint     rect
	fRestore    int32
	fIncUpdate  int32
	rgbReserved [32]byte
}

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

type drawItemStruct struct {
	ctlType    uint32
	ctlID      uint32
	itemID     uint32
	itemAction uint32
	itemState  uint32
	hwndItem   uintptr
	hdc        uintptr
	rcItem     rect
	itemData   uintptr
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

type textSize struct {
	cx int32
	cy int32
}

type measuredControl struct {
	hwnd   uintptr
	x      int
	y      int
	width  int
	height int
}

type measuredTextControl struct {
	hwnd     uintptr
	x        int
	y        int
	paddingX int
	paddingY int
	centered bool
}

type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}
