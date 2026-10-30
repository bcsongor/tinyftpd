package main

import (
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The few Win32 calls the GUI needs. Without a Common Controls v6 manifest,
// Windows draws the classic controls.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	comctl32 = windows.NewLazySystemDLL("comctl32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	comdlg32 = windows.NewLazySystemDLL("comdlg32.dll")

	procDialogBoxIndirectParamW = user32.NewProc("DialogBoxIndirectParamW")
	procEndDialog               = user32.NewProc("EndDialog")
	procGetDlgItem              = user32.NewProc("GetDlgItem")
	procSetDlgItemTextW         = user32.NewProc("SetDlgItemTextW")
	procGetDlgItemTextW         = user32.NewProc("GetDlgItemTextW")
	procGetWindowTextLengthW    = user32.NewProc("GetWindowTextLengthW")
	procSendMessageW            = user32.NewProc("SendMessageW")
	procPostMessageW            = user32.NewProc("PostMessageW")
	procEnableWindow            = user32.NewProc("EnableWindow")
	procCheckDlgButton          = user32.NewProc("CheckDlgButton")
	procIsDlgButtonChecked      = user32.NewProc("IsDlgButtonChecked")
	procMapDialogRect           = user32.NewProc("MapDialogRect")
	procSetProcessDPIAware      = user32.NewProc("SetProcessDPIAware")
	procGetSystemMetrics        = user32.NewProc("GetSystemMetrics")
	procLoadImageW              = user32.NewProc("LoadImageW")
	procSetTimer                = user32.NewProc("SetTimer")
	procInitCommonControlsEx    = comctl32.NewProc("InitCommonControlsEx")
	procSHBrowseForFolderW      = shell32.NewProc("SHBrowseForFolderW")
	procSHGetPathFromIDListW    = shell32.NewProc("SHGetPathFromIDListW")
	procGetOpenFileNameW        = comdlg32.NewProc("GetOpenFileNameW")
)

const (
	wsPopup       = 0x80000000
	wsChild       = 0x40000000
	wsVisible     = 0x10000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsTabStop     = 0x00010000
	wsVScroll     = 0x00200000
	wsHScroll     = 0x00100000
	wsExEdge      = 0x00000200 // WS_EX_CLIENTEDGE

	dsSetFont    = 0x40
	dsModalFrame = 0x80
	dsCenter     = 0x800

	bsDefPushButton = 0x1
	bsAutoCheckBox  = 0x3
	esMultiline     = 0x4
	esPassword      = 0x20
	esAutoVScroll   = 0x40
	esAutoHScroll   = 0x80
	esReadOnly      = 0x800
	esNumber        = 0x2000
	cbsDropDownList = 0x3

	lvsReport        = 0x1
	lvsSingleSel     = 0x4
	lvsShowSelAlways = 0x8
	lvsNoSortHeader  = 0x8000
	lvsExFullRow     = 0x20

	wmClose      = 0x0010
	wmSetIcon    = 0x0080
	wmNotify     = 0x004E
	wmInitDialog = 0x0110
	wmCommand    = 0x0111
	wmTimer      = 0x0113
	wmApp        = 0x8000 // first message id free for the app's own use

	emSetSel       = 0x00B1
	emScrollCaret  = 0x00B7
	emReplaceSel   = 0x00C2
	emSetLimitText = 0x00C5

	cbAddString = 0x0143
	cbGetCurSel = 0x0147
	cbSetCurSel = 0x014E

	lvmDeleteAllItems = 0x1000 + 9
	lvmGetNextItem    = 0x1000 + 12
	lvmSetExStyle     = 0x1000 + 54
	lvmInsertItemW    = 0x1000 + 77
	lvmInsertColumnW  = 0x1000 + 97
	lvmSetItemTextW   = 0x1000 + 116
	lvcfWidth         = 0x2
	lvcfText          = 0x4
	lvifText          = 0x1
	lvniSelected      = 0x2
	nmDblClk          = -3

	idOK     = 1
	idCancel = 2
	idYes    = 6

	mbYesNo        = 0x04
	mbIconError    = 0x10
	mbIconQuestion = 0x20
	mbIconWarning  = 0x30
	mbIconInfo     = 0x40
)

// dialog is a dialog box template built in memory, so the GUI needs no
// resource compiler. Windows handles tab order, Enter, Esc and the font.
// Coordinates are dialog units, which scale with the font and DPI.
type dialog struct {
	title string
	style uint32
	w, h  int16
	items []control
}

type control struct {
	class      string // window class, e.g. "BUTTON" or "SysListView32"
	text       string
	id         uint16
	style, ex  uint32
	x, y, w, h int16
}

// template encodes d as a DLGTEMPLATE followed by DLGITEMTEMPLATEs.
func (d dialog) template() []uint16 {
	var t []uint16
	dword := func(v uint32) { t = append(t, uint16(v), uint16(v>>16)) }
	str := func(s string) { t = append(append(t, utf16.Encode([]rune(s))...), 0) }

	dword(wsPopup | wsCaption | wsSysMenu | dsSetFont | dsCenter | d.style)
	dword(0)
	t = append(t, uint16(len(d.items)), 0, 0, uint16(d.w), uint16(d.h))
	t = append(t, 0, 0) // no menu, default class
	str(d.title)
	t = append(t, 8) // point size
	str("MS Shell Dlg")
	for _, c := range d.items {
		if len(t)%2 == 1 { // items are DWORD aligned
			t = append(t, 0)
		}
		dword(wsChild | wsVisible | c.style)
		dword(c.ex)
		t = append(t, uint16(c.x), uint16(c.y), uint16(c.w), uint16(c.h), c.id)
		str(c.class)
		str(c.text)
		t = append(t, 0) // no creation data
	}
	return t
}

// run shows d modally and returns the value passed to EndDialog. proc must
// come from windows.NewCallback.
func (d dialog) run(owner, proc uintptr) uintptr {
	t := d.template()
	r, _, _ := procDialogBoxIndirectParamW.Call(0, uintptr(unsafe.Pointer(&t[0])), owner, proc, 0)
	return r
}

func endDialog(dlg, result uintptr) { procEndDialog.Call(dlg, result) }

func item(dlg uintptr, id uint16) uintptr {
	h, _, _ := procGetDlgItem.Call(dlg, uintptr(id))
	return h
}

func send(h uintptr, msg uint32, wp, lp uintptr) uintptr {
	r, _, _ := procSendMessageW.Call(h, uintptr(msg), wp, lp)
	return r
}

// post queues msg for the window and returns at once. Unlike send, it's safe
// from any goroutine.
func post(h uintptr, msg uint32) { procPostMessageW.Call(h, uintptr(msg), 0, 0) }

// sendPtr is send for messages whose lParam points at Go memory. The pointer
// must stay an unsafe.Pointer until the Call itself: converting it to uintptr
// any earlier lets the GC move or free what it points at.
func sendPtr(h uintptr, msg uint32, wp uintptr, lp unsafe.Pointer) uintptr {
	r, _, _ := procSendMessageW.Call(h, uintptr(msg), wp, uintptr(lp))
	return r
}

func text(dlg uintptr, id uint16) string {
	n, _, _ := procGetWindowTextLengthW.Call(item(dlg, id))
	buf := make([]uint16, n+1)
	procGetDlgItemTextW.Call(dlg, uintptr(id), uintptr(unsafe.Pointer(&buf[0])), n+1)
	return windows.UTF16ToString(buf)
}

func setText(dlg uintptr, id uint16, s string) {
	procSetDlgItemTextW.Call(dlg, uintptr(id), uintptr(unsafe.Pointer(utf16Ptr(s))))
}

// appendText adds s to the end of an edit control and scrolls to it.
func appendText(edit uintptr, s string) {
	n, _, _ := procGetWindowTextLengthW.Call(edit)
	send(edit, emSetSel, n, n)
	sendPtr(edit, emReplaceSel, 0, unsafe.Pointer(utf16Ptr(s)))
	send(edit, emScrollCaret, 0, 0)
}

// setTimer sends the window WM_TIMER every ms milliseconds until it closes.
func setTimer(h, ms uintptr) { procSetTimer.Call(h, 1, ms, 0) }

func enable(dlg uintptr, id uint16, on bool) {
	procEnableWindow.Call(item(dlg, id), boolArg(on))
}

func checked(dlg uintptr, id uint16) bool {
	r, _, _ := procIsDlgButtonChecked.Call(dlg, uintptr(id))
	return r == 1
}

func setChecked(dlg uintptr, id uint16, on bool) {
	procCheckDlgButton.Call(dlg, uintptr(id), boolArg(on))
}

// dluToPx converts a width in dialog units to pixels.
func dluToPx(dlg uintptr, w int32) int32 {
	r := windows.Rect{Right: w}
	procMapDialogRect.Call(dlg, uintptr(unsafe.Pointer(&r)))
	return r.Right
}

func messageBox(owner uintptr, msg string, flags uint32) int32 {
	r, _ := windows.MessageBox(windows.HWND(owner), utf16Ptr(msg), utf16Ptr("Tiny-FTPd"), flags)
	return r
}

type lvColumn struct {
	mask    uint32
	fmt     int32
	cx      int32
	text    *uint16
	textMax int32
	subItem int32
	image   int32
	order   int32
}

type lvItem struct {
	mask      uint32
	item      int32
	subItem   int32
	state     uint32
	stateMask uint32
	text      *uint16
	textMax   int32
	image     int32
	lParam    uintptr
	indent    int32
}

type nmhdr struct {
	hwndFrom uintptr
	idFrom   uintptr
	code     int32
}

func lvAddColumn(lv uintptr, i int, title string, width int32) {
	col := lvColumn{mask: lvcfText | lvcfWidth, cx: width, text: utf16Ptr(title)}
	sendPtr(lv, lvmInsertColumnW, uintptr(i), unsafe.Pointer(&col))
}

// lvSetRows replaces the list view's contents.
func lvSetRows(lv uintptr, rows [][]string) {
	send(lv, lvmDeleteAllItems, 0, 0)
	for i, row := range rows {
		for col, s := range row {
			it := lvItem{mask: lvifText, item: int32(i), subItem: int32(col), text: utf16Ptr(s)}
			if col == 0 {
				sendPtr(lv, lvmInsertItemW, 0, unsafe.Pointer(&it))
			} else {
				sendPtr(lv, lvmSetItemTextW, uintptr(i), unsafe.Pointer(&it))
			}
		}
	}
}

// lvSelected returns the selected row, or -1.
func lvSelected(lv uintptr) int {
	return int(int32(send(lv, lvmGetNextItem, ^uintptr(0), lvniSelected)))
}

func cbAdd(combo uintptr, s string) {
	sendPtr(combo, cbAddString, 0, unsafe.Pointer(utf16Ptr(s)))
}

// cbSelected returns the selected row, or -1.
func cbSelected(combo uintptr) int {
	return int(int32(send(combo, cbGetCurSel, 0, 0)))
}

func cbSetSelected(combo uintptr, i int) {
	send(combo, cbSetCurSel, uintptr(i), 0)
}

type browseInfo struct {
	owner       uintptr
	root        uintptr
	displayName *uint16
	title       *uint16
	flags       uint32
	fn          uintptr
	lParam      uintptr
	image       int32
}

// browseFolder shows the classic folder picker.
func browseFolder(owner uintptr, title string) (string, bool) {
	const returnOnlyFSDirs, newDialogStyle = 0x1, 0x40
	var name, path [windows.MAX_PATH]uint16
	bi := browseInfo{
		owner:       owner,
		displayName: &name[0],
		title:       utf16Ptr(title),
		flags:       returnOnlyFSDirs | newDialogStyle,
	}
	pidl, _, _ := procSHBrowseForFolderW.Call(uintptr(unsafe.Pointer(&bi)))
	if pidl == 0 {
		return "", false
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(pidl))
	if ok, _, _ := procSHGetPathFromIDListW.Call(pidl, uintptr(unsafe.Pointer(&path[0]))); ok == 0 {
		return "", false
	}
	return windows.UTF16ToString(path[:]), true
}

// setIcon gives a window the APP icon embedded from winres/, at the exact
// small and large sizes so the hand-drawn 16x16 isn't a scaled-down 32x32.
func setIcon(h uintptr) {
	var exe windows.Handle
	windows.GetModuleHandleEx(0, nil, &exe)
	const iconSmall, iconBig, smCXSmIcon, smCXIcon, imageIcon = 0, 1, 49, 11, 1
	for _, size := range [][2]uintptr{{iconSmall, smCXSmIcon}, {iconBig, smCXIcon}} {
		px, _, _ := procGetSystemMetrics.Call(size[1])
		icon, _, _ := procLoadImageW.Call(uintptr(exe), uintptr(unsafe.Pointer(utf16Ptr("APP"))), imageIcon, px, px, 0)
		send(h, wmSetIcon, size[0], icon)
	}
}

type openFileName struct {
	structSize    uint32
	owner         uintptr
	instance      uintptr
	filter        *uint16
	customFilter  *uint16
	maxCustFilter uint32
	filterIndex   uint32
	file          *uint16
	maxFile       uint32
	fileTitle     *uint16
	maxFileTitle  uint32
	initialDir    *uint16
	title         *uint16
	flags         uint32
	fileOffset    uint16
	fileExtension uint16
	defExt        *uint16
	custData      uintptr
	hook          uintptr
	templateName  *uint16
	reserved      uintptr
	reserved2     uint32
	flagsEx       uint32
}

// openFile shows the file-open dialog for PEM files, starting at current.
func openFile(owner uintptr, title, current string) (string, bool) {
	const explorer, fileMustExist, pathMustExist, hideReadOnly, noChangeDir = 0x80000, 0x1000, 0x800, 0x4, 0x8
	file := make([]uint16, 32768)
	copy(file[:len(file)-1], utf16.Encode([]rune(current)))
	// Filter pairs are NUL-separated, ending with two NULs.
	filter := utf16.Encode([]rune("PEM files (*.pem, *.crt, *.cer, *.key)\x00*.pem;*.crt;*.cer;*.key\x00All files\x00*.*\x00\x00"))
	ofn := openFileName{
		owner:   owner,
		filter:  &filter[0],
		file:    &file[0],
		maxFile: uint32(len(file)),
		title:   utf16Ptr(title),
		flags:   explorer | fileMustExist | pathMustExist | hideReadOnly | noChangeDir,
	}
	ofn.structSize = uint32(unsafe.Sizeof(ofn))
	if ok, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn))); ok == 0 {
		return "", false
	}
	return windows.UTF16ToString(file), true
}

// initUI prepares the calling thread for the GUI.
func initUI() {
	procSetProcessDPIAware.Call()
	icc := struct{ size, classes uint32 }{8, 0x1} // ICC_LISTVIEW_CLASSES
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
	// The folder picker's new dialog style needs COM.
	windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED)
}

func utf16Ptr(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil { // s contains a NUL
		return &[]uint16{0}[0]
	}
	return p
}

func boolArg(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
