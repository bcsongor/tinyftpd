package main

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	idListen uint16 = 100 + iota
	idPort
	idToggle
	idUsers
	idAdd
	idEdit
	idRemove
	idShowLog
	idShowSettings
	idStatus
	idName
	idPassword
	idHint
	idFolder
	idBrowse
	idReadOnly
	idBypass
	idStart
	idStartBrowse
	idLog
	idTLS
	idCert
	idCertBrowse
	idKey
	idKeyBrowse
	idSelfSign
	idMaxConns
	idPostQuantum
	idWeb
	idWebPort
)

// wmServerDone tells the main dialog the servers have stopped, and their
// result is waiting in app.done.
const wmServerDone = wmApp

var mainDialog = dialog{
	title: "Tiny-FTPd",
	style: wsMinimizeBox,
	w:     260, h: 154,
	items: []control{
		{class: "STATIC", text: "&Listen on:", x: 7, y: 9, w: 36, h: 8},
		{class: "COMBOBOX", id: idListen, style: wsTabStop | wsVScroll | cbsDropDownList, x: 45, y: 7, w: 90, h: 80},
		{class: "STATIC", text: "&Port:", x: 141, y: 9, w: 18, h: 8},
		{class: "EDIT", id: idPort, style: wsTabStop | esNumber | esAutoHScroll, ex: wsExEdge, x: 161, y: 7, w: 30, h: 12},
		{class: "BUTTON", text: "&Start", id: idToggle, style: wsTabStop, x: 203, y: 6, w: 50, h: 14},
		{class: "SysListView32", id: idUsers, style: wsTabStop | lvsReport | lvsSingleSel | lvsShowSelAlways | lvsNoSortHeader, ex: wsExEdge, x: 7, y: 26, w: 190, h: 100},
		{class: "BUTTON", text: "&Add...", id: idAdd, style: wsTabStop, x: 203, y: 26, w: 50, h: 14},
		{class: "BUTTON", text: "&Edit...", id: idEdit, style: wsTabStop, x: 203, y: 44, w: 50, h: 14},
		{class: "BUTTON", text: "&Remove", id: idRemove, style: wsTabStop, x: 203, y: 62, w: 50, h: 14},
		{class: "BUTTON", text: "&Settings...", id: idShowSettings, style: wsTabStop, x: 203, y: 94, w: 50, h: 14},
		{class: "BUTTON", text: "L&og...", id: idShowLog, style: wsTabStop, x: 203, y: 112, w: 50, h: 14},
		{class: "STATIC", id: idStatus, x: 7, y: 132, w: 246, h: 16},
	},
}

var userDialog = dialog{
	style: dsModalFrame,
	w:     220, h: 143,
	items: []control{
		{class: "STATIC", text: "&Username:", x: 7, y: 9, w: 46, h: 8},
		{class: "EDIT", id: idName, style: wsTabStop | esAutoHScroll, ex: wsExEdge, x: 56, y: 7, w: 157, h: 12},
		{class: "STATIC", text: "&Password:", x: 7, y: 25, w: 46, h: 8},
		{class: "EDIT", id: idPassword, style: wsTabStop | esAutoHScroll | esPassword, ex: wsExEdge, x: 56, y: 23, w: 157, h: 12},
		{class: "STATIC", id: idHint, x: 56, y: 37, w: 157, h: 8},
		{class: "STATIC", text: "&Jail folder:", x: 7, y: 51, w: 46, h: 8},
		{class: "EDIT", id: idFolder, style: wsTabStop | esAutoHScroll, ex: wsExEdge, x: 56, y: 49, w: 107, h: 12},
		{class: "BUTTON", text: "&Browse...", id: idBrowse, style: wsTabStop, x: 166, y: 48, w: 47, h: 14},
		{class: "STATIC", text: "S&tart folder:", x: 7, y: 67, w: 46, h: 8},
		{class: "EDIT", id: idStart, style: wsTabStop | esAutoHScroll, ex: wsExEdge, x: 56, y: 65, w: 107, h: 12},
		{class: "BUTTON", text: "Br&owse...", id: idStartBrowse, style: wsTabStop, x: 166, y: 64, w: 47, h: 14},
		{class: "STATIC", text: "Optional, inside the jail. Blank starts at the top.", x: 56, y: 79, w: 157, h: 8},
		{class: "BUTTON", text: "&Read-only", id: idReadOnly, style: wsTabStop | bsAutoCheckBox, x: 56, y: 92, w: 80, h: 10},
		{class: "BUTTON", text: "Bypass the connection &limit", id: idBypass, style: wsTabStop | bsAutoCheckBox, x: 56, y: 106, w: 157, h: 10},
		{class: "BUTTON", text: "OK", id: idOK, style: wsTabStop | bsDefPushButton, x: 110, y: 122, w: 50, h: 14},
		{class: "BUTTON", text: "Cancel", id: idCancel, style: wsTabStop, x: 163, y: 122, w: 50, h: 14},
	},
}

var settingsDialog = dialog{
	title: "Settings",
	style: dsModalFrame,
	w:     240, h: 158,
	items: []control{
		{class: "STATIC", text: "&Maximum connections:", x: 7, y: 9, w: 78, h: 8},
		{class: "EDIT", id: idMaxConns, style: wsTabStop | esNumber, ex: wsExEdge, x: 88, y: 7, w: 30, h: 12},
		{class: "STATIC", text: "0 means no limit", x: 124, y: 9, w: 109, h: 8},
		{class: "BUTTON", text: "Enable &web browser on port", id: idWeb, style: wsTabStop | bsAutoCheckBox, x: 7, y: 25, w: 106, h: 10},
		{class: "EDIT", id: idWebPort, style: wsTabStop | esNumber, ex: wsExEdge, x: 116, y: 23, w: 30, h: 12},
		{class: "BUTTON", text: "&Require TLS (explicit FTPS) for all connections", id: idTLS, style: wsTabStop | bsAutoCheckBox, x: 7, y: 43, w: 226, h: 10},
		{class: "BUTTON", text: "Require &post-quantum key exchange (TLS 1.3 with ML-KEM)", id: idPostQuantum, style: wsTabStop | bsAutoCheckBox, x: 7, y: 57, w: 226, h: 10},
		{class: "STATIC", text: "&Certificate:", x: 7, y: 75, w: 44, h: 8},
		{class: "EDIT", id: idCert, style: wsTabStop | esAutoHScroll, ex: wsExEdge, x: 54, y: 73, w: 128, h: 12},
		{class: "BUTTON", text: "&Browse...", id: idCertBrowse, style: wsTabStop, x: 185, y: 72, w: 48, h: 14},
		{class: "STATIC", text: "Private &key:", x: 7, y: 93, w: 44, h: 8},
		{class: "EDIT", id: idKey, style: wsTabStop | esAutoHScroll, ex: wsExEdge, x: 54, y: 91, w: 128, h: 12},
		{class: "BUTTON", text: "Br&owse...", id: idKeyBrowse, style: wsTabStop, x: 185, y: 90, w: 48, h: 14},
		{class: "STATIC", text: "PEM files. The certificate may include the chain.", x: 54, y: 107, w: 179, h: 8},
		{class: "BUTTON", text: "&Generate self-signed", id: idSelfSign, style: wsTabStop, x: 7, y: 121, w: 118, h: 14},
		{class: "BUTTON", text: "OK", id: idOK, style: wsTabStop | bsDefPushButton, x: 130, y: 137, w: 50, h: 14},
		{class: "BUTTON", text: "Cancel", id: idCancel, style: wsTabStop, x: 183, y: 137, w: 50, h: 14},
	},
}

// logDialog shows recent server log lines. The text box isn't a tab stop, so
// it opens with focus on Close rather than with all its text selected.
var logDialog = dialog{
	title: "Tiny-FTPd log",
	w:     420, h: 240,
	items: []control{
		{class: "EDIT", id: idLog, style: wsVScroll | wsHScroll | esMultiline | esReadOnly | esAutoVScroll | esAutoHScroll, ex: wsExEdge, x: 7, y: 7, w: 406, h: 206},
		{class: "BUTTON", text: "Close", id: idCancel, style: wsTabStop | bsDefPushButton, x: 363, y: 219, w: 50, h: 14},
	},
}

// app is the GUI state. Dialog procedures all run on the GUI thread, so it
// needs no locking.
type app struct {
	path         string
	cfg          Config
	ips          []string           // listen addresses in the dropdown; "" means all
	stop         context.CancelFunc // stops the servers; nil once asked to
	done         chan error         // the servers' result; nil once they've stopped
	userProc     uintptr            // callback for userDialog
	editing      int                // index of the user being edited, -1 when adding
	logs         logBuffer          // recent log lines, for logDialog
	logProc      uintptr            // callback for logDialog
	settingsProc uintptr            // callback for settingsDialog
	logShown     int                // log lines already in logDialog
}

func runGUI(path string) error {
	// Win32 windows belong to the thread that created them.
	runtime.LockOSThread()
	initUI()

	cfg, err := loadConfig(path)
	if err != nil {
		messageBox(0, err.Error(), mbIconError)
		return err
	}
	a := &app{path: path, cfg: cfg}
	// The server logs through slog's default logger, which writes here.
	log.SetOutput(&a.logs)
	a.userProc = windows.NewCallback(a.userDialogProc)
	a.logProc = windows.NewCallback(a.logDialogProc)
	a.settingsProc = windows.NewCallback(a.settingsDialogProc)
	mainDialog.run(0, windows.NewCallback(a.mainDialogProc))
	return nil
}

func (a *app) mainDialogProc(dlg, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmInitDialog:
		setIcon(dlg)
		a.ips = append([]string{""}, localIPs()...)
		// Keep a saved address that's currently missing, e.g. a VPN that's down.
		if !slices.Contains(a.ips, a.cfg.ListenIP) {
			a.ips = append(a.ips, a.cfg.ListenIP)
		}
		combo := item(dlg, idListen)
		for _, ip := range a.ips {
			cbAdd(combo, cmp.Or(ip, "All addresses"))
		}
		cbSetSelected(combo, slices.Index(a.ips, a.cfg.ListenIP))
		setText(dlg, idPort, strconv.Itoa(a.cfg.Port))
		lv := item(dlg, idUsers)
		send(lv, lvmSetExStyle, lvsExFullRow, lvsExFullRow)
		lvAddColumn(lv, 0, "User", dluToPx(dlg, 40))
		lvAddColumn(lv, 1, "Folder", dluToPx(dlg, 86))
		lvAddColumn(lv, 2, "Access", dluToPx(dlg, 56))
		a.refresh(dlg)
		a.showStatus(dlg)
		return 1

	case wmCommand:
		switch uint16(wp) {
		case idToggle:
			switch {
			case a.stop != nil:
				a.stop()
				a.stop = nil
			case a.done == nil:
				a.start(dlg)
			}
			a.showStatus(dlg)
		case idAdd:
			a.editUser(dlg, -1)
		case idEdit:
			if i := lvSelected(item(dlg, idUsers)); i >= 0 {
				a.editUser(dlg, i)
			}
		case idRemove:
			a.removeUser(dlg)
		case idShowLog:
			logDialog.run(dlg, a.logProc)
		case idShowSettings:
			d := settingsDialog
			if a.done != nil {
				d.title = "Settings (running, stop the server to change them)"
			}
			d.run(dlg, a.settingsProc)
		}
		return 1

	case wmNotify:
		h := (*nmhdr)(unsafe.Pointer(lp))
		if h.idFrom == uintptr(idUsers) && h.code == nmDblClk {
			if i := lvSelected(h.hwndFrom); i >= 0 {
				a.editUser(dlg, i)
			}
		}

	case wmServerDone:
		err := <-a.done
		a.done = nil
		stoppedItself := a.stop != nil
		if stoppedItself {
			a.stop()
			a.stop = nil
		}
		a.showStatus(dlg)
		if stoppedItself && err != nil {
			slog.Error("Tiny-FTPd stopped", "err", err)
			messageBox(dlg, "The server stopped:\n"+err.Error(), mbIconError)
		} else {
			slog.Info("Tiny-FTPd stopped")
		}
		return 1

	case wmClose:
		if a.stop != nil {
			a.stop()
		}
		endDialog(dlg, 0)
		return 1
	}
	return 0
}

// start saves the address and port, then starts the servers. A goroutine
// waits for them and posts wmServerDone once they've stopped, whether asked
// to or not.
func (a *app) start(dlg uintptr) {
	port, err := strconv.Atoi(text(dlg, idPort))
	if err != nil {
		messageBox(dlg, "The port must be a number.", mbIconError)
		return
	}
	cfg := a.cfg
	cfg.Port, cfg.ListenIP = port, a.ips[max(cbSelected(item(dlg, idListen)), 0)]
	if err := cfg.validate(); err != nil {
		messageBox(dlg, err.Error(), mbIconError)
		return
	}
	if (cfg.Port != a.cfg.Port || cfg.ListenIP != a.cfg.ListenIP) && !a.commit(dlg, cfg) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	wait, err := start(ctx, a.path, a.cfg)
	if err != nil {
		cancel()
		messageBox(dlg, "Can't start the server:\n"+err.Error(), mbIconError)
		return
	}
	done := make(chan error, 1)
	go func() {
		done <- wait()
		post(dlg, wmServerDone)
	}()
	a.stop, a.done = cancel, done
	slog.Info("Tiny-FTPd is running on " + a.cfg.addresses())
}

// showStatus reflects whether the servers are running, stopping or stopped.
func (a *app) showStatus(dlg uintptr) {
	stopped := a.done == nil
	enable(dlg, idListen, stopped)
	enable(dlg, idPort, stopped)
	enable(dlg, idToggle, stopped || a.stop != nil)
	switch {
	case a.stop != nil:
		setText(dlg, idToggle, "&Stop")
		setText(dlg, idStatus, "Running on "+a.cfg.addresses())
	case !stopped:
		setText(dlg, idStatus, "Stopping...")
	default:
		setText(dlg, idToggle, "&Start")
		setText(dlg, idStatus, "Stopped")
	}
}

func (a *app) refresh(dlg uintptr) {
	rows := make([][]string, len(a.cfg.Users))
	for i, u := range a.cfg.Users {
		rows[i] = []string{u.Name, u.Root, access(u)}
	}
	lvSetRows(item(dlg, idUsers), rows)
}

// commit saves cfg and only then makes it the GUI's, so a failed save never
// leaves the window showing settings the server doesn't have.
func (a *app) commit(dlg uintptr, cfg Config) bool {
	if err := cfg.save(a.path); err != nil {
		messageBox(dlg, "Can't save settings:\n"+err.Error(), mbIconError)
		return false
	}
	a.cfg = cfg
	return true
}

func (a *app) editUser(dlg uintptr, i int) {
	a.editing = i
	d := userDialog
	d.title = "Add user"
	if i >= 0 {
		d.title = "Edit user"
	}
	if d.run(dlg, a.userProc) == idOK {
		a.refresh(dlg)
	}
}

func (a *app) removeUser(dlg uintptr) {
	i := lvSelected(item(dlg, idUsers))
	if i < 0 {
		return
	}
	name := a.cfg.Users[i].Name
	if messageBox(dlg, fmt.Sprintf("Remove user %q?", name), mbYesNo|mbIconQuestion) != idYes {
		return
	}
	cfg := a.cfg.clone()
	cfg.removeUser(name)
	if a.commit(dlg, cfg) {
		a.refresh(dlg)
	}
}

func (a *app) settingsDialogProc(dlg, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmInitDialog:
		setText(dlg, idMaxConns, strconv.Itoa(a.cfg.MaxConns))
		setChecked(dlg, idWeb, a.cfg.Web)
		setText(dlg, idWebPort, strconv.Itoa(a.cfg.WebPort))
		setChecked(dlg, idTLS, a.cfg.TLS)
		setChecked(dlg, idPostQuantum, a.cfg.TLSPQ)
		setText(dlg, idCert, a.cfg.TLSCert)
		setText(dlg, idKey, a.cfg.TLSKey)
		// While the server runs, show what it started with, greyed out.
		if a.done != nil {
			for _, id := range []uint16{idMaxConns, idWeb, idWebPort, idTLS, idPostQuantum, idCert, idCertBrowse, idKey, idKeyBrowse, idSelfSign, idOK} {
				enable(dlg, id, false)
			}
			setText(dlg, idCancel, "Close")
		}
		return 1
	case wmCommand:
		switch uint16(wp) {
		case idCertBrowse:
			if p, ok := openFile(dlg, "Choose the certificate", text(dlg, idCert)); ok {
				setText(dlg, idCert, p)
			}
		case idKeyBrowse:
			if p, ok := openFile(dlg, "Choose the private key", text(dlg, idKey)); ok {
				setText(dlg, idKey, p)
			}
		case idSelfSign:
			a.selfSign(dlg)
		case idOK:
			a.submitSettings(dlg)
		case idCancel:
			endDialog(dlg, idCancel)
		}
		return 1
	}
	return 0
}

// selfSign creates a self-signed certificate next to the config and fills
// the form in with it. Saving still happens on OK.
func (a *app) selfSign(dlg uintptr) {
	dir := filepath.Dir(a.path)
	if _, err := os.Stat(filepath.Join(dir, selfSignedCert)); err == nil {
		msg := "Replace the existing self-signed certificate?\n\nClients that trusted it will need to trust the new one."
		if messageBox(dlg, msg, mbYesNo|mbIconWarning) != idYes {
			return
		}
	}
	certPath, keyPath, cert, err := selfSign(dir)
	if err != nil {
		messageBox(dlg, "Can't create the certificate:\n"+err.Error(), mbIconError)
		return
	}
	setChecked(dlg, idTLS, true)
	setText(dlg, idCert, certPath)
	setText(dlg, idKey, keyPath)
	messageBox(dlg, "Created a self-signed certificate, valid until "+cert.NotAfter.Format(time.DateOnly)+".\n\n"+
		"Clients will ask you to trust it. Check its SHA-256 fingerprint matches:\n\n"+certFingerprint(cert.Raw), mbIconInfo)
}

// submitSettings saves the settings, keeping the dialog open if they're
// invalid, the certificate doesn't load, or saving fails.
func (a *app) submitSettings(dlg uintptr) {
	if a.done != nil { // read-only while the server runs
		return
	}
	cfg := a.cfg
	var err error
	if cfg.MaxConns, err = strconv.Atoi(text(dlg, idMaxConns)); err != nil {
		messageBox(dlg, "Maximum connections must be a number, 0 for no limit.", mbIconError)
		return
	}
	if cfg.WebPort, err = strconv.Atoi(text(dlg, idWebPort)); err != nil {
		messageBox(dlg, "The web port must be a number.", mbIconError)
		return
	}
	cfg.Web = checked(dlg, idWeb)
	cfg.TLS = checked(dlg, idTLS)
	cfg.TLSPQ = checked(dlg, idPostQuantum)
	cfg.TLSCert = strings.TrimSpace(text(dlg, idCert))
	cfg.TLSKey = strings.TrimSpace(text(dlg, idKey))
	if err := cfg.validate(); err != nil {
		messageBox(dlg, err.Error(), mbIconError)
		return
	}
	if _, err := cfg.tlsConfig(); err != nil {
		messageBox(dlg, err.Error(), mbIconError)
		return
	}
	if a.commit(dlg, cfg) {
		endDialog(dlg, idOK)
	}
}

func (a *app) logDialogProc(dlg, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmInitDialog:
		setIcon(dlg)
		send(item(dlg, idLog), emSetLimitText, 0, 0) // lift the 32K default
		a.logShown = 0
		a.showNewLogs(dlg)
		setTimer(dlg, 500)
		return 1
	case wmTimer:
		a.showNewLogs(dlg)
		return 1
	case wmCommand:
		if uint16(wp) == idCancel {
			endDialog(dlg, idCancel)
		}
		return 1
	}
	return 0
}

func (a *app) showNewLogs(dlg uintptr) {
	// Start over from the buffer once the window holds twice what the buffer
	// can, so it doesn't grow for as long as it's open.
	if n, _, _ := procGetWindowTextLengthW.Call(item(dlg, idLog)); n > 2*logLines*maxLineLen {
		setText(dlg, idLog, "")
		a.logShown = 0
	}
	lines, total := a.logs.since(a.logShown)
	a.logShown = total
	if len(lines) > 0 {
		appendText(item(dlg, idLog), strings.Join(lines, "\r\n")+"\r\n")
	}
}

func (a *app) userDialogProc(dlg, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmInitDialog:
		if a.editing >= 0 {
			u := a.cfg.Users[a.editing]
			setText(dlg, idName, u.Name)
			setText(dlg, idFolder, u.Root)
			if u.Start != "" {
				setText(dlg, idStart, filepath.Join(u.Root, filepath.FromSlash(u.Start)))
			}
			setChecked(dlg, idReadOnly, u.ReadOnly)
			setChecked(dlg, idBypass, u.Bypass)
			setText(dlg, idHint, "Leave blank to keep the current password.")
		}
		return 1

	case wmCommand:
		switch uint16(wp) {
		case idBrowse:
			if p, ok := browseFolder(dlg, "Choose the folder this user is jailed to:"); ok {
				setText(dlg, idFolder, p)
			}
		case idStartBrowse:
			if p, ok := browseFolder(dlg, "Choose the folder this user starts in, inside their jail folder:"); ok {
				setText(dlg, idStart, p)
			}
		case idOK:
			a.submitUser(dlg)
		case idCancel:
			endDialog(dlg, idCancel)
		}
		return 1
	}
	return 0
}

// submitUser saves the form's user, keeping the dialog open on errors.
func (a *app) submitUser(dlg uintptr) {
	var old string
	if a.editing >= 0 {
		old = a.cfg.Users[a.editing].Name
	}
	u := User{Name: text(dlg, idName), Root: text(dlg, idFolder), Start: text(dlg, idStart), ReadOnly: checked(dlg, idReadOnly), Bypass: checked(dlg, idBypass)}
	cfg := a.cfg.clone()
	if err := cfg.setUser(old, u, text(dlg, idPassword)); err != nil {
		messageBox(dlg, err.Error(), mbIconError)
		return
	}
	if a.commit(dlg, cfg) {
		endDialog(dlg, idOK)
	}
}
