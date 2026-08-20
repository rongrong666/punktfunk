//! Windows tray: a hidden top-level window + `Shell_NotifyIconW`, fed by the status poller.
//!
//! The host service (`PunktfunkHost`, LocalSystem) supervises from session 0 and its `serve`
//! child runs as SYSTEM — neither can own a per-user tray icon, so this is a separate small
//! process the installer puts in the HKLM `Run` key (one instance per interactive session,
//! enforced by a `Local\` mutex). Start/Stop/Restart open one UAC consent prompt each
//! (`ShellExecuteW "runas"` on `punktfunk-host.exe service …`) — service control is deliberately
//! left admin-gated rather than DACL-opened to every local user.

use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{
    GetLastError, ERROR_ALREADY_EXISTS, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::HiDpi::GetSystemMetricsForDpi;
use windows::Win32::UI::Shell::{
    SetCurrentProcessExplicitAppUserModelID, ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_INFO,
    NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_LARGE_ICON, NIIF_RESPECT_QUIET_TIME, NIIF_USER,
    NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NIN_SELECT, NOTIFYICONDATAW,
    NOTIFYICON_VERSION_4,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, FindWindowW, GetCursorPos, GetMessageW, LoadImageW, PostMessageW,
    PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow,
    SetMenuDefaultItem, TrackPopupMenuEx, TranslateMessage, HICON, IMAGE_ICON, LR_SHARED,
    MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, SM_CXICON, SM_CXSMICON, SW_HIDE, SW_SHOWNORMAL,
    TPM_BOTTOMALIGN, TPM_RIGHTBUTTON, WINDOW_EX_STYLE, WM_APP, WM_CLOSE, WM_COMMAND,
    WM_CONTEXTMENU, WM_DESTROY, WM_ENDSESSION, WM_NULL, WM_SETTINGCHANGE, WNDCLASSW, WS_OVERLAPPED,
};

use crate::status::{Poller, TrayStatus};
use crate::win_theme;

/// Keyboard "select" on the icon (Enter/Space) — `NIN_SELECT | NINF_KEY`; the windows crate
/// exports only NIN_SELECT.
const NIN_KEYSELECT: u32 = NIN_SELECT | 0x1;

/// Posted by the poller thread when the status changed (never touch TLS on the UI thread).
const WMAPP_STATUS: u32 = WM_APP + 2;
/// The notify-icon callback message (NOTIFYICON_VERSION_4 semantics).
const WMAPP_NOTIFYCALLBACK: u32 = WM_APP + 1;

// Menu command ids (WM_COMMAND LOWORD(wParam)).
const IDM_HEADER: usize = 0x0100; // disabled status line
const IDM_OPEN_WEB: usize = 0x0101;
const IDM_START: usize = 0x0102;
const IDM_STOP: usize = 0x0103;
const IDM_RESTART: usize = 0x0104;
const IDM_LOGS: usize = 0x0105;
const IDM_EXIT: usize = 0x0106;
const IDM_PAIRING: usize = 0x0107;
const IDM_DISPLAYS: usize = 0x0108;

/// Icon resource ordinals (embedded by build.rs).
fn icon_ordinal(status: &TrayStatus) -> u16 {
    match status {
        TrayStatus::Running(_) if status.is_streaming() => 5,
        TrayStatus::Running(_) => 2,
        TrayStatus::Stopped | TrayStatus::NotInstalled => 3,
        TrayStatus::Error(_) => 4,
        TrayStatus::Starting | TrayStatus::Degraded => 6,
    }
}

/// Global tray state — a tray has exactly one window and one wndproc, which cannot carry a
/// closure environment, so the state lives in a `OnceLock` set before window creation.
struct App {
    hwnd: AtomicIsize,
    status: Mutex<TrayStatus>,
    poller: OnceLock<Poller>,
    /// `TaskbarCreated` broadcast id — Explorer restarted, re-add the icon.
    taskbar_created: u32,
    /// `punktfunk-host.exe` next to this exe (the installer lays both in `{app}`).
    host_exe: Option<std::path::PathBuf>,
    /// The console answered the poller's live loopback probe. Drives the label of the (always
    /// present) "Open web console" entry, and whether a left-click on the icon opens the console
    /// or falls back to showing the menu.
    web_console: AtomicBool,
    web_port: u16,
    /// Streaming edge tracker for the connect toast: 0 = no status seen yet, 1 = not streaming,
    /// 2 = streaming. The "no status yet" state keeps a tray started mid-session (sign-in while a
    /// client already streams) from firing a stale toast.
    streaming_seen: AtomicU8,
}

static APP: OnceLock<App> = OnceLock::new();

fn app() -> &'static App {
    APP.get().expect("APP initialized before window creation")
}

fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain([0]).collect()
}

/// Best-effort log for a windows-subsystem process (no stderr): `%LOCALAPPDATA%\punktfunk\tray.log`.
fn log(msg: &str) {
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let dir = std::path::PathBuf::from(base).join("punktfunk");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("tray.log"))
    {
        use std::io::Write;
        let _ = writeln!(f, "{msg}");
    }
}

pub fn run(args: crate::Args) -> anyhow::Result<()> {
    let _ = args.autostart; // Linux-only flag, accepted for a uniform command line
    if args.quit {
        return quit_existing();
    }

    // One tray per session: `Local\` scopes the mutex to this logon session, so fast-user-switched
    // sessions each keep their own icon. Handle deliberately leaked (held for the process life).
    // SAFETY: CreateMutexW with a valid nul-terminated name and no security attributes; the
    // returned handle is never closed (process-lifetime singleton guard).
    let already = unsafe {
        match CreateMutexW(None, false, w!("Local\\PunktfunkTray")) {
            Ok(_) => GetLastError() == ERROR_ALREADY_EXISTS,
            Err(_) => false, // can't tell — carry on rather than losing the icon
        }
    };
    if already {
        return Ok(());
    }

    // Toast identity: the installer registers this AUMID under Classes\AppUserModelId with
    // DisplayName "Punktfunk" + the brand IconUri (punktfunk-host.iss [Registry] — keep in sync),
    // so the connect toast is attributed to "Punktfunk" with the logo instead of a generic entry.
    // Must run before the notify icon exists. Unregistered (dev run) it degrades to the default
    // attribution, never an error.
    // SAFETY: static nul-terminated literal.
    unsafe {
        let _ = SetCurrentProcessExplicitAppUserModelID(w!("unom.punktfunk.tray"));
    }

    // Before the first menu: opt this process's popup menus into the system dark mode.
    win_theme::init_dark_mode();

    let host_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("punktfunk-host.exe")))
        .filter(|p| p.exists());

    // SAFETY: RegisterWindowMessageW with a static nul-terminated literal.
    let taskbar_created = unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) };
    APP.set(App {
        hwnd: AtomicIsize::new(0),
        status: Mutex::new(TrayStatus::Stopped),
        poller: OnceLock::new(),
        taskbar_created,
        host_exe,
        web_console: AtomicBool::new(false), // live-probed by the poller within its first cycle
        web_port: args.web_port,
        streaming_seen: AtomicU8::new(0),
    })
    .ok()
    .expect("run() is called once");

    // Hidden top-level window (NOT message-only — those never receive the TaskbarCreated
    // broadcast, which is how the icon survives an Explorer restart).
    // SAFETY: standard window-class registration + creation; the class name literal outlives the
    // call, wndproc is a valid extern "system" fn, and the window is created on this thread which
    // then runs the message loop.
    let hwnd = unsafe {
        let hinstance = GetModuleHandleW(None)?;
        let class = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance.into(),
            lpszClassName: w!("PunktfunkTrayWindow"),
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            anyhow::bail!("RegisterClassW failed: {:?}", GetLastError());
        }
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("PunktfunkTrayWindow"),
            w!("punktfunk tray"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(hinstance.into()),
            None,
        )?
    };
    app().hwnd.store(hwnd.0 as isize, Ordering::SeqCst);

    // First NIM_ADD retried across the logon race (the taskbar may not exist yet at sign-in).
    let mut added = false;
    for _ in 0..10 {
        if update_icon(hwnd, true) {
            added = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if !added {
        log("Shell_NotifyIconW(NIM_ADD) kept failing — no taskbar?");
    }

    // The poller owns all network/SCM I/O; it only posts a message here.
    let poller = Poller::spawn(
        args.mgmt_addr.clone(),
        args.mgmt_port,
        args.web_port,
        Box::new(move |st, console_up| {
            *app().status.lock().unwrap() = st;
            app().web_console.store(console_up, Ordering::SeqCst);
            let hwnd = HWND(app().hwnd.load(Ordering::SeqCst) as *mut _);
            // SAFETY: PostMessageW is documented thread-safe; a stale/destroyed hwnd fails
            // harmlessly with an error we ignore.
            unsafe {
                let _ = PostMessageW(Some(hwnd), WMAPP_STATUS, WPARAM(0), LPARAM(0));
            }
        }),
    );
    let _ = app().poller.set(poller);

    // SAFETY: classic message pump on the window's owning thread.
    unsafe {
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

/// `--quit`: ask a running instance (this session) to exit — used by the uninstaller before file
/// deletion. High-IL callers may message a medium-IL window (UIPI blocks only low→high).
fn quit_existing() -> anyhow::Result<()> {
    // SAFETY: FindWindowW/PostMessageW on a class-name literal; both fail harmlessly when no
    // instance is running.
    unsafe {
        if let Ok(hwnd) = FindWindowW(w!("PunktfunkTrayWindow"), PCWSTR::null()) {
            let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
    }
    Ok(())
}

/// Build/refresh the notify icon from the current status. Returns false when the shell rejected
/// the call (no taskbar yet).
fn update_icon(hwnd: HWND, add: bool) -> bool {
    let status = app().status.lock().unwrap().clone();
    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
        uCallbackMessage: WMAPP_NOTIFYCALLBACK,
        ..Default::default()
    };
    // Ask for the shell's small-icon size at this DPI, so LoadImageW serves the best frame of the
    // multi-size .ico instead of the 32 px default the shell then downscales (soft at 125 %+).
    // SAFETY: plain metric query; 0 (failure) falls back to the classic 16 px.
    let sm = match unsafe { GetSystemMetricsForDpi(SM_CXSMICON, win_theme::window_dpi(hwnd)) } {
        0 => 16,
        n => n,
    };
    // SAFETY: LoadImageW by ordinal from this exe's embedded resources (build.rs); the ordinal is
    // one of the ids compiled in, LR_SHARED handles are system-cached (never destroyed by us),
    // and a failure falls back to a null icon rather than UB.
    nid.hIcon = unsafe {
        LoadImageW(
            Some(GetModuleHandleW(None).unwrap_or_default().into()),
            PCWSTR(icon_ordinal(&status) as usize as *const u16),
            IMAGE_ICON,
            sm,
            sm,
            LR_SHARED,
        )
    }
    .map(|h| HICON(h.0))
    .unwrap_or(HICON(std::ptr::null_mut()));
    // Tooltip: truncate to the szTip capacity (127 UTF-16 units + nul).
    let tip = to_wide(&status.headline());
    let n = tip.len().min(nid.szTip.len() - 1);
    nid.szTip[..n].copy_from_slice(&tip[..n]);

    // SAFETY: nid is fully initialized with a correct cbSize; NIM_* calls only read it.
    unsafe {
        if add {
            if !Shell_NotifyIconW(NIM_ADD, &nid).as_bool() {
                return false;
            }
            let mut v = nid;
            v.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            let _ = Shell_NotifyIconW(NIM_SETVERSION, &v);
            true
        } else {
            if !Shell_NotifyIconW(NIM_MODIFY, &nid).as_bool() {
                // Icon vanished (Explorer crash we missed) — re-add.
                return update_icon(hwnd, true);
            }
            true
        }
    }
}

/// Toast when a client connects (the idle → streaming edge, as seen by the poller). Windows 11
/// renders `NIF_INFO` balloons as native toasts under the app's name — no WinRT/AUMID
/// registration needed for a plain exe. Fired from the UI thread on WMAPP_STATUS.
fn notify_on_connect(hwnd: HWND) {
    let status = app().status.lock().unwrap().clone();
    let now: u8 = if status.is_streaming() { 2 } else { 1 };
    // 0 = first status since launch: record only. A tray started mid-session (sign-in while a
    // client already streams) must not fire a stale toast.
    let was = app().streaming_seen.swap(now, Ordering::SeqCst);
    if !(was == 1 && now == 2) {
        return;
    }
    let (title, body) = match &status {
        TrayStatus::Running(s) => (
            // The host resolves the name from its trust store, else the device's own Hello name;
            // absent (older host / nameless client) the toast stays generic.
            match &s.client_name {
                Some(name) => format!("{name} 已连接"),
                None => "客户端已连接".to_string(),
            },
            match &s.session {
                Some(sess) => format!(
                    "正在串流 {}×{} @ {} fps",
                    sess.width, sess.height, sess.fps
                ),
                None => "有客户端正在从这台主机串流。".to_string(),
            },
        ),
        _ => return, // is_streaming() implies Running; stay defensive
    };
    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_INFO, // NIM_MODIFY touches only the balloon fields; icon/tip stay as-is
        dwInfoFlags: NIIF_USER | NIIF_LARGE_ICON | NIIF_RESPECT_QUIET_TIME,
        ..Default::default()
    };
    let title = to_wide(&title);
    let n = title.len().min(nid.szInfoTitle.len() - 1);
    nid.szInfoTitle[..n].copy_from_slice(&title[..n]);
    let body = to_wide(&body);
    let n = body.len().min(nid.szInfo.len() - 1);
    nid.szInfo[..n].copy_from_slice(&body[..n]);
    // SAFETY: plain metric query; 0 (failure) falls back to the classic 32 px.
    let sm = match unsafe { GetSystemMetricsForDpi(SM_CXICON, win_theme::window_dpi(hwnd)) } {
        0 => 32,
        n => n,
    };
    // The brand logo (ordinal 1, punktfunk.ico) at full toast size — the toast is Punktfunk
    // speaking, not a status glyph. SAFETY: LoadImageW by ordinal from this exe's embedded
    // resources; LR_SHARED handles are system-cached (never destroyed by us), and on failure the
    // toast just shows no image.
    nid.hBalloonIcon = unsafe {
        LoadImageW(
            Some(GetModuleHandleW(None).unwrap_or_default().into()),
            // `without_provenance`, not `ptr::dangling()`: this is MAKEINTRESOURCE(1) — the
            // ADDRESS is the resource ordinal, and dangling() would yield align_of::<u16>() = 2.
            PCWSTR(std::ptr::without_provenance(1)),
            IMAGE_ICON,
            sm,
            sm,
            LR_SHARED,
        )
    }
    .map(|h| HICON(h.0))
    .unwrap_or(HICON(std::ptr::null_mut()));
    // SAFETY: nid fully initialized with a correct cbSize; NIM_MODIFY only reads it.
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

/// The right-click menu, rebuilt from the live status each time.
fn show_menu(hwnd: HWND) {
    let status = app().status.lock().unwrap().clone();
    let running = matches!(
        status,
        TrayStatus::Running(_) | TrayStatus::Starting | TrayStatus::Degraded
    );
    let startable = matches!(status, TrayStatus::Stopped | TrayStatus::Error(_));
    let can_control = app().host_exe.is_some();

    // SAFETY: menu handle created and destroyed here; AppendMenuW copies the item strings, whose
    // wide buffers outlive each call. TrackPopupMenuEx requires the foreground quirk handled
    // below (SetForegroundWindow before, WM_NULL after) per the Shell_NotifyIcon docs.
    unsafe {
        let Ok(menu) = CreatePopupMenu() else { return };
        // Glyph bitmaps: the menu references but does not own them; the guard deletes them after
        // DestroyMenu below.
        let mut glyphs = win_theme::MenuGlyphs::new(hwnd);
        let mut add = |id: usize, text: &str, grayed: bool, glyph: Option<u16>| {
            let wide = to_wide(text);
            let flags = if grayed {
                MF_STRING | MF_GRAYED
            } else {
                MF_STRING
            };
            let _ = AppendMenuW(menu, flags, id, PCWSTR(wide.as_ptr()));
            if let Some(g) = glyph {
                glyphs.set(menu, id, g);
            }
        };
        add(IDM_HEADER, &status.headline(), true, None);
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        // The console entry is ALWAYS here — it is the reason most people open this menu, and
        // left-clicking the icon is not a discoverable substitute. When the loopback probe says
        // the console isn't answering the label says so, rather than the entry vanishing.
        if app().web_console.load(Ordering::SeqCst) {
            add(
                IDM_OPEN_WEB,
                "打开 Web 控制台",
                false,
                Some(win_theme::GLYPH_GLOBE),
            );
        } else {
            add(
                IDM_OPEN_WEB,
                "打开 Web 控制台（无响应）",
                false,
                Some(win_theme::GLYPH_GLOBE),
            );
        }
        let _ = SetMenuDefaultItem(menu, IDM_OPEN_WEB as u32, 0);
        if status.pairing_attention() {
            add(
                IDM_PAIRING,
                "批准配对请求…",
                false,
                Some(win_theme::GLYPH_APPROVE),
            );
        }
        match status.kept_displays() {
            0 => {}
            1 => add(
                IDM_DISPLAYS,
                "释放保留的显示器…",
                false,
                Some(win_theme::GLYPH_DISPLAY),
            ),
            n => add(
                IDM_DISPLAYS,
                &format!("释放 {n} 个保留的显示器…"),
                false,
                Some(win_theme::GLYPH_DISPLAY),
            ),
        }
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        // The service actions all carry the shield: Explorer's convention for "selecting this
        // opens a UAC prompt" (each runs `punktfunk-host.exe service …` elevated).
        if can_control {
            if startable {
                add(
                    IDM_START,
                    "启动主机",
                    false,
                    Some(win_theme::GLYPH_SHIELD),
                );
            }
            if running {
                add(IDM_STOP, "停止主机", false, Some(win_theme::GLYPH_SHIELD));
                add(
                    IDM_RESTART,
                    "重启主机",
                    false,
                    Some(win_theme::GLYPH_SHIELD),
                );
            } else if matches!(status, TrayStatus::Error(_)) {
                add(
                    IDM_RESTART,
                    "重启主机",
                    false,
                    Some(win_theme::GLYPH_SHIELD),
                );
            }
        }
        add(
            IDM_LOGS,
            "打开日志文件夹",
            false,
            Some(win_theme::GLYPH_FOLDER),
        );
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        add(IDM_EXIT, "退出托盘", false, Some(win_theme::GLYPH_POWER));

        let mut pt = Default::default();
        let _ = GetCursorPos(&mut pt);
        let _ = SetForegroundWindow(hwnd);
        let _ = TrackPopupMenuEx(
            menu,
            (TPM_RIGHTBUTTON | TPM_BOTTOMALIGN).0,
            pt.x,
            pt.y,
            hwnd,
            None,
        );
        let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
        let _ = DestroyMenu(menu);
    }
}

/// `ShellExecuteW` "open" on a URL / folder.
fn shell_open(hwnd: HWND, target: &str) {
    let wide = to_wide(target);
    // SAFETY: all strings nul-terminated and live across the call.
    unsafe {
        ShellExecuteW(
            Some(hwnd),
            w!("open"),
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// One UAC prompt per service action: relaunch the host exe elevated with `service <verb>`.
/// A declined prompt (ERROR_CANCELLED) is deliberately ignored.
fn elevate_service(hwnd: HWND, verb: &str) {
    let Some(exe) = app().host_exe.as_ref() else {
        return;
    };
    let exe_w = to_wide(&exe.to_string_lossy());
    let params = to_wide(&format!("service {verb}"));
    // SAFETY: nul-terminated strings live across the call; "runas" spawns the elevated child
    // (hidden console — the tray re-polls for the outcome instead of scraping its output).
    unsafe {
        ShellExecuteW(
            Some(hwnd),
            w!("runas"),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR(params.as_ptr()),
            PCWSTR::null(),
            SW_HIDE,
        );
    }
    if let Some(p) = app().poller.get() {
        p.poke();
    }
}

/// Open the web console at `path` ("" = dashboard). Deep links land the operator on the page the
/// menu entry promised — the pairing queue, the virtual displays — instead of the dashboard.
fn open_web_console(hwnd: HWND, path: &str) {
    // 127.0.0.1, not `localhost`: the console binds HOST=0.0.0.0 (the service supervisor's
    // `spawn_web` wiring), which is IPv4-ONLY, while Windows resolves `localhost` to ::1 first. A
    // browser that does not
    // fall back cleanly got connection-refused on a perfectly healthy console — and because the
    // poller probes 127.0.0.1, the tray would call it up while handing over a URL that fails. Same
    // literal in both places, so the menu can never disagree with the status next to it.
    shell_open(
        hwnd,
        &format!("https://127.0.0.1:{}/{path}", app().web_port),
    );
}

fn open_logs(hwnd: HWND) {
    let Some(base) = std::env::var_os("ProgramData") else {
        return;
    };
    let dir = std::path::PathBuf::from(base)
        .join("punktfunk")
        .join("logs");
    shell_open(hwnd, &dir.to_string_lossy());
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let Some(app) = APP.get() else {
        // SAFETY: pass-through for messages arriving before APP is set (CreateWindowExW sends
        // WM_NCCREATE/WM_CREATE synchronously — APP is set before that, but stay defensive).
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    };
    match msg {
        WMAPP_STATUS => {
            update_icon(hwnd, false);
            notify_on_connect(hwnd);
            LRESULT(0)
        }
        WM_SETTINGCHANGE => {
            // Light/dark flipped while running: drop the cached menu theme so the next popup
            // renders in the new mode.
            if win_theme::is_color_scheme_change(lparam) {
                win_theme::on_color_scheme_changed();
            }
            // SAFETY: setting broadcasts still get default processing.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WMAPP_NOTIFYCALLBACK => {
            // NOTIFYICON_VERSION_4: LOWORD(lParam) is the event.
            match (lparam.0 as u32) & 0xffff {
                WM_CONTEXTMENU => show_menu(hwnd),
                x if x == NIN_SELECT || x == NIN_KEYSELECT => {
                    if app.web_console.load(Ordering::SeqCst) {
                        open_web_console(hwnd, "");
                    } else {
                        show_menu(hwnd);
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            match (wparam.0) & 0xffff {
                IDM_OPEN_WEB => open_web_console(hwnd, ""),
                IDM_PAIRING => open_web_console(hwnd, "pairing"),
                IDM_DISPLAYS => open_web_console(hwnd, "displays"),
                IDM_START => elevate_service(hwnd, "start"),
                IDM_STOP => elevate_service(hwnd, "stop"),
                IDM_RESTART => elevate_service(hwnd, "restart"),
                IDM_LOGS => open_logs(hwnd),
                // SAFETY: DestroyWindow on the wndproc's own window/thread.
                IDM_EXIT => unsafe {
                    let _ = DestroyWindow(hwnd);
                },
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE | WM_ENDSESSION => {
            // SAFETY: as above — triggers WM_DESTROY below.
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            let nid = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: 1,
                ..Default::default()
            };
            // SAFETY: minimal, correctly sized nid; NIM_DELETE only reads hWnd/uID.
            unsafe {
                let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
                PostQuitMessage(0);
            }
            LRESULT(0)
        }
        m if m == app.taskbar_created => {
            // Explorer restarted — the icon is gone; add it back.
            update_icon(hwnd, true);
            LRESULT(0)
        }
        // SAFETY: default handling for everything else.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}
