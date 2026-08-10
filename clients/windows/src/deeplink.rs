//! `punktfunk://` activation for the Windows shell (design/client-deep-links.md §4.2).
//!
//! Protocol activation of a full-trust packaged app delivers the URI as the command line, so
//! a browser prompt, `start punktfunk://…` and a written `.lnk` all arrive the same way: as a
//! positional argument. What Windows does NOT give us is single-instancing — unlike
//! GApplication on Linux, a second activation is simply a second process. So this module adds
//! it: the first instance claims a named mutex, and any later one hands its URL to the winner
//! over `WM_COPYDATA` and exits.
//!
//! A URL must never be silently dropped, which is why the hand-off retries while the primary's
//! window is still coming up, and why a hand-off that ultimately fails falls back to running
//! this instance normally rather than exiting quietly.

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Mutex;
use windows::Win32::commctrl::{DefSubclassProc, SetWindowSubclass};
use windows::Win32::minwindef::{LPARAM, LRESULT, WPARAM};
use windows::Win32::synchapi::{CreateMutexW, ReleaseMutex};
use windows::Win32::windef::HWND;
use windows::Win32::winuser::{FindWindowW, SendMessageW, COPYDATASTRUCT, WM_COPYDATA};

/// The single-instance mutex. Named per the design; deliberately not `Global\` — one shell per
/// user session is the rule, and a second desktop user gets their own.
const MUTEX_NAME: windows::core::PCWSTR = windows::core::w!("unom.punktfunk.client");

/// Tags our `WM_COPYDATA` so a stray message from anything else is ignored rather than parsed.
const COPYDATA_URL: usize = 0x7066_0001; // 'pf' + 1

/// Subclass id for the receiver hook.
const SUBCLASS_ID: usize = 0x7066_0002;

/// URLs delivered by another instance, waiting for the app's poll to pick them up. A queue
/// rather than a single slot: two shortcuts double-clicked in quick succession are two links,
/// and dropping either would be exactly the silent loss this design forbids.
static INBOX: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The claimed mutex handle, held for the process lifetime. Stored so it is released on exit
/// (Windows would release it anyway when the process dies; being explicit costs nothing and
/// documents the intent).
static MUTEX: AtomicIsize = AtomicIsize::new(0);

/// A positional `punktfunk://` (or the `pf://` input alias) anywhere in argv — how protocol
/// activation, `start`, and a `.lnk` shortcut all deliver a link. Validation happens later in
/// the shared parser; this only decides whether argv carries something addressed to us.
pub(crate) fn positional_url(args: &[String]) -> Option<String> {
    args.iter()
        .skip(1)
        .find(|a| {
            let lower = a.to_ascii_lowercase();
            lower.starts_with("punktfunk://") || lower.starts_with("pf://")
        })
        .cloned()
}

/// Try to become the one shell for this user. `true` = we are it; `false` = another instance
/// holds the mutex and this process should hand off and exit.
pub(crate) fn claim_primary() -> bool {
    // SAFETY: `CreateMutexW` takes a static wide name literal and no pointer we own; the handle it
    // returns is stored in `MUTEX` and released once in `release_primary`.
    unsafe {
        let handle = CreateMutexW(None, true, MUTEX_NAME);
        // Without the mutex we cannot tell primary from secondary; behaving as primary is
        // the safe answer — a second window is a nuisance, a dropped launch is a bug.
        if handle.0.is_null() {
            let e = windows::Win32::errhandlingapi::GetLastError();
            tracing::warn!(error = e, "single instance mutex; continuing as primary");
            return true;
        }
        // ERROR_ALREADY_EXISTS means someone else created it first — `CreateMutexW` still
        // hands back a valid handle, so ask the OS what actually happened.
        let already = windows::Win32::errhandlingapi::GetLastError()
            == windows::Win32::winerror::ERROR_ALREADY_EXISTS as u32;
        if already {
            return false;
        }
        MUTEX.store(handle.0 as isize, Ordering::Relaxed);
        true
    }
}

/// Release the single-instance mutex (process exit).
pub(crate) fn release_primary() {
    let raw = MUTEX.swap(0, Ordering::Relaxed);
    if raw != 0 {
        // SAFETY: `raw` is the handle `claim_primary` stored, taken out of the atomic by `swap` so
        // this runs at most once even if two threads race here.
        unsafe {
            let _ = ReleaseMutex(windows::Win32::winnt::HANDLE(raw as *mut _));
        }
    }
}

/// Hand `url` to the running shell. Retries briefly: the primary may still be creating its
/// window when a second launch lands (a double-clicked shortcut while the app is starting is
/// the ordinary case), and giving up in that window would drop the link.
///
/// `false` = the primary never answered, and the caller should just run normally.
pub(crate) fn forward_to_primary(url: &str) -> bool {
    let wide: Vec<u16> = url.encode_utf16().collect();
    for attempt in 0..20 {
        // SAFETY: `FindWindowW` takes static literals. The `COPYDATASTRUCT` points at `wide`, a
        // local that outlives the call because `SendMessage` is synchronous — the receiver has
        // finished with the buffer before it returns, which is precisely why this is not `Post`.
        unsafe {
            let hwnd = FindWindowW(None, windows::core::w!("Punktfunk"));
            if !hwnd.0.is_null() {
                let data = COPYDATASTRUCT {
                    dwData: COPYDATA_URL,
                    cbData: (wide.len() * 2) as u32,
                    lpData: wide.as_ptr() as *mut _,
                };
                // SendMessage, not Post: the buffer must stay alive until the receiver has
                // copied it, which only a synchronous send guarantees.
                SendMessageW(
                    hwnd,
                    WM_COPYDATA as u32,
                    WPARAM(0),
                    LPARAM(&data as *const _ as isize),
                );
                tracing::info!(attempt, "handed the link to the running shell");
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    tracing::warn!("no running shell answered; opening this link here instead");
    false
}

/// Start listening for links from later instances. Idempotent, and safe to call before the
/// window exists — it retries on its own thread until the shell window can be found.
pub(crate) fn install_receiver() {
    std::thread::Builder::new()
        .name("pf-deeplink-receiver".into())
        .spawn(|| {
            for _ in 0..200 {
                // SAFETY: `FindWindowW` takes static literals, and `SetWindowSubclass` is given
                // our own `wnd_proc` plus a plain id; the window handle is one the OS just returned.
                unsafe {
                    let hwnd = FindWindowW(None, windows::core::w!("Punktfunk"));
                    if !hwnd.0.is_null() {
                        // Subclassing (rather than replacing the window proc) is what lets the
                        // WinUI window keep behaving as itself; the same mechanism the stream
                        // input hooks already use.
                        let _ = SetWindowSubclass(hwnd, Some(wnd_proc), SUBCLASS_ID, 0);
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            tracing::warn!("shell window never appeared; links from other instances won't arrive");
        })
        .ok();
}

/// The subclass hook: copy our tagged payload out and queue it, pass everything else through.
unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    if msg == WM_COPYDATA as u32 {
        // SAFETY: for `WM_COPYDATA` the OS marshals the sender's `COPYDATASTRUCT` and its buffer
        // into THIS process and keeps both valid for the duration of the handler — that is the
        // guarantee this relies on, not the sender's honesty, which is why a hostile sender can at
        // worst supply a wrong `dwData`/contents rather than a bad pointer.
        let cds = unsafe { &*(lparam.0 as *const COPYDATASTRUCT) };
        if cds.dwData == COPYDATA_URL && !cds.lpData.is_null() {
            let len = cds.cbData as usize / 2;
            // SAFETY: as above, `lpData` is the OS-marshalled copy, valid for `cbData` bytes and
            // suitably aligned because the OS allocated it; `len` is `cbData / 2`, so the slice
            // cannot read past the buffer even if `cbData` is odd (the division rounds down).
            let slice = unsafe { std::slice::from_raw_parts(cds.lpData as *const u16, len) };
            let url = String::from_utf16_lossy(slice);
            tracing::debug!(%url, "link from another instance");
            INBOX.lock().unwrap().push(url);
            return LRESULT(1);
        }
    }
    // SAFETY: the default handler is called with exactly the parameters the OS passed this window
    // procedure, unmodified — forwarding them on is what a subclass proc is required to do for any
    // message it does not consume.
    unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
}

/// Take everything delivered since the last call — the app polls this and routes each one.
pub(crate) fn drain() -> Vec<String> {
    std::mem::take(&mut *INBOX.lock().unwrap())
}

/// Queue a link this process was launched with, so the cold start and the hand-off path feed
/// the router through one door.
pub(crate) fn queue(url: String) {
    INBOX.lock().unwrap().push(url);
}

/// Write a `.lnk` on the Desktop that launches this URL, and return its path.
///
/// The shortcut targets the app execution alias with the URL as an ARGUMENT, rather than being
/// a `.url` internet shortcut. Both would work while the scheme is registered; only this one
/// still works if it isn't, because it invokes the client directly — which is the whole point
/// of a shortcut being a container for a URL rather than a second launch mechanism
/// (design/client-deep-links.md §5). Targeting the alias (not the package path) is what keeps
/// it valid across updates, since the install path changes and the alias doesn't.
pub(crate) fn write_shortcut(label: &str, url: &str) -> Result<std::path::PathBuf, String> {
    use windows::core::{Interface, HSTRING};
    use windows::Win32::combaseapi::{CoCreateInstance, CoInitializeEx};
    use windows::Win32::objbase::COINIT_APARTMENTTHREADED;
    use windows::Win32::objidl::IPersistFile;
    use windows::Win32::shobjidl_core::{IShellLinkW, ShellLink};
    use windows::Win32::wtypesbase::CLSCTX_INPROC_SERVER;

    let desktop = std::env::var("USERPROFILE")
        .map(|p| std::path::PathBuf::from(p).join("Desktop"))
        .map_err(|_| "USERPROFILE isn't set".to_string())?;
    let path = desktop.join(format!("{}.lnk", file_name(label)));
    // SAFETY: COM calls on this thread's apartment. `CoCreateInstance` returns an owned interface
    // checked by `?`, and every setter below takes a borrowed `HSTRING`/`PCWSTR` that outlives its
    // synchronous call; nothing here dereferences a pointer the caller supplied.
    unsafe {
        // The UI thread is already apartment-threaded; this is belt and braces for the case
        // where a caller ever moves this off it. An already-initialised apartment returns
        // S_FALSE, which is not an error.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED as u32);
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("shell link: {e}"))?;
        link.SetPath(&HSTRING::from("punktfunk-client.exe"))
            .ok()
            .map_err(|e| format!("shortcut target: {e}"))?;
        link.SetArguments(&HSTRING::from(url))
            .ok()
            .map_err(|e| format!("shortcut argument: {e}"))?;
        link.SetDescription(&HSTRING::from(format!("从 {label} 串流")))
            .ok()
            .map_err(|e| format!("shortcut description: {e}"))?;
        let persist: IPersistFile = link.cast().map_err(|e| format!("shortcut save: {e}"))?;
        // `to_string_lossy` rather than the OsStr: HSTRING is UTF-16 and the path came from an
        // env var plus our own sanitised name, so there is nothing lossy left to lose.
        persist
            .Save(&HSTRING::from(path.to_string_lossy().as_ref()), true)
            .ok()
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(path)
}

/// A filename Windows will accept: its reserved characters replaced, length capped, and never
/// empty. Host and profile names are user text and reach this directly.
fn file_name(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '-',
            c if (c as u32) < 0x20 => '-',
            c => c,
        })
        .take(64)
        .collect();
    let trimmed = cleaned.trim().trim_end_matches('.').to_string();
    if trimmed.is_empty() {
        "Punktfunk".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Links are recognised wherever they sit in argv, and nothing else is.
    #[test]
    fn positional_url_finds_links_only() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            positional_url(&args(&["punktfunk-client.exe", "punktfunk://connect/Desk"])),
            Some("punktfunk://connect/Desk".into())
        );
        // The alias form still parses (it is never emitted, only accepted).
        assert_eq!(
            positional_url(&args(&["exe", "--windowed", "PF://connect/Desk"])),
            Some("PF://connect/Desk".into())
        );
        assert_eq!(positional_url(&args(&["exe", "--console"])), None);
        // argv[0] is never a link, even if someone renames the binary.
        assert_eq!(positional_url(&args(&["punktfunk://connect/Desk"])), None);
    }

    /// Shortcut names survive user text: reserved characters, control characters, a trailing
    /// dot (which Windows silently strips, breaking the path) and an empty result.
    #[test]
    fn shortcut_file_names_are_safe() {
        assert_eq!(file_name("Living Room PC"), "Living Room PC");
        assert_eq!(file_name("Desk: Work/Play"), "Desk- Work-Play");
        assert_eq!(file_name("Desk\u{1}"), "Desk-");
        assert_eq!(file_name("Trailing."), "Trailing");
        assert_eq!(file_name("   "), "Punktfunk");
        assert!(file_name(&"x".repeat(300)).len() <= 64);
    }
}
