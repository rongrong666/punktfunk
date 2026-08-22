//! The screen wall ("屏幕墙"): one tap connects to EVERY connectable saved host at once,
//! each stream in its own session window tiled over the desktop work area — the naive
//! multi-window wall (per-host windows, no single-canvas compositor yet). Per-tile state
//! lives in `Shared::wall`; this page is the wall's control surface (per-tile status plus
//! stop-all). The wall never touches `Shared::session` (the single-stream slot), so a
//! plain connect alongside a running wall behaves exactly as before.
//!
//! Window placement is the session binary's existing `--window-pos` plus the wall-only
//! `--window-size`: the shell computes one grid over the primary work area and hands each
//! tile its cell. WG relay ports are allocated up front (`alloc_relay_pair` with the
//! batch's own `used` list), closing the probe-then-bind race a batch spawn would
//! otherwise hit on the default pair.

use super::style::*;
use super::{AppCtx, Screen};
use crate::spawn::{SessionChild, SpawnEvent};
use crate::trust::KnownHosts;
use pf_client_core::orchestrate::{ConnectPlan, alloc_relay_pair};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use windows_reactor::*;

/// One tiled session: its kill handle plus the status string the wall page renders.
/// The child's reader thread updates both fields off the UI thread; the page re-renders
/// off the root `wall_rev` bump every update performs.
pub(crate) struct WallTile {
    pub(crate) name: String,
    pub(crate) addr: String,
    pub(crate) child: SessionChild,
    /// "连接中…" → "已连接" → "已断开：…" — plain text, rendered as-is.
    pub(crate) status: Mutex<String>,
    /// The reader thread finished (Exited delivered). A dead tile's kill is a no-op.
    pub(crate) dead: AtomicBool,
}

/// Bump counter backing the root `wall_rev` async state: reader threads can't
/// read-modify-write the async value, so they fetch_add here and publish the new number.
pub(crate) fn bump(rev: &AtomicU64, set: &AsyncSetState<u64>) {
    set.call(rev.fetch_add(1, Ordering::SeqCst) + 1);
}

/// The primary monitor's work area (desktop minus the taskbar) — the rectangle the wall
/// tiles over. Falls back to the full primary screen if the work-area query fails.
fn work_area() -> (i32, i32, i32, i32) {
    use windows::Win32::windef::RECT;
    use windows::Win32::winuser::{
        GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN, SPI_GETWORKAREA, SystemParametersInfoW,
    };
    // SAFETY: `r` is a live local the call fills; the trailing 0 is the no-broadcast/
    // no-write flags value, and no pointer it takes escapes the call.
    let mut r = RECT::default();
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA as u32,
            0,
            &mut r as *mut _ as *mut std::ffi::c_void,
            0,
        )
    };
    if ok.as_bool() {
        return (r.left, r.top, r.right - r.left, r.bottom - r.top);
    }
    // SAFETY: plain metrics queries, no pointers.
    let (w, h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    (0, 0, w, h)
}

/// Nearly-square grid for N tiles: 2 → 2×1, 3–4 → 2×2, 5–6 → 3×2, …
fn grid_dims(n: usize) -> (usize, usize) {
    let cols = (n as f64).sqrt().ceil() as usize;
    (cols.max(1), n.div_ceil(cols.max(1)))
}

/// The hosts a wall can bring up unattended: a WireGuard host authenticates via the tunnel
/// handshake (no pin needed), anything else must carry a real pinned fingerprint (a pending
/// placeholder is not one).
fn connectable(hosts: &[crate::trust::KnownHost]) -> Vec<crate::trust::KnownHost> {
    hosts
        .iter()
        .filter(|h| h.wg.is_some() || crate::trust::parse_hex32(&h.fp_hex).is_some())
        .cloned()
        .collect()
}

/// Start the wall: spawn one tiled session per connectable host and switch to the wall
/// page. With nothing connectable the user stays on the host list with an explanatory
/// banner. Already-running wall → the caller navigates to the page instead (the hosts-page
/// button routes), this always builds a FRESH batch.
pub(crate) fn start_wall(
    ctx: &Arc<AppCtx>,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
    set_wall_rev: &AsyncSetState<u64>,
) {
    let known = KnownHosts::load();
    let hosts = connectable(&known.hosts);
    if hosts.is_empty() {
        set_status.call("没有可直接连接的主机——先添加主机并完成首次连接。".to_string());
        return;
    }
    // One relay pair per WG host, allocated for the whole batch before any spawn so two
    // tiles can never probe-pick the same free pair (the race `alloc_relay_pair` documents).
    let (wx, wy, ww, wh) = work_area();
    let (cols, rows) = grid_dims(hosts.len());
    let cell_w = (ww / cols as i32).max(320);
    let cell_h = (wh / rows as i32).max(200);

    let mut tiles: Vec<Arc<WallTile>> = Vec::new();
    let mut used_pairs: Vec<(u16, u16)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for (i, host) in hosts.iter().enumerate() {
        let tile = Arc::new(WallTile {
            name: host.name.clone(),
            addr: format!("{}:{}", host.addr, host.port),
            child: SessionChild::default(),
            status: Mutex::new("连接中…".to_string()),
            dead: AtomicBool::new(false),
        });
        let mut plan = ConnectPlan::for_host(host, None, None);
        // The wall tiles windows — a fullscreen session would swallow its monitor.
        plan.settings.fullscreen_on_stream = false;
        if plan.host.wg.is_some() {
            match alloc_relay_pair(&used_pairs) {
                Some(pair) => {
                    plan.wg_relay_ports = Some(pair);
                    used_pairs.push(pair);
                }
                None => {
                    *tile.status.lock().unwrap() =
                        "WG 端口对耗尽（最多 5 路隧道）".to_string();
                    tile.dead.store(true, Ordering::SeqCst);
                    tiles.push(tile);
                    continue;
                }
            }
        }
        let mut args = plan.session_args();
        // Spec mode, same as a single connect: the child reads no stores and cannot
        // disagree with this shell about them.
        let spec_path = match plan.spec(plan.clipboard).write_temp() {
            Ok(path) => {
                args.push("--resolved-spec".into());
                args.push(path.to_string_lossy().into_owned());
                Some(path)
            }
            Err(e) => {
                tracing::warn!(error = %e, "wall: couldn't write the resolved spec");
                None
            }
        };
        let (x, y) = (
            wx + (i % cols) as i32 * cell_w,
            wy + (i / cols) as i32 * cell_h,
        );
        let mut cmd = std::process::Command::new(crate::spawn::session_binary());
        cmd.args(args);
        cmd.arg("--window-pos").arg(format!("{x},{y}"));
        cmd.arg("--window-size").arg(format!("{cell_w},{cell_h}"));

        let shared = ctx.shared.clone();
        let (tile_ref, set_rev) = (tile.clone(), set_wall_rev.clone());
        let spawned = crate::spawn::spawn_with(
            cmd,
            &format!("{}:{}", host.addr, host.port),
            spec_path,
            tile.child.clone(),
            move |event| {
                match event {
                    SpawnEvent::Ready => {
                        *tile_ref.status.lock().unwrap() = "已连接".to_string();
                    }
                    // The wall never redirects the shell to a per-host error screen — the
                    // tile carries its own outcome and the rest of the wall keeps running.
                    SpawnEvent::Exited { error, ended, code } => {
                        let reason = error
                            .map(|(msg, _)| msg)
                            .or(ended)
                            .or_else(|| crate::spawn::silent_exit_banner(code))
                            .unwrap_or_else(|| "已断开".to_string());
                        *tile_ref.status.lock().unwrap() = reason;
                        tile_ref.dead.store(true, Ordering::SeqCst);
                    }
                    // Stats / window-size reports: nothing the wall page shows.
                    _ => {}
                }
                bump(&shared.wall_rev, &set_rev);
            },
        );
        if let Err(e) = spawned {
            failures.push(format!("{}：{e}", host.name));
            continue;
        }
        tiles.push(tile);
    }
    *ctx.shared.wall.lock().unwrap() = tiles;
    bump(&ctx.shared.wall_rev, set_wall_rev);
    if failures.is_empty() {
        set_status.call(String::new());
        set_screen.call(Screen::Wall);
    } else {
        set_status.call(format!("部分主机未能启动：{}", failures.join("；")));
        set_screen.call(Screen::Wall);
    }
}

/// Stop every tile (kill handles are no-ops on dead children) and return to the host list.
pub(crate) fn stop_wall(
    ctx: &Arc<AppCtx>,
    set_screen: &AsyncSetState<Screen>,
    set_wall_rev: &AsyncSetState<u64>,
) {
    {
        let mut wall = ctx.shared.wall.lock().unwrap();
        for tile in wall.iter() {
            tile.child.kill();
        }
        wall.clear();
    }
    bump(&ctx.shared.wall_rev, set_wall_rev);
    set_screen.call(Screen::Hosts);
}

/// The wall page: one status row per tile plus the stop-all button. No hooks (the page
/// reads `Shared::wall` directly; reader-thread updates reach it via the root `wall_rev`
/// re-render), so it is called inline like the other status pages.
pub(crate) fn wall_page(
    ctx: &Arc<AppCtx>,
    _wall_rev: u64,
    set_screen: &AsyncSetState<Screen>,
    set_wall_rev: &AsyncSetState<u64>,
) -> Element {
    let tiles: Vec<Arc<WallTile>> = ctx.shared.wall.lock().unwrap().clone();
    let live = tiles.iter().filter(|t| !t.dead.load(Ordering::SeqCst)).count();

    let mut body: Vec<Element> = vec![grid((
        vstack((
            text_block("屏幕墙").font_size(30.0).bold(),
            text_block(if tiles.is_empty() {
                "没有运行中的会话。".to_string()
            } else {
                format!(
                    "{} 台主机 · 各串流窗口已平铺在桌面，本窗口可最小化。",
                    tiles.len()
                )
            })
            .wrap()
            .foreground(ThemeRef::SecondaryText),
        ))
        .spacing(2.0)
        .grid_column(0)
        .vertical_alignment(VerticalAlignment::Center),
        hstack({
            let mut actions: Vec<Element> = Vec::new();
            if !tiles.is_empty() {
                actions.push(
                    button(format!("全部断开（{live}）"))
                        .icon(Symbol::Cancel)
                        .on_click({
                            let (c, ss, swr) =
                                (ctx.clone(), set_screen.clone(), set_wall_rev.clone());
                            move || stop_wall(&c, &ss, &swr)
                        })
                        .into(),
                );
            }
            actions.push(
                button("返回主机列表").accent().icon(Symbol::Back).on_click({
                    let ss = set_screen.clone();
                    move || ss.call(Screen::Hosts)
                })
                .into(),
            );
            actions
        })
        .spacing(8.0)
        .grid_column(1)
        .vertical_alignment(VerticalAlignment::Center),
    ))
    .columns([GridLength::Star(1.0), GridLength::Auto])
    .margin(edges(0.0, 0.0, 0.0, 10.0))
    .into()];

    for tile in tiles {
        let (name, addr) = (tile.name.clone(), tile.addr.clone());
        let status = tile.status.lock().unwrap().clone();
        let dead = tile.dead.load(Ordering::SeqCst);
        body.push(
            card(
                grid((
                    vstack((
                        text_block(name).font_size(15.0).semibold(),
                        text_block(addr)
                            .font_size(12.0)
                            .foreground(ThemeRef::SecondaryText),
                    ))
                    .spacing(2.0)
                    .grid_column(0)
                    .vertical_alignment(VerticalAlignment::Center),
                    text_block(status)
                        .font_size(12.0)
                        .foreground(if dead {
                            ThemeRef::SecondaryText
                        } else {
                            ThemeRef::Accent
                        })
                        .grid_column(1)
                        .vertical_alignment(VerticalAlignment::Center),
                ))
                .columns([GridLength::Star(1.0), GridLength::Auto]),
            )
            .margin(edges(0.0, 0.0, 0.0, 8.0))
            .into(),
        );
    }
    page(body)
}

#[cfg(test)]
mod tests {
    use super::grid_dims;

    #[test]
    fn the_grid_stays_nearly_square() {
        assert_eq!(grid_dims(1), (1, 1));
        assert_eq!(grid_dims(2), (2, 1));
        assert_eq!(grid_dims(3), (2, 2));
        assert_eq!(grid_dims(4), (2, 2));
        assert_eq!(grid_dims(5), (3, 2));
        assert_eq!(grid_dims(6), (3, 2));
    }
}
