//! The hosts page: saved (trusted/paired) hosts and live mDNS discovery as tap-to-connect
//! tiles in a responsive grid, with a per-host "…" menu (connect / speed test / edit /
//! forget) and a manual connect entry — the same card layout as the Linux and Apple clients.

use super::connect::{initiate, initiate_waking, open_console};
use super::speed::SpeedState;
use super::style::*;
use super::{Screen, Svc, Target};
use crate::discovery::DiscoveredHost;
use crate::trust::KnownHosts;
use std::collections::HashMap;
use windows_reactor::*;

/// Overflow-menu item labels — `on_item_clicked` reports the clicked item by its text.
const MENU_CONNECT: &str = "连接";
const MENU_LIBRARY: &str = "浏览游戏库\u{2026}";
const MENU_SPEED: &str = "测试网络速度\u{2026}";
const MENU_WAKE: &str = "唤醒主机";
/// One entry for every per-host property (name, address, MAC, clipboard sharing) — the
/// Apple client's add/edit sheet. A menu item per field read as clutter and buried the ones
/// that matter.
const MENU_EDIT: &str = "编辑\u{2026}";
/// The per-profile families nest in submenus. Submenu LEAVES are what the shared click
/// callback reports (the backend wires clicks recursively and hands back the leaf text):
/// "Connect with"'s leaves are the bare profile names + [`SUB_WITH_DEFAULT`]; "Pin tiles"'s
/// leaves keep a verb prefix, which is what tells the two families apart in the callback.
/// (A profile literally named like a fixed entry, e.g. "Connect", is shadowed by it — the
/// same last-wins rule the scope dropdown documents.)
const SUB_WITH: &str = "使用配置连接";
const SUB_WITH_DEFAULT: &str = "默认设置";
const SUB_PIN: &str = "固定磁贴";
const MENU_COPY_LINK: &str = "复制链接";
const MENU_SHORTCUT: &str = "创建快捷方式\u{2026}";
const MENU_PIN: &str = "固定磁贴: ";
const MENU_UNPIN: &str = "取消固定: ";
const MENU_FORGET: &str = "忘记\u{2026}";

/// Whether the console (gamepad) UI is available in this build: the session binary ships
/// its Skia `ui` feature on x64 only (no skia prebuilts for aarch64 yet) — the entry
/// points compile everywhere but only show where `--browse` can actually run.
const CONSOLE_UI_AVAILABLE: bool = cfg!(target_arch = "x86_64");

/// Tile-grid metrics: minimum tile width before dropping a column, and the gap between tiles.
const TILE_MIN_WIDTH: f64 = 320.0;
const TILE_GAP: f64 = 12.0;

/// Props for the hosts page: the services plus the changing discovery/status data that must
/// drive its re-render (compared by value, so a new host list or error refreshes the page).
///
/// `forget` and `rename` are the per-host action state, and they live in ROOT (not this page's
/// own `use_state`) on purpose: the "…" overflow is a WinUI `MenuFlyout`, whose item clicks are
/// wired directly in the reactor backend (`add_Click`) and so bypass the normal event-dispatch
/// flush — a *sync* child `SetState` from that handler marks state dirty but never pumps the
/// reconciler, so nothing re-renders. Root `AsyncSetState` re-renders the whole tree; because
/// these values are props, the changed value propagates back into this page (a child's own async
/// state would be memoised away when its props are unchanged). `(fp_hex, _)` in each identifies
/// the target saved host; `rename`'s second field is the in-progress draft name.
#[derive(Clone)]
pub(crate) struct HostsProps {
    pub(crate) svc: Svc,
    pub(crate) hosts: Vec<DiscoveredHost>,
    /// Saved hosts proven reachable by the periodic QUIC probe (keyed by `fp_hex`), OR'd with
    /// live-advert presence to drive the Online pip — so a host reached only over a routed
    /// network (Tailscale/VPN), which never advertises on mDNS, still reads Online.
    pub(crate) probed: HashMap<String, bool>,
    pub(crate) status: String,
    /// Connected-controller count (root state, mirrored from the gamepad service) — a
    /// pad plus a paired host surfaces the "Open console UI" hint card.
    pub(crate) pads: usize,
    pub(crate) forget: Option<(String, String)>,
    pub(crate) rename: Option<(String, String)>,
    /// Whether the "Add host" modal is open. Root state (like `forget`/`rename`), not the page's
    /// own `use_state`: a child component's sync `SetState` marks its slot dirty but does not
    /// re-render when its props are otherwise unchanged, so the toggle wouldn't take.
    pub(crate) show_add: bool,
    /// The modal's entrance-tween progress (0 → 1, root-driven): opacity + slide-up offset.
    pub(crate) add_anim: f64,
    /// The hovered tile's stable id (saved: fp_hex, discovered: `addr:port`) — root state because
    /// the pointer enter/exit handlers bypass the reconciler flush, like the flyout clicks above.
    pub(crate) hover: Option<String>,
    /// Bumped when a menu action changes what the page should SHOW without changing any
    /// state it already reads — pinning/unpinning a profile tile, which rewrites the
    /// known-hosts store behind the tiles (the hosts-page mirror of `settings_rev`).
    pub(crate) hosts_rev: u64,
    pub(crate) set_forget: AsyncSetState<Option<(String, String)>>,
    pub(crate) set_rename: AsyncSetState<Option<(String, String)>>,
    pub(crate) set_show_add: AsyncSetState<bool>,
    pub(crate) set_hover: AsyncSetState<Option<String>>,
    pub(crate) set_hosts_rev: AsyncSetState<u64>,
}

impl PartialEq for HostsProps {
    fn eq(&self, other: &Self) -> bool {
        // Setters are identity-stable; only the value fields drive re-render.
        self.svc == other.svc
            && self.hosts == other.hosts
            && self.probed == other.probed
            && self.status == other.status
            && self.pads == other.pads
            && self.forget == other.forget
            && self.rename == other.rename
            && self.show_add == other.show_add
            && self.add_anim == other.add_anim
            && self.hover == other.hover
            && self.hosts_rev == other.hosts_rev
    }
}

/// A host tile. The tap-to-connect summary (monogram, name, address, status row) and the
/// optional "…" menu button are SIBLINGS overlaid in one grid cell, never nested: WinUI bubbles
/// `Tapped` out of buttons (reactor doesn't mark it handled), so a button inside the tap target
/// would fire both its own click and the tile's connect (the old forget-also-connects bug).
///
/// Hover renders the WinUI card pointer-over look — the card background lifts to the control
/// hover fill while the pointer is inside the tile (tracked via `hover`, see `HostsProps`).
fn host_tile(
    id: &str,
    hover: &Hover,
    name: &str,
    sub: &str,
    status_row: Element,
    menu: Option<Button>,
    on_tap: Option<Box<dyn Fn()>>,
) -> Element {
    let mut summary = border(
        vstack((
            avatar(name)
                .width(44.0)
                .height(44.0)
                .horizontal_alignment(HorizontalAlignment::Left),
            text_block(name)
                .font_size(15.0)
                .semibold()
                .wrap()
                .margin(edges(0.0, 12.0, 0.0, 0.0)),
            text_block(sub)
                .font_size(12.0)
                .font_family("Consolas")
                .foreground(ThemeRef::SecondaryText)
                .margin(edges(0.0, 2.0, 0.0, 0.0)),
            status_row,
        ))
        .spacing(0.0),
    )
    .background(hit_test_backstop())
    .padding(uniform(18.0));
    if let Some(f) = on_tap {
        summary = summary.on_tapped(f);
    }

    let mut children: Vec<Element> = vec![summary.into()];
    if let Some(m) = menu {
        children.push(
            m.horizontal_alignment(HorizontalAlignment::Right)
                .vertical_alignment(VerticalAlignment::Top)
                .margin(edges(0.0, 8.0, 8.0, 0.0))
                .into(),
        );
    }
    let mut tile = card_flush(grid(children));
    if hover.current.as_deref() == Some(id) {
        tile = tile.background(ThemeRef::ControlFillSecondary);
    }
    let enter = {
        let (set, id) = (hover.set.clone(), id.to_string());
        move |_: PointerEventInfo| set.call(Some(id.clone()))
    };
    let exit = {
        let set = hover.set.clone();
        move || set.call(None)
    };
    tile.on_pointer_entered(enter)
        .on_pointer_exited(exit)
        .into()
}

/// The hover-tracking pair `host_tile` needs: the currently hovered tile id + its root setter.
pub(crate) struct Hover {
    pub(crate) current: Option<String>,
    pub(crate) set: AsyncSetState<Option<String>>,
}

/// The status row at the bottom of a tile: the host's OS mark (when advertised), presence
/// dot + Online/Offline, plus a trust chip only where it says something (see
/// [`status_row_with`]).
fn status_row(os: &str, online: Option<bool>, badge: Option<(&str, Pill)>) -> Element {
    status_row_with(os, online, badge, None)
}

/// [`status_row`] plus the profile: what a plain click on THIS tile will use — its own
/// profile on a pinned tile, the host's binding on the primary one. A binding whose profile
/// was deleted shows nothing and resolves as the defaults, which is what will happen on
/// connect (design §6).
///
/// The row is METADATA, not a badge shelf — three chips side by side read as noise. Paired
/// is the normal resting state of a saved host, so it earns NO chip at all; a chip appears
/// only where it carries a decision ("Trusted" = TOFU without pairing, "PIN"/"Open" on a
/// discovered host). The profile is a small dot in the profile's own colour plus its name
/// in plain caption text — recognisable at a glance without competing with the host name.
fn status_row_with(
    os: &str,
    online: Option<bool>,
    badge: Option<(&str, Pill)>,
    profile: Option<(&str, Option<String>)>,
) -> Element {
    let mut items: Vec<Element> = Vec::new();
    // The OS mark leads the row; nothing at all for an older host that doesn't advertise
    // one, so those tiles render exactly as they always did. Raster at 16px from the
    // materialized cache (reactor has no vector element); the raw chain is the tooltip.
    if let Some(uri) = super::os_icons::uri(os) {
        items.push(
            Image::new_with_uri(uri)
                .width(16.0)
                .height(16.0)
                .tooltip(os)
                .vertical_alignment(VerticalAlignment::Center)
                .into(),
        );
    }
    if let Some(online) = online {
        items.push(
            presence_dot(online)
                .vertical_alignment(VerticalAlignment::Center)
                .into(),
        );
        items.push(
            text_block(if online { "在线" } else { "离线" })
                .font_size(11.0)
                .foreground(ThemeRef::SecondaryText)
                .vertical_alignment(VerticalAlignment::Center)
                .into(),
        );
    }
    if let Some((badge, kind)) = badge {
        items.push(
            pill(badge, kind)
                .vertical_alignment(VerticalAlignment::Center)
                .into(),
        );
    }
    if let Some((name, accent)) = profile {
        // The profile's own colour where it has one, a neutral disc where it doesn't — the
        // palette stays opt-in, and an unparsable value falls back rather than being trusted.
        let colour = accent
            .as_deref()
            .and_then(super::settings::hex_color)
            .unwrap_or(Color {
                a: 120,
                r: 128,
                g: 128,
                b: 128,
            });
        items.push(
            border(vstack(Vec::<Element>::new()).width(8.0).height(8.0))
                .background(colour)
                .corner_radius(4.0)
                .margin(edges(
                    if items.is_empty() { 0.0 } else { 4.0 },
                    0.0,
                    0.0,
                    0.0,
                ))
                .vertical_alignment(VerticalAlignment::Center)
                .into(),
        );
        items.push(
            text_block(name)
                .font_size(11.0)
                .foreground(ThemeRef::SecondaryText)
                .vertical_alignment(VerticalAlignment::Center)
                .into(),
        );
    }
    hstack(items)
        .spacing(6.0)
        .margin(edges(0.0, 12.0, 0.0, 0.0))
        .into()
}

/// The in-tile host editor (a ContentDialog can't hold text fields): every per-host
/// property in one place, mirroring the Apple client's add/edit sheet — name, address,
/// port, Wake-on-LAN MAC, and whether this machine shares its clipboard with the host.
/// Replaced a menu-item-per-property, which buried the useful entries in noise.
///
/// Drafts live in refs owned by the page and are read at Save time; the root `edit` state
/// carries only the target's fingerprint + initial name, so typing doesn't round-trip
/// through a re-render.
#[allow(clippy::too_many_arguments)]
fn edit_editor(
    fp: &str,
    initial_name: &str,
    name_draft: HookRef<String>,
    addr_draft: HookRef<String>,
    port_draft: HookRef<String>,
    mac_draft: HookRef<String>,
    clip_draft: HookRef<bool>,
    set_edit: AsyncSetState<Option<(String, String)>>,
) -> Element {
    let commit = {
        let (fp, se) = (fp.to_string(), set_edit.clone());
        let (name_draft, addr_draft, port_draft, mac_draft, clip_draft) = (
            name_draft.clone(),
            addr_draft.clone(),
            port_draft.clone(),
            mac_draft.clone(),
            clip_draft.clone(),
        );
        move || {
            let mut known = KnownHosts::load();
            if let Some(h) = known.hosts.iter_mut().find(|h| h.fp_hex == fp) {
                // Each field falls back to what was stored: a cleared box means "leave it",
                // never "erase it" — except the MAC, which is legitimately clearable.
                let name = name_draft.borrow().trim().to_string();
                if !name.is_empty() {
                    h.name = name;
                }
                let addr = addr_draft.borrow().trim().to_string();
                if !addr.is_empty() {
                    h.addr = addr;
                }
                if let Ok(p) = port_draft.borrow().trim().parse::<u16>()
                    && p != 0
                {
                    h.port = p;
                }
                let mac = mac_draft.borrow().trim().to_string();
                h.mac = if mac.is_empty() {
                    Vec::new()
                } else {
                    mac.split(&[',', ' '][..])
                        .filter(|m| !m.trim().is_empty())
                        .map(|m| m.trim().to_string())
                        .collect()
                };
                h.clipboard_sync = *clip_draft.borrow();
            }
            let _ = known.save();
            se.call(None);
        }
    };
    // The profile binding: what a plain click on this tile will use. It commits on change
    // rather than at Save — it is a picker with no draft ref, and the rest of the sheet's
    // fields are text boxes that genuinely need one.
    let profile_picker = {
        let catalog = pf_client_core::profiles::ProfilesFile::load();
        let stored = KnownHosts::load()
            .hosts
            .iter()
            .find(|h| h.fp_hex == fp)
            .and_then(|h| h.profile_id.clone());
        let mut names = vec!["默认设置".to_string()];
        let mut ids: Vec<String> = vec![String::new()];
        for p in &catalog.profiles {
            names.push(p.name.clone());
            ids.push(p.id.clone());
        }
        // A binding whose profile is gone reads as Default settings — the same "dangling
        // resolves as none" rule the connect path follows — and is cleaned up on the next pick.
        let current = stored
            .as_ref()
            .and_then(|id| ids.iter().position(|i| i == id))
            .unwrap_or(0);
        let fp = fp.to_string();
        ComboBox::new(names)
            .header("配置方案")
            .selected_index(current as i32)
            .on_selection_changed(move |i: i32| {
                let Some(id) = ids.get(i.max(0) as usize) else {
                    return;
                };
                let mut known = KnownHosts::load();
                if let Some(h) = known.hosts.iter_mut().find(|h| h.fp_hex == fp) {
                    h.profile_id = (!id.is_empty()).then(|| id.clone());
                    let _ = known.save();
                }
            })
    };
    let field = |label: &str, value: String, placeholder: &str, draft: HookRef<String>| {
        vstack((
            text_block(label)
                .font_size(12.0)
                .foreground(ThemeRef::SecondaryText)
                .horizontal_alignment(HorizontalAlignment::Left),
            text_box(&value)
                .placeholder_text(placeholder)
                .on_text_changed(move |t: String| draft.set(t)),
        ))
        .spacing(2.0)
    };
    let (name0, addr0, port0, mac0, clip0) = (
        name_draft.borrow().clone(),
        addr_draft.borrow().clone(),
        port_draft.borrow().clone(),
        mac_draft.borrow().clone(),
        *clip_draft.borrow(),
    );
    // A centred SHEET (scrim + card), not an in-grid tile: as a tile the editor inherited a
    // grid cell in the middle of the page, and on an ordinary window its lower half sat
    // below the fold with nothing hinting at it (live-diagnosed 2026-07-29: a control's
    // visible rect was a 9-px sliver). A sheet centres at its own height — and its content
    // sits in a scroll_view, so a short window scrolls the card instead of clipping it.
    // A tap on the scrim, or Escape, cancels (a tap INSIDE the card bubbles to the scrim —
    // the flag makes the scrim swallow exactly that one).
    let inside_tap = std::rc::Rc::new(std::cell::Cell::new(false));
    let cancel = {
        let se = set_edit.clone();
        move || se.call(None)
    };
    let modal = dialog_surface(scroll_view(
        vstack((
            text_block(format!("编辑 \u{201c}{initial_name}\u{201d}"))
                .font_size(20.0)
                .bold(),
            field("名称", name0, "例如：客厅", name_draft),
            field("地址", addr0, "IP 或主机名", addr_draft),
            field("端口", port0, "9777", port_draft),
            field(
                "MAC（网络唤醒）",
                mac0,
                "已知时自动填写",
                mac_draft,
            ),
            vstack((
                profile_picker,
                text_block(
                    "直接点击此主机时使用的设置。磁贴菜单中的\u{201c}使用配置连接\u{201d}\
                     可临时覆盖一次，不会修改此处的绑定。",
                )
                .font_size(12.0)
                .foreground(ThemeRef::SecondaryText)
                .wrap()
                .horizontal_alignment(HorizontalAlignment::Left),
            ))
            .spacing(4.0),
            vstack((
                ToggleSwitch::new(clip0)
                    .header("与此主机共享剪贴板")
                    .on_content("开")
                    .off_content("关")
                    .on_toggled(move |v: bool| clip_draft.set(v)),
                text_block(
                    "在一台机器上复制，在另一台机器上粘贴。默认对所有主机关闭，需在此\
                     开启；主机端也必须允许剪贴板共享。",
                )
                .font_size(12.0)
                .foreground(ThemeRef::SecondaryText)
                .wrap()
                .horizontal_alignment(HorizontalAlignment::Left),
            ))
            .spacing(4.0),
            hstack((
                button("保存")
                    .accent()
                    .icon(Symbol::Accept)
                    .on_click(commit),
                button("取消")
                    .subtle()
                    .on_click(move || set_edit.call(None)),
            ))
            .spacing(8.0)
            .horizontal_alignment(HorizontalAlignment::Right),
        ))
        .spacing(10.0),
    ))
    .on_tapped({
        let inside_tap = inside_tap.clone();
        move || inside_tap.set(true)
    })
    .max_width(460.0)
    .horizontal_alignment(HorizontalAlignment::Center)
    .vertical_alignment(VerticalAlignment::Center)
    .margin(uniform(24.0));
    let scrim_cancel = cancel.clone();
    Element::from(
        border(modal)
            .background(Color {
                a: 140,
                r: 0,
                g: 0,
                b: 0,
            })
            .on_tapped(move || {
                if inside_tap.replace(false) {
                    return;
                }
                scrim_cancel();
            }),
    )
    .keyboard_accelerator(KeyboardAccelerator::new(
        VirtualKey::Escape,
        VirtualKeyModifiers::None,
        cancel,
    ))
}

pub(crate) fn hosts_page(props: &HostsProps, cx: &mut RenderCx) -> Element {
    let ctx = &props.svc.ctx;
    let hosts = props.hosts.as_slice();
    let status = props.status.as_str();
    let set_screen = &props.svc.set_screen;
    let set_status = &props.svc.set_status;
    let (manual, set_manual) = cx.use_state(String::new());
    // The Add-host field's live value, read by Connect at click time. This page's `use_state` is
    // unreliable as the click's source of truth: while the modal is open the page usually has no
    // reason to re-render (you open it precisely because the host ISN'T being discovered, so no
    // discovery tick fires), and the top-down reconcile skips this unchanged-props subtree — so a
    // sync `set_manual` write never re-renders the Connect button to re-capture the address, and it
    // would connect to the empty mount-time value. Mirror every keystroke into this stable ref (the
    // pair-screen PIN pattern). `manual` still drives the text box's displayed value.
    let manual_live = cx.use_ref(String::new());
    // "Add host" modal open state lives in ROOT (see `HostsProps`).
    let show_add = props.show_add;
    let set_show_add = &props.set_show_add;
    // Forget confirmation and in-progress rename live in ROOT state (see `HostsProps`) — the
    // overflow menu's flyout clicks can't re-render off a sync setter. Both are `(fp_hex, _)`.
    let forget = props.forget.clone();
    let rename = props.rename.clone();
    let set_forget = &props.set_forget;
    let set_rename = &props.set_rename;
    // The live edit drafts, read at Save time (see `edit_editor`). Root `rename` carries only
    // the target's fingerprint + initial name, so typing never round-trips through a
    // re-render. Every draft is re-seeded from the STORED host whenever the edit target
    // changes (open, cancel, or switching to another host).
    let name_draft = cx.use_ref(String::new());
    let addr_draft = cx.use_ref(String::new());
    let port_draft = cx.use_ref(String::new());
    let mac_draft = cx.use_ref(String::new());
    let clip_draft = cx.use_ref(false);
    let edit_seed = cx.use_ref(Option::<String>::None);
    {
        let active = rename.as_ref().map(|(fp, _)| fp.clone());
        if *edit_seed.borrow() != active {
            let stored = active.as_ref().and_then(|fp| {
                KnownHosts::load()
                    .hosts
                    .into_iter()
                    .find(|h| &h.fp_hex == fp)
            });
            name_draft.set(stored.as_ref().map(|h| h.name.clone()).unwrap_or_default());
            addr_draft.set(stored.as_ref().map(|h| h.addr.clone()).unwrap_or_default());
            port_draft.set(
                stored
                    .as_ref()
                    .map(|h| h.port.to_string())
                    .unwrap_or_default(),
            );
            mac_draft.set(
                stored
                    .as_ref()
                    .map(|h| h.mac.join(", "))
                    .unwrap_or_default(),
            );
            clip_draft.set(stored.as_ref().is_some_and(|h| h.clipboard_sync));
            edit_seed.set(active);
        }
    }
    let hover = Hover {
        current: props.hover.clone(),
        set: props.set_hover.clone(),
    };
    let known = KnownHosts::load();

    // Responsive column count from the live window width (re-renders on resize): as many
    // TILE_MIN_WIDTH columns as fit the page's content width, at least one.
    let window = cx.use_inner_size();
    let content_w = (window.width - 64.0).clamp(TILE_MIN_WIDTH, 1120.0);
    let cols = (((content_w + TILE_GAP) / (TILE_MIN_WIDTH + TILE_GAP)).floor() as usize).max(1);
    let mut body: Vec<Element> = Vec::new();

    // Header: title block + the page actions. ONE labelled primary — Add host, in accent —
    // and the rest icon-only with tooltips: four written-out buttons in a row read as four
    // competing calls to action (review feedback), and icon-only needs no compact-width
    // special case either.
    let icon_btn =
        |label: &str, sym: Symbol| button("").icon(sym).tooltip(label).automation_name(label);
    body.push(
        grid((
            vstack((
                text_block("Punktfunk").font_size(30.0).bold(),
                text_block("从网络中的主机串流。")
                    .wrap()
                    .foreground(ThemeRef::SecondaryText),
            ))
            .spacing(2.0)
            .grid_column(0)
            .vertical_alignment(VerticalAlignment::Center),
            hstack({
                let mut actions: Vec<Element> = vec![button("添加主机")
                    .icon(Symbol::Add)
                    .accent()
                    .on_click({
                        let sa = set_show_add.clone();
                        move || sa.call(true)
                    })
                    .into()];
                // Re-query mDNS. The browse runs for the app's lifetime, and `mdns-sd` backs its
                // re-query interval off to as much as an hour — so a host that appeared since
                // startup, or whose announcement was lost to multicast, may need an actual ask.
                actions.push(
                    icon_btn("重新扫描网络中的主机", Symbol::Refresh)
                        .on_click({
                            let (c, st) = (ctx.clone(), set_status.clone());
                            move || {
                                if let Some(r) = c.shared.rescan.lock().unwrap().as_ref() {
                                    r.request();
                                }
                                st.call("正在扫描网络\u{2026}".to_string());
                            }
                        })
                        .into(),
                );
                // The couch UI's front door, beside the other page actions. Absent on ARM64,
                // where the session binary ships without its Skia console.
                if CONSOLE_UI_AVAILABLE {
                    actions.push(
                        icon_btn(
                            "控制台 UI\u{2014}\u{2014}手柄驱动的客厅界面",
                            Symbol::Play,
                        )
                        .on_click({
                            let (c, ss, st) = (ctx.clone(), set_screen.clone(), set_status.clone());
                            // No target: the console opens its OWN host view rather than
                            // one host's library — the couch counterpart of this page.
                            move || open_console(&c, None, &ss, &st)
                        })
                        .into(),
                    );
                }
                actions.push(
                    icon_btn("键盘快捷键", Symbol::Keyboard)
                        .on_click({
                            let ss = set_screen.clone();
                            move || ss.call(Screen::Help)
                        })
                        .into(),
                );
                actions.push(
                    icon_btn("设置", Symbol::Setting)
                        .on_click({
                            let (c, ss) = (ctx.clone(), set_screen.clone());
                            move || {
                                // Re-base the settings snapshot on the file before the page
                                // renders — this process is not its only writer (see
                                // settings::refresh_snapshot).
                                super::settings::refresh_snapshot(&c);
                                ss.call(Screen::Settings)
                            }
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
        .into(),
    );

    if !status.is_empty() {
        body.push(
            InfoBar::new("连接失败")
                .message(status.to_string())
                .error()
                .is_closable(false)
                .into(),
        );
    }

    // Saved (trusted/paired) hosts — reachable even when mDNS isn't. A saved host that's also
    // being advertised right now shows as Online (and is deduped out of the discovery section).
    if !known.hosts.is_empty() {
        body.push(section("已保存的主机"));
        let mut tiles: Vec<Element> = Vec::new();
        // One catalog read per render, shared by every tile's menu and chip.
        let profiles: Vec<(String, String, Option<String>)> =
            pf_client_core::profiles::ProfilesFile::load()
                .profiles
                .into_iter()
                .map(|p| (p.id, p.name, p.accent))
                .collect();
        for k in &known.hosts {
            let target = Target {
                name: k.name.clone(),
                addr: k.addr.clone(),
                port: k.port,
                fp_hex: Some(k.fp_hex.clone()),
                pair_optional: false,
                mac: k.mac.clone(),
                mgmt_port: k.mgmt_port,
                profile: None,
                launch: None,
            };
            // Online = advertising on mDNS OR proven reachable by the last probe sweep (the latter
            // covers a routed/Tailscale host that never advertises — the display companion to
            // dial-first).
            let online = hosts
                .iter()
                .any(|h| h.fp_hex == k.fp_hex || (h.addr == k.addr && h.port == k.port))
                || props.probed.get(&k.fp_hex).copied().unwrap_or(false);
            // Learn what this host's live advert teaches while it's online: its wake MAC(s) (so we
            // can wake it once it sleeps), its OS chain (so the tile's mark survives it going
            // offline), and its management port — the last load-bearing rather than cosmetic, as
            // a host moved off 47990 loses its library entirely once mDNS is gone unless we write
            // the port down. No-op, and no disk write, when unchanged.
            if let Some(a) = hosts
                .iter()
                .find(|h| h.fp_hex == k.fp_hex || (h.addr == k.addr && h.port == k.port))
            {
                crate::trust::learn_from_advert(
                    &k.fp_hex,
                    &k.addr,
                    k.port,
                    &a.mac,
                    &a.os,
                    a.mgmt_port,
                );
            }
            let can_wake = !online && !k.mac.is_empty();
            let menu = {
                let (svc, target) = (props.svc.clone(), target.clone());
                let (sf, sr) = (set_forget.clone(), set_rename.clone());
                let (fp, name) = (k.fp_hex.clone(), k.name.clone());
                let menu_profiles = profiles.clone();
                let pinned_now = k.pinned_profiles.clone();
                let (hosts_rev, set_hosts_rev) = (props.hosts_rev, props.set_hosts_rev.clone());
                let (link_host, link_profile) = (k.clone(), None::<String>);
                let shortcut_host = k.clone();
                button("")
                    .icon(Symbol::More)
                    .subtle()
                    .tooltip("更多选项")
                    .automation_name("更多选项")
                    .menu_flyout({
                        // Kept short deliberately, and in sections. It had grown into a list of
                        // everything, with the entries you actually reach for (connect, library,
                        // speed) buried in list management. The per-profile families nest in
                        // SUBMENUS — one "Connect with" and one "Pin tiles" — so the top level
                        // stays a fixed handful whatever the catalog grows to.
                        let mut items = vec![menu_item(MENU_CONNECT)];
                        // One-off connects: "Connect with" NEVER rebinds the host. Submenu
                        // leaves report their own text, so the leaf names stay bare.
                        if !profiles.is_empty() {
                            let mut leaves: Vec<MenuItemDef> = profiles
                                .iter()
                                .map(|(_, name, _)| menu_item(name.clone()))
                                .collect();
                            leaves.push(menu_item(SUB_WITH_DEFAULT));
                            items.push(menu_sub_item(SUB_WITH, leaves));
                        }

                        items.push(menu_separator());
                        // The library surfaces — mouse/KB page and the gamepad console UI — for
                        // paired hosts only, because the mgmt API needs the paired identity.
                        if k.paired {
                            items.push(menu_item(MENU_LIBRARY));
                        }
                        items.push(menu_item(MENU_SPEED));
                        // An explicit wake only when the host is offline and we have a MAC.
                        if can_wake {
                            items.push(menu_item(MENU_WAKE));
                        }

                        items.push(menu_separator());
                        items.push(menu_item(MENU_COPY_LINK));
                        items.push(menu_item(MENU_SHORTCUT));
                        // Pin/unpin a profile's one-click tile, beside the other tile-shaped
                        // shortcuts. The verb prefixes stay on the leaves: "Connect with"'s
                        // leaves are bare names, and the shared click callback only gets the
                        // leaf text — the prefix is what keeps the two families apart.
                        if !profiles.is_empty() {
                            let leaves: Vec<MenuItemDef> = profiles
                                .iter()
                                .map(|(id, name, _)| {
                                    let pinned = pinned_now.iter().any(|x| x == id);
                                    menu_item(format!(
                                        "{}{name}",
                                        if pinned { MENU_UNPIN } else { MENU_PIN }
                                    ))
                                })
                                .collect();
                            items.push(menu_sub_item(SUB_PIN, leaves));
                        }

                        items.push(menu_separator());
                        items.push(menu_item(MENU_EDIT));
                        items.push(menu_item(MENU_FORGET));
                        items
                    })
                    .on_item_clicked(move |item: String| match item.as_str() {
                        // The profile items are dynamic, so they are matched by prefix before
                        // the fixed ones.
                        _ if item.starts_with(MENU_PIN) || item.starts_with(MENU_UNPIN) => {
                            let (on, name) = if let Some(n) = item.strip_prefix(MENU_PIN) {
                                (true, n)
                            } else {
                                (false, item.trim_start_matches(MENU_UNPIN))
                            };
                            let Some((id, ..)) = menu_profiles.iter().find(|(_, n, _)| n == name)
                            else {
                                return;
                            };
                            tracing::info!(pin = %id, host = %fp, on, "pin toggle");
                            let mut known = KnownHosts::load();
                            if let Some(h) = known.hosts.iter_mut().find(|h| h.fp_hex == fp) {
                                h.pinned_profiles.retain(|x| x != id);
                                if on {
                                    h.pinned_profiles.push(id.clone());
                                }
                                if let Err(e) = known.save() {
                                    tracing::warn!(error = %format!("{e:#}"), "saving a pin");
                                }
                            }
                            // The store changed behind the tiles and nothing the page reads
                            // as state did — the bump is what makes the pinned tile appear
                            // (or vanish) NOW, not on the next discovery tick.
                            set_hosts_rev.call(hosts_rev + 1);
                        }
                        MENU_SHORTCUT => {
                            let url = pf_client_core::deeplink::DeepLink::for_host(
                                &shortcut_host,
                                None,
                                None,
                            )
                            .to_url();
                            match crate::deeplink::write_shortcut(&shortcut_host.name, &url) {
                                Ok(p) => tracing::info!(path = %p.display(), "shortcut written"),
                                Err(e) => tracing::warn!(error = %e, "writing the shortcut"),
                            }
                        }
                        MENU_COPY_LINK => {
                            let url = pf_client_core::deeplink::DeepLink::for_host(
                                &link_host,
                                None,
                                link_profile.as_deref(),
                            )
                            .to_url();
                            pf_client_core::clipboard::set_text(&url);
                        }
                        MENU_CONNECT => {
                            initiate(&svc.ctx, target.clone(), &svc.set_screen, &svc.set_status)
                        }
                        MENU_LIBRARY => {
                            *svc.ctx.shared.target.lock().unwrap() = target.clone();
                            super::library::start_fetch(&svc.ctx, &svc.set_library);
                            svc.set_screen.call(Screen::Library);
                        }
                        MENU_WAKE => crate::wol::wake(&target.mac, target.addr.parse().ok()),
                        MENU_SPEED => {
                            *svc.ctx.shared.target.lock().unwrap() = target.clone();
                            // New run: invalidate any still-in-flight probe, reset the screen.
                            svc.ctx
                                .shared
                                .speed_gen
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            svc.set_speed.call(SpeedState::Running);
                            svc.set_screen.call(Screen::SpeedTest);
                        }
                        MENU_EDIT => sr.call(Some((fp.clone(), name.clone()))),
                        MENU_FORGET => sf.call(Some((fp.clone(), name.clone()))),
                        // "Connect with"'s submenu leaves: a bare profile name, or
                        // SUB_WITH_DEFAULT. `Some("")` — not `None` — so Default settings
                        // really does override a bound host for this one connect.
                        other => {
                            let profile_id = if other == SUB_WITH_DEFAULT {
                                Some(String::new())
                            } else {
                                menu_profiles
                                    .iter()
                                    .find(|(_, n, _)| n == other)
                                    .map(|(id, _, _)| id.clone())
                            };
                            if let Some(id) = profile_id {
                                let mut target = target.clone();
                                target.profile = Some(id);
                                initiate(&svc.ctx, target, &svc.set_screen, &svc.set_status)
                            }
                        }
                    })
            };
            let (ctx2, ss, st) = (ctx.clone(), set_screen.clone(), set_status.clone());
            let pinned_base = target.clone();
            tiles.push(host_tile(
                &k.fp_hex,
                &hover,
                &k.name,
                &format!("{}:{}", k.addr, k.port),
                status_row_with(
                    &k.os,
                    Some(online),
                    // Paired is the resting state — no chip; TOFU-only trust is worth one.
                    (!k.paired).then_some(("已信任", Pill::Info)),
                    // The dot carries the profile's own colour where it has one —
                    // that is what makes two bound hosts tell apart at a glance.
                    k.profile_id
                        .as_ref()
                        .and_then(|id| profiles.iter().find(|(pid, _, _)| pid == id))
                        .map(|(_, name, accent)| (name.as_str(), accent.clone())),
                ),
                Some(menu),
                Some(Box::new(move || {
                    // Saved host with a known MAC that isn't advertising: fire a wake packet and
                    // DIAL IMMEDIATELY — mDNS absence ≠ unreachable (a routed/Tailscale host never
                    // advertises here); only a failed dial falls into the "Waking…" wait. An
                    // online host dials straight away.
                    if can_wake {
                        initiate_waking(&ctx2, target.clone(), &ss, &st);
                    } else {
                        initiate(&ctx2, target.clone(), &ss, &st);
                    }
                })),
            ));

            // …then this host's pinned host+profile tiles, in the order they were pinned
            // (design §5.2a). They share the host's live status because they read the same
            // record, and a pin whose profile is gone simply doesn't render. Their menu is
            // deliberately short: a pinned tile is a shortcut, not a second host, so it carries
            // only what STARTS it (the library — this tile's connect with a title picked first,
            // which is why the grid it opens launches with the tile's profile), the link that
            // reproduces it, and the way to remove it. Everything that configures the machine —
            // pair, speed test, wake, edit, forget, and pinning itself — stays on the primary
            // tile's menu, the one place you decide it.
            for id in &k.pinned_profiles {
                let Some((id, name, accent)) = profiles.iter().find(|(pid, ..)| pid == id) else {
                    continue;
                };
                let (ctx3, ss3, st3) = (ctx.clone(), set_screen.clone(), set_status.clone());
                let mut pinned_target = pinned_base.clone();
                pinned_target.profile = Some(id.clone());
                let pinned_menu = {
                    let (svc, target) = (props.svc.clone(), pinned_target.clone());
                    let (fp, pin_id) = (k.fp_hex.clone(), id.clone());
                    let (hosts_rev, set_hosts_rev) = (props.hosts_rev, props.set_hosts_rev.clone());
                    let link_host = k.clone();
                    let link_profile = id.clone();
                    let unpin_label = format!("{MENU_UNPIN}{name}");
                    let unpin_item = unpin_label.clone();
                    button("")
                        .icon(Symbol::More)
                        .subtle()
                        .tooltip("More options")
                        .automation_name("More options")
                        .menu_flyout({
                            let mut items = Vec::new();
                            // Same gate as the primary tile's: the mgmt API needs the paired
                            // identity, so an unpaired host has nothing to show.
                            if k.paired {
                                items.push(menu_item(MENU_LIBRARY));
                            }
                            items.push(menu_item(MENU_COPY_LINK));
                            items.push(menu_separator());
                            items.push(menu_item(unpin_label));
                            items
                        })
                        .on_item_clicked(move |item: String| match item.as_str() {
                            MENU_LIBRARY => {
                                // The shared target IS what the library page launches through, so
                                // parking THIS tile's target here is what makes its grid launch
                                // with the pinned profile.
                                *svc.ctx.shared.target.lock().unwrap() = target.clone();
                                super::library::start_fetch(&svc.ctx, &svc.set_library);
                                svc.set_screen.call(Screen::Library);
                            }
                            MENU_COPY_LINK => {
                                let url = pf_client_core::deeplink::DeepLink::for_host(
                                    &link_host,
                                    None,
                                    Some(link_profile.as_str()),
                                )
                                .to_url();
                                pf_client_core::clipboard::set_text(&url);
                            }
                            other if other == unpin_item => {
                                tracing::info!(pin = %pin_id, host = %fp, on = false, "pin toggle");
                                let mut known = KnownHosts::load();
                                if let Some(h) = known.hosts.iter_mut().find(|h| h.fp_hex == fp) {
                                    h.pinned_profiles.retain(|x| x != &pin_id);
                                    if let Err(e) = known.save() {
                                        tracing::warn!(
                                            error = %format!("{e:#}"), "saving a pin"
                                        );
                                    }
                                }
                                // Same reason as the primary tile's toggle: nothing the page reads
                                // as state changed, so the bump is what makes this tile vanish NOW.
                                set_hosts_rev.call(hosts_rev + 1);
                            }
                            _ => {}
                        })
                };
                tiles.push(host_tile(
                    // Its own hover key: two tiles for one host must not light up together.
                    &format!("{}#{id}", k.fp_hex),
                    &hover,
                    &k.name,
                    &format!("{}:{}", k.addr, k.port),
                    status_row_with(
                        &k.os,
                        Some(online),
                        (!k.paired).then_some(("已信任", Pill::Info)),
                        Some((name.as_str(), accent.clone())),
                    ),
                    Some(pinned_menu),
                    Some(Box::new(move || {
                        if can_wake {
                            initiate_waking(&ctx3, pinned_target.clone(), &ss3, &st3);
                        } else {
                            initiate(&ctx3, pinned_target.clone(), &ss3, &st3);
                        }
                    })),
                ));
            }
        }
        body.push(tile_grid(tiles, cols, TILE_GAP));
    }

    // Discovered hosts not already saved above.
    body.push(section("本网络中的主机"));
    let discovered: Vec<&DiscoveredHost> = hosts
        .iter()
        .filter(|h| {
            !known.hosts.iter().any(|k| {
                (!h.fp_hex.is_empty() && k.fp_hex == h.fp_hex)
                    || (k.addr == h.addr && k.port == h.port)
            })
        })
        .collect();
    if discovered.is_empty() {
        body.push(
            card(
                hstack((
                    ProgressRing::indeterminate().width(18.0).height(18.0),
                    text_block("正在搜索局域网\u{2026}").foreground(ThemeRef::SecondaryText),
                ))
                .spacing(12.0),
            )
            .into(),
        );
    } else {
        let mut tiles: Vec<Element> = Vec::new();
        for h in discovered {
            let target = Target {
                name: h.name.clone(),
                addr: h.addr.clone(),
                port: h.port,
                fp_hex: (!h.fp_hex.is_empty()).then(|| h.fp_hex.clone()),
                pair_optional: h.pair == "optional",
                mac: h.mac.clone(),
                mgmt_port: h.mgmt_port,
                profile: None,
                launch: None,
            };
            let (ctx2, ss, st) = (ctx.clone(), set_screen.clone(), set_status.clone());
            let (badge, kind) = if h.pair == "required" {
                ("PIN", Pill::Info)
            } else {
                ("开放", Pill::Neutral)
            };
            tiles.push(host_tile(
                &format!("{}:{}", h.addr, h.port),
                &hover,
                &h.name,
                &format!("{}:{}", h.addr, h.port),
                status_row(&h.os, None, Some((badge, kind))),
                None,
                Some(Box::new(move || initiate(&ctx2, target.clone(), &ss, &st))),
            ));
        }
        body.push(tile_grid(tiles, cols, TILE_GAP));
    }

    // Forget confirmation, armed while `forget` holds a pending host. ALWAYS MOUNTED with
    // `is_open` doing the arming, and in a STABLE trailing layer rather than in `body`
    // (whose child list shifts with discovery): unmounting — or positionally re-pairing —
    // a ContentDialog trips the reactor backend's phantom-child bookkeeping (the handle
    // dies before `remove_child` runs, the dialog stops being recognised as phantom, and a
    // visual child that never existed gets RemoveAt()'d — E_BOUNDS panic; see the
    // delete-profile dialog in settings.rs). Confirmed first, since it's destructive and
    // re-establishing trust needs a fresh pairing.
    let forget_confirm: Element = {
        let sf = set_forget.clone();
        let pending = forget.clone();
        let content = pending
            .as_ref()
            .map(|(_, name)| {
                format!(
                    "忘记 \u{201C}{name}\u{201D}？重新连接需要再次配对（或信任）\
                     该主机。"
                )
            })
            .unwrap_or_default();
        ContentDialog::new("移除已保存的主机？")
            .content(content)
            .primary_button_text("移除")
            .close_button_text("取消")
            .is_open(pending.is_some())
            .on_closed(move |r: ContentDialogResult| {
                if r == ContentDialogResult::Primary
                    && let Some((fp, _)) = &pending
                {
                    let mut known = KnownHosts::load();
                    known.remove_by_fp(fp);
                    let _ = known.save();
                }
                sf.call(None); // re-renders the page; the row is gone on the next load
            })
            .into()
    };

    let page = page_wide(body);

    // "Add host" modal: a scrim + centered card. It's an in-tree overlay, not a WinUI
    // ContentDialog, because ContentDialog is text-only in windows-reactor (no room for a text
    // field). The scrim border fills the cell and is hit-testable, so it blocks the page behind;
    // it closes only via Cancel/Connect (a scrim tap would bubble `Tapped` up from the card too).
    let connect_manual = {
        let (ctx2, ss, st, live, sa) = (
            ctx.clone(),
            set_screen.clone(),
            set_status.clone(),
            manual_live.clone(),
            set_show_add.clone(),
        );
        move || {
            let text = live.borrow();
            let text = text.trim();
            if text.is_empty() {
                return;
            }
            let (addr, port) = match text.rsplit_once(':') {
                Some((a, p)) => (a.to_string(), p.parse().unwrap_or(9777)),
                None => (text.to_string(), 9777),
            };
            sa.call(false);
            initiate(
                &ctx2,
                Target {
                    name: addr.clone(),
                    addr,
                    port,
                    fp_hex: None,
                    pair_optional: false,
                    mac: Vec::new(),
                    // Added by hand, so nothing has told us where its mgmt API is: fall back to
                    // 47990 (exactly today's behaviour) until an advert teaches us otherwise.
                    // A host that moved its mgmt port AND is never visible on mDNS still needs the
                    // host to announce the port in-band — see the note in `Target::mgmt_port`.
                    mgmt_port: None,
                    profile: None,
                    launch: None,
                },
                &ss,
                &st,
            );
        }
    };
    let modal = dialog_surface(
        vstack((
            text_block("添加主机").font_size(20.0).bold(),
            text_block(
                "输入主机的 IP 地址或名称。仅在使用非默认端口时才附加 :port\
                 （默认端口为 9777）。",
            )
            .font_size(13.0)
            .wrap()
            .foreground(ThemeRef::SecondaryText),
            text_box(manual)
                .header("地址")
                .placeholder_text("192.168.1.20  or  my-pc.local")
                .on_text_changed({
                    let live = manual_live.clone();
                    move |s: String| {
                        live.set(s.clone());
                        set_manual.call(s);
                    }
                })
                .margin(edges(0.0, 6.0, 0.0, 0.0)),
            hstack((
                button("连接")
                    .accent()
                    .icon(Symbol::Forward)
                    .on_click(connect_manual),
                button("取消").on_click({
                    let sa = set_show_add.clone();
                    move || sa.call(false)
                }),
            ))
            .spacing(8.0)
            .horizontal_alignment(HorizontalAlignment::Right)
            .margin(edges(0.0, 6.0, 0.0, 0.0)),
        ))
        .spacing(12.0),
    )
    .max_width(460.0)
    .horizontal_alignment(HorizontalAlignment::Center)
    .vertical_alignment(VerticalAlignment::Center)
    // Entrance: fade + slide up, driven by the root tween (`add_anim` 0 → 1). The card starts
    // a bit low and rises to centre — for a centred element, extra top margin shifts it down by
    // half the difference, so the offset is doubled.
    .opacity(props.add_anim)
    .margin(edges(
        24.0,
        24.0 + (1.0 - props.add_anim) * 56.0,
        24.0,
        24.0,
    ));

    // The scrim fades in with the same tween. Its layer slot is STABLE (a same-kind,
    // background-less Border when closed — invisible and not hit-testable) so the layer
    // list never changes shape around the always-mounted dialog after it. A tap on the
    // scrim, or Escape, cancels — with the same bubble-swallow flag the sheets use.
    let add_slot: Element = if show_add {
        let inside_tap = std::rc::Rc::new(std::cell::Cell::new(false));
        let cancel = {
            let sa = set_show_add.clone();
            move || sa.call(false)
        };
        let scrim_cancel = cancel.clone();
        Element::from(
            border(Element::from(modal).on_tapped({
                let inside_tap = inside_tap.clone();
                move || inside_tap.set(true)
            }))
            .background(Color {
                a: (140.0 * props.add_anim) as u8,
                r: 0,
                g: 0,
                b: 0,
            })
            .on_tapped(move || {
                if inside_tap.replace(false) {
                    return;
                }
                scrim_cancel();
            }),
        )
        .keyboard_accelerator(KeyboardAccelerator::new(
            VirtualKey::Escape,
            VirtualKeyModifiers::None,
            cancel,
        ))
    } else {
        border(vstack(Vec::<Element>::new())).into()
    };
    // The host editor sheet, in its own stable slot (see the add modal's note).
    let edit_slot: Element = if let Some((fp, initial)) = &rename {
        edit_editor(
            fp,
            initial,
            name_draft.clone(),
            addr_draft.clone(),
            port_draft.clone(),
            mac_draft.clone(),
            clip_draft.clone(),
            set_rename.clone(),
        )
    } else {
        border(vstack(Vec::<Element>::new())).into()
    };
    grid(vec![page, add_slot, edit_slot, forget_confirm]).into()
}
