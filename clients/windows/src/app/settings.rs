//! The settings screen. Every control writes straight back to the persisted [`Settings`]
//! (there is no Apply step), via the small [`setting_combo`]/[`setting_toggle`] builders.
//!
//! **Structure mirrors the Apple client's 2026-07 settings revamp** (its
//! `SettingsCategory` + `SettingsView+Sections.swift`), so the two desktop clients read the
//! same way: General = session/app behavior, Display = everything about the picture,
//! Input = touch/keyboard/mouse, Audio, Controllers, About. Each field carries its
//! explanation DIRECTLY under it ([`described`]) rather than only on hover — the same move
//! Apple made, for the same reason (guidance nobody hovers for is guidance nobody reads).
//! Wording is shared verbatim wherever the setting means the same thing on both platforms;
//! where the BEHAVIOR differs the text is deliberately Windows-specific (the forwarded-
//! controller picker especially: Apple forwards one pad, this client forwards them all).

use super::style::*;
use super::{AppCtx, Screen};
use crate::trust::{KnownHosts, Settings};
use pf_client_core::profiles::{ProfilesFile, StreamProfile};
use pf_client_core::trust::StatsVerbosity;
use punktfunk_core::config::GamepadPref;
use std::sync::Arc;
use windows_reactor::*;

/// `(0, 0)` = the native size of the display the window is on, resolved at connect.
const RESOLUTIONS: &[(u32, u32)] = &[
    (0, 0),
    (1280, 720),
    (1920, 1080),
    (2560, 1440),
    (3840, 2160),
];
/// `0` = the display's native refresh, resolved at connect.
const REFRESH: &[u32] = &[0, 30, 60, 90, 120, 144, 165, 240];
/// Render-scale multipliers (persisted as f64; mirrors [`punktfunk_core::render_scale::PRESETS`]).
/// `1.0` = Native. Applied at connect and each match-window resize.
const RENDER_SCALES: &[f64] = &[0.5, 0.67, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 4.0];

/// A compact label for a render-scale multiplier: "Native" / "1.5×" / "2× (supersample)".
fn render_scale_label(scale: f64) -> String {
    if scale == 1.0 {
        "原生".to_string()
    } else if scale > 1.0 {
        format!("{scale}\u{00D7}（超采样）")
    } else {
        format!("{scale}\u{00D7}")
    }
}
/// Decode backend presets: `(stored value, display label)`.
// A stored legacy value that matches no preset (the D3D11VA-era "hardware", and since M10
// the bare "vulkan"/"d3d11va" that named libavcodec's rungs) shows as Automatic — which is
// how the session's ladder reads "hardware", and near enough for the other two, which
// `pf_client_core::video::migrate_decoder_pref` maps onto the entries below anyway.
const DECODERS: &[(&str, &str)] = &[
    ("auto", "自动（GPU，失败时回退 CPU）"),
    ("native-vulkan", "硬件（Vulkan Video）"),
    ("native-d3d11va", "硬件（Direct3D 11 / DXVA）"),
    ("software", "软件（CPU）"),
];
/// Audio channel presets: `(channel count, display label)`. The host clamps to what it can
/// capture; the resolved count drives the decoder + WASAPI render layout.
const AUDIO_CHANNELS: &[(u8, &str)] = &[(2, "立体声"), (6, "5.1 环绕声"), (8, "7.1 环绕声")];
/// Preferred-codec presets: `(stored value, display label)`. Soft — the host falls back if it
/// can't encode the chosen codec.
const CODECS: &[(&str, &str)] = &[
    ("auto", "自动"),
    ("hevc", "HEVC (H.265)"),
    ("h264", "H.264 (AVC)"),
    ("av1", "AV1"),
    // Preference-only by design: `resolve_codec` never auto-picks PyroWave, and asking for
    // it on a host or device that can't do it simply falls back down the ladder to HEVC.
    ("pyrowave", "PyroWave (wired LAN)"),
];
/// Virtual-pad presets: `(stored value, display label)` — the pad the HOST creates. Same set the
/// GTK client offers; "Automatic" resolves from the physical controller at connect.
const GAMEPADS: &[(&str, &str)] = &[
    ("auto", "自动（匹配手柄）"),
    ("xbox360", "Xbox 360"),
    ("dualsense", "DualSense"),
    ("xboxone", "Xbox One"),
    ("dualshock4", "DualShock 4"),
    // Kept in lockstep with the GTK picker: this row was missing here, so a Windows
    // user could not ask the host for the Deck-shaped pad (trackpads, back grips).
    ("steamdeck", "Steam Deck"),
];
/// System-button routing: `(stored value, display label)` — where the guide (Xbox/PS)
/// and quick-access presses land while streaming. The cross-client `system_buttons` key;
/// Automatic forwards on desktop and stays local under Gaming Mode.
const SYSTEM_BUTTONS: &[(&str, &str)] = &[
    ("auto", "自动"),
    ("forward", "发送到主机"),
    ("local", "本设备"),
];
/// The hold-Select guide gesture: `(stored value, display label)` — the cross-client
/// `guide_gesture` key. Automatic arms it only where the raw press can't reach the host.
const GUIDE_GESTURES: &[(&str, &str)] = &[("auto", "自动"), ("on", "开"), ("off", "关")];
/// Stats-overlay tiers: `(stored value, display label)` — the cross-client verbosity ladder
/// (Compact ⊂ Normal ⊂ Detailed); Ctrl+Alt+Shift+S cycles it live in the session window.
const STATS_TIERS: &[(StatsVerbosity, &str)] = &[
    (StatsVerbosity::Off, "关"),
    (StatsVerbosity::Compact, "紧凑"),
    (StatsVerbosity::Normal, "标准"),
    (StatsVerbosity::Detailed, "详细"),
];
/// Touch-input presets: `(stored value, display label)` — how a touchscreen's fingers drive
/// the host. The cross-client set (Android/Apple); only meaningful on a touchscreen device.
const TOUCH_MODES: &[(&str, &str)] = &[
    ("trackpad", "触控板"),
    ("pointer", "直接指针"),
    ("touch", "触摸透传"),
];
/// Physical-mouse presets: `(stored value, display label)` — capture (pointer lock,
/// relative, for games) vs desktop (uncaptured absolute pointer, for remote desktop
/// work). Ctrl+Alt+Shift+M flips the model live in-stream.
const MOUSE_MODES: &[(&str, &str)] = &[
    ("capture", "捕获（游戏）"),
    ("desktop", "桌面（绝对坐标）"),
];
/// Presentation intent: `(stored value, display label)` — the `present_priority` key the
/// Apple and Android clients share, so one profile means the same thing everywhere.
const PRESENT_PRIORITIES: &[(&str, &str)] =
    &[("latency", "最低延迟"), ("smooth", "流畅度")];
/// Smoothness buffer depth in frames: `(stored value, display label)`. `0` = Automatic,
/// which resolves to 2 (`PresentPriority::resolve`). No millisecond hints — the cost is
/// one refresh per frame, and the refresh isn't known here when the mode is Native.
const SMOOTH_BUFFERS: &[(u8, &str)] = &[
    (0, "自动"),
    (1, "1 帧"),
    (2, "2 帧"),
    (3, "3 帧"),
];
/// Host compositor presets: `(stored value, display label)`. Advisory — the host falls back to
/// auto-detect when the choice is unavailable. Only meaningful against a Linux host.
const COMPOSITORS: &[(&str, &str)] = &[
    ("auto", "自动"),
    ("kwin", "KWin"),
    ("wlroots", "wlroots (Sway/Hyprland)"),
    ("mutter", "Mutter (GNOME)"),
    ("gamescope", "gamescope"),
];

/// The chip palette a profile can carry (`StreamProfile.accent`), same set as the GTK client so
/// a profile looks the same on both. Eight legible colours rather than a free picker: the job is
/// telling profiles apart at a glance on a host tile, and the schema still accepts any
/// `#RRGGBB` a hand-edit writes.
const SWATCHES: &[(&str, &str)] = &[
    ("", "无"),
    ("#e01b24", "红"),
    ("#ff7800", "橙"),
    ("#f6d32d", "黄"),
    ("#33d17a", "绿"),
    ("#3584e4", "蓝"),
    ("#9141ac", "紫"),
    ("#d16d9e", "粉"),
    ("#77767b", "灰蓝"),
];

/// `#RRGGBB` to a brush colour. Anything else is refused rather than guessed at — the value is
/// user data and reaches the renderer.
pub(crate) fn hex_color(hex: &str) -> Option<Color> {
    let h = hex.strip_prefix('#')?;
    if h.len() != 6 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(Color {
        a: 255,
        r: u8::from_str_radix(&h[0..2], 16).ok()?,
        g: u8::from_str_radix(&h[2..4], 16).ok()?,
        b: u8::from_str_radix(&h[4..6], 16).ok()?,
    })
}

/// The colour row: one tappable swatch per palette entry, the current one ringed.
fn colour_swatches(profile: &StreamProfile, rev: u64, set_rev: &AsyncSetState<u64>) -> Element {
    let current = profile.accent.clone().unwrap_or_default();
    let mut row: Vec<Element> = vec![text_block("颜色")
        .font_size(12.0)
        .foreground(ThemeRef::SecondaryText)
        .vertical_alignment(VerticalAlignment::Center)
        .margin(edges(0.0, 0.0, 6.0, 0.0))
        .into()];
    for (hex, name) in SWATCHES {
        let selected = current == *hex;
        // "None" (and anything unparsable) draws as a faint neutral disc, so the row still
        // reads as a palette with a clear "no colour" end.
        let fill = hex_color(hex).unwrap_or(Color {
            a: 40,
            r: 128,
            g: 128,
            b: 128,
        });
        let (id, set_rev, hex_owned) = (profile.id.clone(), set_rev.clone(), hex.to_string());
        row.push(
            // Size on the BORDER itself: sized only via its child, the border gets squeezed
            // by the sheet's layout and the discs render as squashed ovals.
            border(vstack(Vec::<Element>::new()))
                .width(20.0)
                .height(20.0)
                .background(fill)
                .corner_radius(10.0)
                .border_brush(if selected {
                    ThemeRef::Accent
                } else {
                    ThemeRef::CardStroke
                })
                .border_thickness(uniform(if selected { 2.0 } else { 1.0 }))
                .tooltip(*name)
                .on_tapped(move || {
                    let mut catalog = ProfilesFile::load();
                    if let Some(p) = catalog.profiles.iter_mut().find(|p| p.id == id) {
                        p.accent = (!hex_owned.is_empty()).then(|| hex_owned.clone());
                        if let Err(e) = catalog.save() {
                            tracing::warn!(error = %format!("{e:#}"), "saving the profile colour");
                        }
                    }
                    set_rev.call(rev + 1);
                })
                .into(),
        );
    }
    hstack(row).spacing(8.0).into()
}

/// The Edit-profile modal: a scrim + centered card, the same in-tree overlay the Add-host
/// modal uses (ContentDialog is text-only in windows-reactor — no room for a text field or
/// the swatch row). Every control in it commits in place, exactly like the settings rows, so
/// the modal needs no draft state and Close is the only way out — there is nothing to cancel.
/// The one deferred repaint is the profile NAME: renaming commits as you type but the pane's
/// scope dropdown refreshes on Close (one revision bump), so the ComboBox is not remounted
/// under the user mid-keystroke.
fn edit_profile_modal(
    profile: Option<&StreamProfile>,
    switcher: Option<ComboBox>,
    set_scope: &AsyncSetState<String>,
    set_delete: &AsyncSetState<Option<String>>,
    set_edit: &AsyncSetState<bool>,
    rev: u64,
    set_rev: &AsyncSetState<u64>,
) -> Element {
    let mut rows: Vec<Element> = vec![text_block(if switcher.is_some() {
        "配置方案"
    } else {
        "编辑配置方案"
    })
    .font_size(20.0)
    .bold()
    .into()];
    if let Some(sw) = switcher {
        // Keyed by scope: an in-sheet scope switch re-renders this combo with a different
        // selection, and the in-place diff would leave it blank (the documented
        // items/selected_index hazard) — a remount applies every prop.
        rows.push(
            vstack(vec![Element::from(sw)])
                .with_key(format!(
                    "sheet-scope-{}",
                    profile.map(|p| p.id.as_str()).unwrap_or("")
                ))
                .into(),
        );
    }
    if let Some(profile) = profile {
        let id = profile.id.clone();
        let name_box = {
            let id = id.clone();
            text_box(&profile.name)
                .header("名称")
                .placeholder_text("配置方案名称")
                .on_text_changed(move |t: String| {
                    let name = t.trim().to_string();
                    if name.is_empty() {
                        return;
                    }
                    let mut catalog = ProfilesFile::load();
                    // Names are unique case-insensitively — menus keyed by name are ambiguous
                    // otherwise. A collision simply doesn't commit; the box keeps what was typed.
                    if catalog.name_taken(&name, Some(&id)) {
                        return;
                    }
                    if let Some(p) = catalog.profiles.iter_mut().find(|p| p.id == id) {
                        p.name = name;
                        let _ = catalog.save();
                    }
                })
        };
        rows.push(name_box.into());
        rows.push(colour_swatches(profile, rev, set_rev));
    }
    rows.push(
        text_block(
            "配置方案只覆盖你在选中它时修改的项；其余都遵循默认设置。\
             重命名即时生效。删除后，使用它的主机将回退到默认设置。",
        )
        .font_size(12.0)
        .wrap()
        .foreground(ThemeRef::SecondaryText)
        .into(),
    );
    let mut buttons: Vec<Element> = Vec::new();
    if let Some(p) = profile {
        let id = p.id.clone();
        buttons.push(
            {
                let (id, set_scope) = (id.clone(), set_scope.clone());
                button("创建副本").icon(Symbol::Copy).on_click(move || {
                    let mut catalog = ProfilesFile::load();
                    let Some(source) = catalog.find_by_id(&id).cloned() else {
                        return;
                    };
                    let name = (2..)
                        .map(|n| format!("{} {n}", source.name))
                        .find(|n| !catalog.name_taken(n, None))
                        .unwrap_or_else(|| source.name.clone());
                    let mut copy = StreamProfile::new(name);
                    copy.overrides = source.overrides.clone();
                    copy.accent = source.accent.clone();
                    let new_id = copy.id.clone();
                    catalog.profiles.push(copy);
                    if catalog.save().is_ok() {
                        // The sheet stays open and now edits the copy — scope follows it.
                        set_scope.call(new_id);
                    }
                })
            }
            .into(),
        );
        buttons.push(
            {
                let set_delete = set_delete.clone();
                button("删除\u{2026}")
                    .icon(Symbol::Delete)
                    .on_click(move || set_delete.call(Some(id.clone())))
            }
            .into(),
        );
    }
    // "Save", not "Close": every field in the sheet commits as you type, so this is really
    // "done" — but the review is right that a sheet full of edits wants a verb, and Save
    // is the promise the button already keeps.
    let close_sheet = {
        let (set_edit, set_rev) = (set_edit.clone(), set_rev.clone());
        move || {
            set_edit.call(false);
            // The deferred repaint: the bar dropdown (and any pinned tiles) pick up the
            // rename now, in one pass, instead of remounting per keystroke.
            set_rev.call(rev + 1);
        }
    };
    buttons.push(
        {
            let close_sheet = close_sheet.clone();
            button("保存")
                .accent()
                .icon(Symbol::Save)
                .on_click(close_sheet)
        }
        .into(),
    );
    rows.push(
        hstack(buttons)
            .spacing(8.0)
            .horizontal_alignment(HorizontalAlignment::Right)
            .margin(edges(0.0, 6.0, 0.0, 0.0))
            .into(),
    );
    // The content scrolls when the window is shorter than the sheet (same rule as the host
    // editor) — a sheet must never clip its own controls.
    // A tap INSIDE the card bubbles up to the scrim (WinUI bubbles `Tapped`; reactor can't
    // mark it handled), so the card raises this flag first and the scrim's handler swallows
    // exactly that tap — a tap on the scrim itself, and Escape, dismiss the sheet.
    let inside_tap = std::rc::Rc::new(std::cell::Cell::new(false));
    let modal = dialog_surface(scroll_view(vstack(rows).spacing(12.0)))
        .on_tapped({
            let inside_tap = inside_tap.clone();
            move || inside_tap.set(true)
        })
        .max_width(420.0)
        .horizontal_alignment(HorizontalAlignment::Center)
        .vertical_alignment(VerticalAlignment::Center)
        .margin(uniform(24.0));
    let scrim_close = close_sheet.clone();
    let esc_close = close_sheet;
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
                scrim_close();
            }),
    )
    .keyboard_accelerator(KeyboardAccelerator::new(
        VirtualKey::Escape,
        VirtualKeyModifiers::None,
        esc_close,
    ))
}

/// Persist one control's edit into the layer being edited.
///
/// This shell commits PER CONTROL (unlike the GTK one, which writes when its dialog closes),
/// so it can't hand the profile a list of touched fields. It hands over the effective settings
/// before and after instead, and [`SettingsOverlay::absorb`] records the field that moved —
/// the comparison is against what the control was SHOWING, so picking a value that happens to
/// equal the global still records an override (the pin the design asks for).
///
/// Every commit ends by bumping the revision: a profile-scope edit changes what the page
/// should SHOW (the row's Overridden marker, the catalog behind the controls) without
/// changing any state the page reads, so without the bump no render pass runs and the
/// marker only appears after some unrelated re-render — the exact bug the Linux client
/// fixed in "the override marker appears on touch". Bumping on global-scope edits too is
/// deliberate: it is one code path, a same-value repaint is cheap, and it also refreshes
/// rows whose displayed effective value derives from the field just written.
fn commit(
    ctx: &Arc<AppCtx>,
    scope: &str,
    rev: (u64, &AsyncSetState<u64>),
    edit: impl FnOnce(&mut Settings),
) {
    if scope.is_empty() {
        // Rebase on the file before the whole-struct save: the process-lifetime snapshot
        // in `ctx.settings` is not the only writer — a spawned session persists its
        // match-window size, the console's own settings screen saves too — and saving the
        // stale snapshot would silently revert whatever they stored (the same
        // load-modify-save family as the GTK dialog's 2026-07-31 fix; profiles.rs
        // documents why there's no merge). The edit lands on the fresh load, and the
        // snapshot follows so every row keeps rendering what's on disk.
        let mut s = ctx.settings.lock().unwrap();
        *s = Settings::load();
        edit(&mut s);
        s.save();
        rev.1.call(rev.0 + 1);
        return;
    }
    let mut catalog = ProfilesFile::load();
    // The same rebase as the global arm above: `base` is what `absorb`'s before/after
    // effective settings derive from, and the snapshot is not the file — another process
    // (session resize, console UI, Decky) may have moved a global under us. The historical
    // rebase fix ("settings saves stop reverting each other") covered the whole-file
    // writers but missed this arm.
    let base = {
        let mut s = ctx.settings.lock().unwrap();
        *s = Settings::load();
        s.clone()
    };
    let Some(p) = catalog.profiles.iter_mut().find(|p| p.id == scope) else {
        return; // deleted from under us; the next render falls back to the defaults scope
    };
    let before = p.overrides.apply(&base);
    let mut after = before.clone();
    edit(&mut after);
    p.overrides.absorb(&before, &after);
    if let Err(e) = catalog.save() {
        tracing::warn!(error = %format!("{e:#}"), "saving the profile catalog");
    }
    rev.1.call(rev.0 + 1);
}

/// Re-base the process-lifetime settings snapshot on the file — called from the navigation
/// handlers that (re)enter this page, NOT per render pass. `ctx.settings` is loaded once at
/// process start and this process is not the file's only writer (a spawned session persists
/// its match-window size, the console UI and Decky save too — profiles.rs documents the
/// family), so without this the page opens showing values another process already replaced,
/// which then visibly "jump" the moment a row is touched and `commit`'s rebase pulls the
/// file in. The field report this fixes: a codec setting that "changed by itself".
pub(crate) fn refresh_snapshot(ctx: &Arc<AppCtx>) {
    *ctx.settings.lock().unwrap() = Settings::load();
}

/// Which tier-P rows the profile in scope overrides. Plain bools rather than a lookup so the
/// call sites read as `over.codec` — the row and its flag stay visibly paired.
#[derive(Default)]
struct OverrideFlags {
    resolution: bool,
    refresh_hz: bool,
    render_scale: bool,
    bitrate_kbps: bool,
    codec: bool,
    hdr_enabled: bool,
    enable_444: bool,
    compositor: bool,
    audio_channels: bool,
    mic_enabled: bool,
    echo_cancel: bool,
    touch_mode: bool,
    mouse_mode: bool,
    invert_scroll: bool,
    inhibit_shortcuts: bool,
    gamepad: bool,
    gamepad_forwarding: bool,
    system_buttons: bool,
    guide_gesture: bool,
    stats_verbosity: bool,
    fullscreen_on_stream: bool,
    present_priority: bool,
    smooth_buffer: bool,
    vsync: bool,
    allow_vrr: bool,
}

impl OverrideFlags {
    fn of(profile: Option<&StreamProfile>) -> OverrideFlags {
        let Some(o) = profile.map(|p| &p.overrides) else {
            return OverrideFlags::default();
        };
        OverrideFlags {
            // One control drives the width/height/match-window tri-state, so any of the three
            // marks the row.
            resolution: o.width.is_some() || o.height.is_some() || o.match_window.is_some(),
            refresh_hz: o.refresh_hz.is_some(),
            render_scale: o.render_scale.is_some(),
            bitrate_kbps: o.bitrate_kbps.is_some(),
            codec: o.codec.is_some(),
            hdr_enabled: o.hdr_enabled.is_some(),
            enable_444: o.enable_444.is_some(),
            compositor: o.compositor.is_some(),
            audio_channels: o.audio_channels.is_some(),
            mic_enabled: o.mic_enabled.is_some(),
            echo_cancel: o.echo_cancel.is_some(),
            touch_mode: o.touch_mode.is_some(),
            mouse_mode: o.mouse_mode.is_some(),
            invert_scroll: o.invert_scroll.is_some(),
            inhibit_shortcuts: o.inhibit_shortcuts.is_some(),
            gamepad: o.gamepad.is_some(),
            gamepad_forwarding: o.gamepad_forwarding.is_some(),
            system_buttons: o.system_buttons.is_some(),
            guide_gesture: o.guide_gesture.is_some(),
            stats_verbosity: o.stats_verbosity.is_some(),
            fullscreen_on_stream: o.fullscreen_on_stream.is_some(),
            present_priority: o.present_priority.is_some(),
            smooth_buffer: o.smooth_buffer.is_some(),
            vsync: o.vsync.is_some(),
            allow_vrr: o.allow_vrr.is_some(),
        }
    }
}

/// The layer the settings screen is editing, resolved for display: `None` = the defaults.
fn active_profile(scope: &str) -> Option<StreamProfile> {
    (!scope.is_empty())
        .then(|| ProfilesFile::load().find_by_id(scope).cloned())
        .flatten()
}

// NOTE: the row builders no longer set the widget's own `.header` — the row label is
// rendered by [`described_overridable`]/[`described_labeled`], because the Overridden pill
// must sit BETWEEN the label and the input, and a widget-embedded header allows nothing
// between itself and its box.
fn setting_combo(
    ctx: &Arc<AppCtx>,
    scope: &str,
    rev: (u64, &AsyncSetState<u64>),
    names: Vec<String>,
    current: usize,
    apply: impl Fn(&mut Settings, usize) + 'static,
) -> ComboBox {
    let (ctx, scope) = (ctx.clone(), scope.to_string());
    let (rev, set_rev) = (rev.0, rev.1.clone());
    let max = names.len().saturating_sub(1);
    ComboBox::new(names)
        .selected_index(current as i32)
        .on_selection_changed(move |i: i32| {
            commit(&ctx, &scope, (rev, &set_rev), |s| {
                apply(s, (i.max(0) as usize).min(max));
            });
        })
}

/// The labels of a `(value, label)` preset table, plus the index of `is_current`'s match.
fn presets<V>(table: &[(V, &str)], is_current: impl Fn(&V) -> bool) -> (Vec<String>, usize) {
    let names = table.iter().map(|(_, l)| l.to_string()).collect();
    let current = table.iter().position(|(v, _)| is_current(v)).unwrap_or(0);
    (names, current)
}

/// A `ToggleSwitch` bound to one boolean settings field (label rendered by the row — see
/// [`setting_combo`]'s note).
fn setting_toggle(
    ctx: &Arc<AppCtx>,
    scope: &str,
    rev: (u64, &AsyncSetState<u64>),
    on: bool,
    apply: impl Fn(&mut Settings, bool) + 'static,
) -> ToggleSwitch {
    let (ctx, scope) = (ctx.clone(), scope.to_string());
    let (rev, set_rev) = (rev.0, rev.1.clone());
    ToggleSwitch::new(on)
        .on_content("开")
        .off_content("关")
        .on_toggled(move |v: bool| {
            commit(&ctx, &scope, (rev, &set_rev), |s| apply(s, v));
        })
}

/// One field: the control with its explanation directly underneath (Apple's `described`).
///
/// The caption goes BELOW the control on purpose. An earlier revision put guidance only in
/// hover tooltips because a paragraph *above* a control reads as that control's label — true,
/// but a caption under it reads as a caption, which is how every Windows Settings page and
/// the Apple client both do it. Width-capped for the same reason Apple caps at 360pt: a
/// full-width caption runs into the control column and the whole cell reads as one block.
/// [`described_labeled`], plus the override marker and reset a profile-scope row carries: the caption
/// says the profile changes this one, and the button is the only way back to inheriting.
/// An override is recorded when a control's committed value differs from what it was
/// SHOWING (`SettingsOverlay::absorb` diffs against the effective snapshot — see `commit`);
/// WinUI change events don't fire on a no-op re-selection, so every reachable edit marks
/// its row, and "not overridden" needs an explicit Reset. (Linux marks a literal no-op
/// touch too — unobservable here, the one intentional divergence.)
fn described_overridable(
    rev: (u64, &AsyncSetState<u64>),
    scope: &str,
    field: &'static str,
    label: &str,
    overridden: bool,
    control: impl Into<Element>,
    caption: &str,
) -> Element {
    if scope.is_empty() || !overridden {
        return described_labeled(label, control, caption);
    }
    // The override marker is ONE capsule on its own line BETWEEN the control and its
    // caption (the reviewed placement): left-aligned like everything else in the card, so
    // every row's marker sits identically no matter how wide its control is. The capsule
    // holds the state ("Overridden") and the way out ("Reset") as segments of a single
    // tinted pill, the whole of which is the tap target; the caption below stays a plain
    // description in both states.
    let (rev, set_rev) = (rev.0, rev.1.clone());
    let scope = scope.to_string();
    let reset_pill = border(
        hstack((
            text_block("已被覆盖")
                .font_size(11.0)
                .semibold()
                .foreground(ThemeRef::SystemAttention)
                .vertical_alignment(VerticalAlignment::Center),
            // The seam between the state and the action.
            border(vstack(Vec::<Element>::new()).width(1.0).height(12.0))
                .background(ThemeRef::CardStroke)
                .vertical_alignment(VerticalAlignment::Center),
            text_block("重置")
                .font_size(11.0)
                .semibold()
                .foreground(ThemeRef::AccentText)
                .vertical_alignment(VerticalAlignment::Center),
        ))
        .spacing(7.0),
    )
    .background(ThemeRef::SystemAttentionBackground)
    .border_brush(ThemeRef::CardStroke)
    .border_thickness(uniform(1.0))
    .corner_radius(10.0)
    .padding(edges(10.0, 3.0, 10.0, 3.0))
    .tooltip("此项已被当前配置方案覆盖\u{2014}\u{2014}点击可重置为默认设置")
    .on_tapped(move || {
        let mut catalog = ProfilesFile::load();
        if let Some(p) = catalog.profiles.iter_mut().find(|p| p.id == scope) {
            p.overrides.clear(field);
            if let Err(e) = catalog.save() {
                tracing::warn!(error = %format!("{e:#}"), "clearing an override");
            }
        }
        // The catalog changed behind the controls, and nothing the page reads as state
        // did — bump the revision so the row re-renders showing the inherited value.
        set_rev.call(rev + 1);
    });
    vstack((
        row_label(label),
        Element::from(reset_pill).horizontal_alignment(HorizontalAlignment::Left),
        control.into(),
        row_caption(caption),
    ))
    .spacing(6.0)
    .into()
}

/// The row's label line — what the widgets' `.header` used to render, moved out so the
/// Overridden pill can sit between label and input with ONE consistent gap everywhere.
fn row_label(label: &str) -> Element {
    text_block(label)
        .horizontal_alignment(HorizontalAlignment::Left)
        .into()
}

/// The row's caption line (shared styling for every variant).
fn row_caption(caption: &str) -> Element {
    text_block(caption)
        .font_size(12.0)
        .foreground(ThemeRef::SecondaryText)
        .wrap()
        .max_width(420.0)
        .horizontal_alignment(HorizontalAlignment::Left)
        .into()
}

/// The plain row with the row-owned label line: label, input, caption — the same skeleton
/// as an overridable row minus the pill, so both kinds space out identically.
fn described_labeled(label: &str, control: impl Into<Element>, caption: &str) -> Element {
    vstack((row_label(label), control.into(), row_caption(caption)))
        .spacing(6.0)
        .into()
}

/// A settings sub-section heading. Deliberately NOT the shared [`section`] helper: that one
/// carries a 2px left inset (fine over the hosts/licenses lists it was written for), which
/// here left every heading hanging one nudge right of the card edge below it. Flush left, so
/// heading and card share one line.
fn group_heading(label: &str) -> Element {
    text_block(label)
        .font_size(12.0)
        .semibold()
        .foreground(ThemeRef::SecondaryText)
        .horizontal_alignment(HorizontalAlignment::Left)
        .margin(edges(0.0, 14.0, 0.0, 2.0))
        .into()
}

/// One settings group: an optional sub-section label, a card of fields, and an optional
/// form-level note under it (Apple's Section header/footer). Groups stack down the page.
/// A group with NO fields renders NOTHING — several groups pass an empty list in profile
/// scope (Decoding, Library: device facts, never per profile), and a heading over an empty
/// card read as a bug.
fn group(header: Option<&str>, fields: Vec<Element>, footer: Option<&str>) -> Vec<Element> {
    if fields.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(3);
    if let Some(h) = header {
        out.push(group_heading(h));
    }
    out.push(card(vstack(fields).spacing(14.0)).into());
    if let Some(f) = footer {
        out.push(
            text_block(f)
                .font_size(12.0)
                .foreground(ThemeRef::SecondaryText)
                .wrap()
                .horizontal_alignment(HorizontalAlignment::Left)
                .margin(edges(0.0, 6.0, 0.0, 0.0))
                .into(),
        );
    }
    out
}

/// The settings screen: a stock WinUI `NavigationView` (the Windows-Settings sidebar pattern) —
/// one pane item per section, the section's card as the content, the built-in back arrow
/// returning to the host list. `section`/`set_section` are the selected pane tag, held in ROOT
/// state (this page stays hook-free): `on_selection_changed` is wired in the reactor backend, so
/// only a root `AsyncSetState` reliably re-renders the new section in. `progress` is the
/// section-switch entrance tween (0 → 1), mapped onto the content column's opacity + offset.
#[allow(clippy::too_many_arguments)]
pub(crate) fn settings_page(
    ctx: &Arc<AppCtx>,
    set_screen: &AsyncSetState<Screen>,
    section: &str,
    set_section: &AsyncSetState<String>,
    scope_id: &str,
    set_scope: &AsyncSetState<String>,
    delete_pending: &Option<String>,
    set_delete: &AsyncSetState<Option<String>>,
    edit_open: bool,
    set_edit: &AsyncSetState<bool>,
    rev: u64,
    set_rev: &AsyncSetState<u64>,
    progress: f64,
) -> Element {
    // The layer being edited. A scope pointing at a deleted profile degrades to the defaults,
    // the same rule a dangling host binding follows.
    let active = active_profile(scope_id);
    let scope: &str = match &active {
        Some(p) => &p.id,
        None => "",
    };
    let profile_mode = active.is_some();
    // Which rows this profile overrides — the marker + reset each of them carries. In the
    // defaults scope nothing is marked, and `described_overridable` degrades to `described_labeled`.
    let over = OverrideFlags::of(active.as_ref());
    // Every control shows the EFFECTIVE value: the global underneath with this profile's
    // overrides on top, so a row the profile doesn't override reads as the live global.
    let s = {
        let base = ctx.settings.lock().unwrap().clone();
        match &active {
            Some(p) => p.overrides.apply(&base),
            None => base,
        }
    };

    // --- Display ---------------------------------------------------------------------------
    // The D1 tri-state: Native, Match window (a virtual index 1, stored as the
    // `match_window` flag), then the explicit sizes.
    let (res_names, res_i) = {
        let names: Vec<String> = std::iter::once("原生显示器".to_string())
            .chain(std::iter::once("匹配窗口".to_string()))
            .chain(
                RESOLUTIONS
                    .iter()
                    .skip(1)
                    .map(|&(w, h)| format!("{w} \u{00D7} {h}")),
            )
            .collect();
        let i = if s.match_window {
            1
        } else {
            RESOLUTIONS
                .iter()
                .position(|&(w, h)| w == s.width && h == s.height)
                .map(|i| if i == 0 { 0 } else { i + 1 })
                .unwrap_or(0)
        };
        (names, i)
    };
    let res_combo = setting_combo(ctx, scope, (rev, set_rev), res_names, res_i, |s, i| {
        s.match_window = i == 1;
        (s.width, s.height) = if i <= 1 { (0, 0) } else { RESOLUTIONS[i - 1] };
    });
    let (hz_names, hz_i) = {
        let names: Vec<String> = REFRESH
            .iter()
            .map(|&r| {
                if r == 0 {
                    "原生".into()
                } else {
                    format!("{r} Hz")
                }
            })
            .collect();
        let i = REFRESH.iter().position(|&r| r == s.refresh_hz).unwrap_or(0);
        (names, i)
    };
    let hz_combo = setting_combo(ctx, scope, (rev, set_rev), hz_names, hz_i, |s, i| {
        s.refresh_hz = REFRESH[i];
    });
    let (scale_names, scale_i) = {
        let names: Vec<String> = RENDER_SCALES
            .iter()
            .map(|&x| render_scale_label(x))
            .collect();
        let i = RENDER_SCALES
            .iter()
            .position(|&x| (x - s.render_scale).abs() < 1e-6)
            .unwrap_or_else(|| RENDER_SCALES.iter().position(|&x| x == 1.0).unwrap());
        (names, i)
    };
    let scale_combo = setting_combo(ctx, scope, (rev, set_rev), scale_names, scale_i, |s, i| {
        s.render_scale = RENDER_SCALES[i];
    });
    let (comp_names, comp_i) = presets(COMPOSITORS, |v| *v == s.compositor);
    let comp_combo = setting_combo(ctx, scope, (rev, set_rev), comp_names, comp_i, |s, i| {
        s.compositor = COMPOSITORS[i].0.to_string();
    });
    let auto_wake_toggle = setting_toggle(ctx, scope, (rev, set_rev), s.auto_wake, |s, on| {
        s.auto_wake = on
    });
    let fullscreen_toggle = setting_toggle(
        ctx,
        scope,
        (rev, set_rev),
        s.fullscreen_on_stream,
        |s, on| s.fullscreen_on_stream = on,
    );

    // --- Video -----------------------------------------------------------------------------
    // Migrated for the LOOKUP only (the store is left alone): a pre-M10 settings file
    // holds `vulkan`/`d3d11va`, which match no preset — the combo would show Automatic and
    // a save would silently rewrite the user's hardware preference to `auto`.
    let stored_decoder = pf_client_core::video::migrate_decoder_pref(&s.decoder);
    let (dec_names, dec_i) = presets(DECODERS, |v| *v == stored_decoder);
    let decoder_combo = setting_combo(ctx, scope, (rev, set_rev), dec_names, dec_i, |s, i| {
        s.decoder = DECODERS[i].0.to_string();
    });
    // GPU picker, only on a multi-GPU box (hybrid laptop, eGPU): which adapter decodes + presents.
    // Stored as the adapter description; empty = automatic (the window's monitor's adapter).
    let gpus = crate::gpu::adapter_names();
    let gpu_combo = (gpus.len() > 1).then(|| {
        let mut names = vec!["自动（显示器所用的 GPU）".to_string()];
        names.extend(gpus.iter().cloned());
        let current = gpus
            .iter()
            .position(|n| *n == s.adapter)
            .map_or(0, |i| i + 1);
        let gpus = gpus.clone();
        setting_combo(ctx, scope, (rev, set_rev), names, current, move |s, i| {
            s.adapter = if i == 0 {
                String::new()
            } else {
                gpus[i - 1].clone()
            };
        })
    });
    let (codec_names, codec_i) = presets(CODECS, |v| *v == s.codec);
    let codec_combo = setting_combo(ctx, scope, (rev, set_rev), codec_names, codec_i, |s, i| {
        s.codec = CODECS[i].0.to_string();
    });
    // Free-form Mb/s (0 = host default) instead of presets, so a speed-test recommendation
    // round-trips exactly. Through `commit` like every other row: writing `ctx.settings`
    // directly here would edit the GLOBAL defaults from inside a profile scope (and record
    // no override, so the row could never say "Overridden here").
    let bitrate_box = {
        let (ctx, scope, set_rev) = (ctx.clone(), scope.to_string(), set_rev.clone());
        NumberBox::new(f64::from(s.bitrate_kbps) / 1000.0)
            .range(0.0, 3000.0)
            .on_value_changed(move |v: f64| {
                commit(&ctx, &scope, (rev, &set_rev), |s| {
                    s.bitrate_kbps = (v.clamp(0.0, 3000.0) * 1000.0) as u32;
                });
            })
    };
    let hdr_toggle = setting_toggle(ctx, scope, (rev, set_rev), s.hdr_enabled, |s, on| {
        s.hdr_enabled = on
    });
    let chroma_toggle = setting_toggle(ctx, scope, (rev, set_rev), s.enable_444, |s, on| {
        s.enable_444 = on
    });
    // Presentation intent (design/desktop-presentation-rebuild.md). The buffer row is
    // rendered only under Smoothness — `commit` bumps the revision, so flipping the
    // intent re-renders the section and the row appears/disappears with it.
    let (present_names, present_i) = presets(PRESENT_PRIORITIES, |v| *v == s.present_priority);
    let present_combo = setting_combo(
        ctx,
        scope,
        (rev, set_rev),
        present_names,
        present_i,
        |s, i| s.present_priority = PRESENT_PRIORITIES[i].0.to_string(),
    );
    let smoothing = s.present_priority == "smooth";
    let (buffer_names, buffer_i) = presets(SMOOTH_BUFFERS, |v| *v == s.smooth_buffer);
    let buffer_combo = setting_combo(
        ctx,
        scope,
        (rev, set_rev),
        buffer_names,
        buffer_i,
        |s, i| s.smooth_buffer = SMOOTH_BUFFERS[i].0,
    );
    let vsync_toggle = setting_toggle(ctx, scope, (rev, set_rev), s.vsync, |s, on| s.vsync = on);
    let vrr_toggle = setting_toggle(ctx, scope, (rev, set_rev), s.allow_vrr, |s, on| {
        s.allow_vrr = on
    });

    // --- Input -----------------------------------------------------------------------------
    // Controller forwarding: Automatic forwards EVERY real controller, each as its own pad;
    // pinning one restricts the session to that single controller (single-player). Persisted
    // by stable key (`Settings::forward_pad`, GTK parity) so the pin survives restarts AND
    // reaches the spawned session binary, whose service applies the same key.
    let pads = ctx.gamepad.pads();
    let (fwd_names, fwd_i) = {
        let mut names = vec!["自动（所有手柄）".to_string()];
        names.extend(pads.iter().map(|p| {
            let kind = p.kind_label();
            if kind.is_empty() {
                p.name.clone()
            } else {
                format!("{} \u{00B7} {kind}", p.name)
            }
        }));
        let i = (!s.forward_pad.is_empty())
            .then(|| pads.iter().position(|p| p.key == s.forward_pad))
            .flatten()
            .map_or(0, |i| i + 1);
        (names, i)
    };
    let forward_combo = {
        let svc = ctx.gamepad.clone();
        let ctx2 = ctx.clone();
        let keys: Vec<String> = pads.iter().map(|p| p.key.clone()).collect();
        ComboBox::new(fwd_names)
            .selected_index(fwd_i as i32)
            .on_selection_changed(move |i: i32| {
                let sel = i.max(0) as usize;
                let key = if sel == 0 {
                    None
                } else {
                    keys.get(sel - 1).cloned()
                };
                // Apply live to the gamepad service and persist — the spawned session
                // reads `forward_pad` at connect. Rebase on the file first (the same
                // discipline as `commit()`): this handler bypasses commit and a stale
                // whole-struct save would revert other writers.
                svc.set_pinned(key.clone());
                let mut s = ctx2.settings.lock().unwrap();
                *s = Settings::load();
                s.forward_pad = key.unwrap_or_default();
                s.save();
            })
            // Dimmed with the master switch above it, like echo cancellation under the mic
            // (see that row) — this and the three below have nothing to act on while no
            // controller is forwarded at all. Every commit bumps `rev` and re-renders this
            // screen, so they follow the toggle live. Brings this client in line with how GTK
            // (`set_sensitive`), the touch settings on both mobile clients (`enabled`) and the
            // console UI (dim + refuse the step) have always drawn the same relationship.
            .enabled(s.gamepad_forwarding)
    };
    let pad_forward_toggle =
        setting_toggle(ctx, scope, (rev, set_rev), s.gamepad_forwarding, |s, on| {
            s.gamepad_forwarding = on
        });
    let (pad_names, pad_i) = presets(GAMEPADS, |v| {
        GamepadPref::from_name(v) == GamepadPref::from_name(&s.gamepad)
    });
    let pad_combo = setting_combo(ctx, scope, (rev, set_rev), pad_names, pad_i, |s, i| {
        s.gamepad = GAMEPADS[i].0.to_string();
    })
    .enabled(s.gamepad_forwarding);
    let (sysbtn_names, sysbtn_i) = presets(SYSTEM_BUTTONS, |v| *v == s.system_buttons);
    let sysbtn_combo = setting_combo(
        ctx,
        scope,
        (rev, set_rev),
        sysbtn_names,
        sysbtn_i,
        |s, i| {
            s.system_buttons = SYSTEM_BUTTONS[i].0.to_string();
        },
    )
    .enabled(s.gamepad_forwarding);
    let (gesture_names, gesture_i) = presets(GUIDE_GESTURES, |v| *v == s.guide_gesture);
    let gesture_combo = setting_combo(
        ctx,
        scope,
        (rev, set_rev),
        gesture_names,
        gesture_i,
        |s, i| {
            s.guide_gesture = GUIDE_GESTURES[i].0.to_string();
        },
    )
    .enabled(s.gamepad_forwarding);
    let (touch_names, touch_i) = presets(TOUCH_MODES, |v| *v == s.touch_mode);
    let touch_combo = setting_combo(ctx, scope, (rev, set_rev), touch_names, touch_i, |s, i| {
        s.touch_mode = TOUCH_MODES[i].0.to_string();
    });
    let (mouse_names, mouse_i) = presets(MOUSE_MODES, |v| *v == s.mouse_mode);
    let mouse_combo = setting_combo(ctx, scope, (rev, set_rev), mouse_names, mouse_i, |s, i| {
        s.mouse_mode = MOUSE_MODES[i].0.to_string();
    });
    let invert_scroll_toggle =
        setting_toggle(ctx, scope, (rev, set_rev), s.invert_scroll, |s, on| {
            s.invert_scroll = on
        });
    let shortcuts_toggle =
        setting_toggle(ctx, scope, (rev, set_rev), s.inhibit_shortcuts, |s, on| {
            s.inhibit_shortcuts = on
        });

    // --- Audio -----------------------------------------------------------------------------
    let (ac_names, ac_i) = presets(AUDIO_CHANNELS, |v| *v == s.audio_channels);
    let channels_combo = setting_combo(ctx, scope, (rev, set_rev), ac_names, ac_i, |s, i| {
        s.audio_channels = AUDIO_CHANNELS[i].0;
    });
    let mic_toggle = setting_toggle(ctx, scope, (rev, set_rev), s.mic_enabled, |s, on| {
        s.mic_enabled = on
    });
    // Endpoint pickers (the WASAPI probe — the GTK client's PipeWire twins): visible
    // labels are friendly names, the stored value is the endpoint id. Hidden when the
    // probe found at most the default; a saved device that's gone keeps a revertable
    // "(not detected)" entry, like the GPU row. Device facts — defaults scope only.
    let (speakers, mics) = pf_client_core::audio::devices().unwrap_or_default();
    let dev_combo = |saved: &str,
                     devs: &[pf_client_core::audio::AudioDevice],
                     apply: fn(&mut Settings, String)| {
        let mut names = vec!["系统默认".to_string()];
        let mut keys = vec![String::new()];
        for d in devs {
            names.push(d.description.clone());
            keys.push(d.name.clone());
        }
        if !saved.is_empty() && !keys.iter().any(|k| k == saved) {
            names.push(format!("{saved}（未检测到）"));
            keys.push(saved.to_string());
        }
        (keys.len() > 1).then(|| {
            let current = keys.iter().position(|k| k == saved).unwrap_or(0);
            setting_combo(ctx, scope, (rev, set_rev), names, current, move |s, i| {
                apply(s, keys[i.min(keys.len() - 1)].clone());
            })
        })
    };
    let speaker_combo = dev_combo(&s.speaker_device, &speakers, |s, v| s.speaker_device = v);
    let mic_dev_combo = dev_combo(&s.mic_device, &mics, |s, v| s.mic_device = v);
    // Echo cancellation is meaningless without an uplink, so it greys out with the mic above
    // it. Every commit bumps `rev` and re-renders this screen, so the two stay in step live.
    let echo_toggle = setting_toggle(ctx, scope, (rev, set_rev), s.echo_cancel, |s, on| {
        s.echo_cancel = on
    })
    .enabled(s.mic_enabled);

    let (hud_names, hud_i) = presets(STATS_TIERS, |v| *v == s.stats_verbosity());
    let hud_combo = setting_combo(ctx, scope, (rev, set_rev), hud_names, hud_i, |s, i| {
        s.set_stats_verbosity(STATS_TIERS[i].0);
    });

    let licenses_button = {
        let ss = set_screen.clone();
        button("第三方许可").on_click(move || ss.call(Screen::Licenses))
    };
    // The client log's home — the file every "check the client log" message means, which until
    // this row had no way in from the UI at all. The folder rather than the file so the rotated
    // `.old` generation is in reach too.
    //
    // `real_dir` (not the literal %LOCALAPPDATA% path) because Explorer lives outside our MSIX
    // container: handed a path the package redirection keeps from ever existing, it silently
    // opens the user's Documents folder instead of failing, which is precisely what this button
    // shipped doing. The `is_dir` guard keeps that fallback unreachable — if the resolve ever
    // comes back wrong, the click does nothing rather than landing somewhere misleading.
    // Best-effort otherwise, like the log itself: a failed spawn stays silent.
    let logs_button = button("打开日志文件夹").on_click(|| {
        if let Some(dir) = crate::logfile::real_dir().filter(|d| d.is_dir()) {
            let _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
        }
    });
    let library_toggle = setting_toggle(ctx, scope, (rev, set_rev), s.library_enabled, |s, on| {
        s.library_enabled = on
    });
    // App identity + version at the top of the About card (the WinUI Settings convention; the About
    // screen previously showed no version at all). CARGO_PKG_VERSION is the workspace version, baked
    // in at compile time.
    let about_identity = vstack((
        text_block("Punktfunk").font_size(20.0).semibold(),
        text_block(concat!("版本 ", env!("CARGO_PKG_VERSION")))
            .font_size(12.0)
            .foreground(ThemeRef::SecondaryText),
    ))
    .spacing(2.0);

    // The selected section's content, grouped exactly like the Apple client's categories
    // (SettingsCategory + SettingsView+Sections.swift). Each field's explanation sits under
    // it; the only form-level notes are the "applies from the next session" footers, matching
    // Apple's decision to keep exactly one of those per affected category.
    let (title, groups): (&str, Vec<Element>) = match section {
        "display" => {
            let mut out = group(
                Some("分辨率"),
                vec![
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "resolution",
                        "分辨率",
                        over.resolution,
                        res_combo,
                        "主机会以此精确尺寸驱动一个真实的虚拟输出\u{2014}\u{2014}真实像素，\
                         无缩放。\u{201C}原生显示器\u{201D}跟随此窗口所在的显示器；\
                         \u{201C}匹配窗口\u{201D}让画面在每次调整大小时都保持\
                         像素级精确（1:1）。",
                    ),
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "refresh_hz",
                        "刷新率",
                        over.refresh_hz,
                        hz_combo,
                        "\u{201C}原生\u{201D}在连接时解析为此显示器的刷新率。",
                    ),
                ],
                None,
            );
            out.extend(group(
                Some("画质"),
                vec![
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "render_scale",
                        "渲染比例",
                        over.render_scale,
                        scale_combo,
                        "高于原生比例可通过超采样提升锐度；低于则减轻主机与链路负担。\
                         本设备会将结果重采样到窗口大小。",
                    ),
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "bitrate_kbps",
                        "码率（Mb/s，0 = 自动）",
                        over.bitrate_kbps,
                        bitrate_box,
                        "设为 0 由主机决定（其默认值，并受主机能力限制）。\
                         主机卡片的右键菜单中有网络速度测试。",
                    ),
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "codec",
                        "视频编码器",
                        over.codec,
                        codec_combo,
                        "此为偏好设置\u{2014}\u{2014}主机无法编码时会自动回退。\
                         PyroWave 是面向有线链路的低延迟小波编码器：它用\
                         高码率（数百 Mb/s）换取近乎为零的解码时间，\
                         因此需要千兆以太网。",
                    ),
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "hdr_enabled",
                        "HDR (10-bit, BT.2020 PQ)",
                        over.hdr_enabled,
                        hdr_toggle,
                        "当主机有 HDR 内容且本显示器支持时启用 HDR10。\
                         仅支持 HEVC；否则串流保持 SDR。",
                    ),
                    // First sentence shared with the GTK client (its chroma_row); the
                    // constraint sentence names the real gate (host: PyroWave || NVENC) —
                    // "where the host can encode it" cost field users the discovery time.
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "enable_444",
                        "全色度（4:4:4）",
                        over.enable_444,
                        chroma_toggle,
                        "全彩色视频：小字与细线更清晰，但占用更多带宽。\
                         需要 NVIDIA 主机（NVENC）或 PyroWave 编码器\
                         \u{2014}\u{2014}其他编码器使用 4:2:0。",
                    ),
                ],
                None,
            ));
            // Decoder and GPU are facts about THIS device's hardware — never per profile.
            out.extend(group(
                Some("解码"),
                if profile_mode {
                    Vec::new()
                } else {
                    let mut fields = vec![described_labeled(
                        "视频解码器",
                        decoder_combo,
                        "自动会选择此 GPU 最擅长的硬件路径\u{2014}\u{2014}Intel 用\
                         Direct3D 11，NVIDIA 和 AMD 用 Vulkan Video\u{2014}\u{2014}并\
                         回退到 CPU。仅在调试时修改。",
                    )];
                    if let Some(c) = gpu_combo {
                        fields.push(described_labeled(
                            "GPU",
                            c,
                            "用哪块显卡解码并呈现串流。自动使用驱动此窗口\
                             显示器的 GPU。",
                        ));
                    }
                    fields
                },
                None,
            ));
            out.extend(group(
                Some("呈现"),
                {
                    let mut fields = vec![described_overridable(
                        (rev, set_rev),
                        scope,
                        "present_priority",
                        "优先策略",
                        over.present_priority,
                        present_combo,
                        "最低延迟会在显示器可接受的瞬间立即显示每一帧\
                         \u{2014}\u{2014}网络抖动会表现为偶尔重复或跳过的帧。\
                         流畅度则会稍作缓冲来抹平这些抖动。",
                    )];
                    if smoothing {
                        fields.push(described_overridable(
                            (rev, set_rev),
                            scope,
                            "smooth_buffer",
                            "流畅度缓冲",
                            over.smooth_buffer,
                            buffer_combo,
                            "显示前保留的帧数。每一帧可吸收约一次刷新周期的\
                             网络抖动，同时增加一次刷新周期的延迟。\
                             自动保留两帧。",
                        ));
                    }
                    fields.push(described_overridable(
                        (rev, set_rev),
                        scope,
                        "vsync",
                        "V-Sync",
                        over.vsync,
                        vsync_toggle,
                        "防撕裂。关闭可消除等待屏幕刷新的时间\u{2014}\u{2014}延迟\
                         最低，但会出现可见的画面撕裂。并非所有驱动都支持；\
                         统计浮层会显示实际使用的模式。",
                    ));
                    fields.push(described_overridable(
                        (rev, set_rev),
                        scope,
                        "allow_vrr",
                        "跟随可变刷新率",
                        over.allow_vrr,
                        vrr_toggle,
                        "在 VRR/FreeSync/G-Sync 屏幕上，让面板跟随串流节奏\
                         刷新，而非固定频率。仅对全屏会话生效；在固定\
                         刷新率屏幕上无副作用。",
                    ));
                    fields
                },
                None,
            ));
            out.extend(group(
                Some("主机输出"),
                vec![described_overridable(
                    (rev, set_rev),
                    scope,
                    "compositor",
                    "主机合成器",
                    over.compositor,
                    comp_combo,
                    "主机用于虚拟输出的后端（仅限 Linux 主机）。指定的\
                     后端不可用时回退到自动检测。",
                )],
                // The one form-level note, exactly as on Apple.
                Some("显示设置的更改将在下次会话时生效。"),
            ));
            ("显示", out)
        }
        "input" => {
            let mut out = group(
                Some("触摸与指针"),
                vec![described_overridable(
                    (rev, set_rev),
                    scope,
                    "touch_mode",
                    "触摸输入",
                    over.touch_mode,
                    touch_combo,
                    "触摸屏如何操控主机：触控板模式像笔记本触控板一样移动\
                     主机光标（点按即点击），直接指针模式将光标跳转到\
                     触摸位置，触摸透传模式发送真实多点触控。",
                )],
                None,
            );
            out.extend(group(
                Some("键盘与鼠标"),
                vec![
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "mouse_mode",
                        "鼠标输入",
                        over.mouse_mode,
                        mouse_combo,
                        "捕获模式将指针锁定在串流画面内并发送相对位移——\
                         适合游戏。桌面模式让指针自由进出串流画面并\
                         发送绝对坐标——适合远程桌面。\
                         Ctrl+Alt+Shift+M 可实时切换。",
                    ),
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "inhibit_shortcuts",
                        "捕获系统快捷键（Alt+Tab、Win 等）",
                        over.inhibit_shortcuts,
                        shortcuts_toggle,
                        "当串流捕获输入时，Alt+Tab、Windows 键等会发送到\
                         主机。关闭时，它们作用于本机。",
                    ),
                    described_overridable(
                        (rev, set_rev),
                        scope,
                        "invert_scroll",
                        "反转滚动方向",
                        over.invert_scroll,
                        invert_scroll_toggle,
                        "反转发送到主机的滚轮和触控板滚动方向。",
                    ),
                ],
                None,
            ));
            ("输入", out)
        }
        "controllers" => (
            "手柄",
            group(
                None,
                [
                    // The read-only pad inventory (GTK parity): what THIS device sees right
                    // now — the fastest answer to "is my controller even detected?". A
                    // device fact, so defaults scope only, like the forward picker below.
                    (!profile_mode).then(|| {
                        let inventory: Element = if pads.is_empty() {
                            text_block("未检测到手柄")
                                .font_size(12.0)
                                .foreground(ThemeRef::SecondaryText)
                                .into()
                        } else {
                            vstack(
                                pads.iter()
                                    .map(|p| {
                                        let sub = if p.steam_virtual {
                                            "Steam Input 的虚拟手柄\u{2014}\u{2014}连接了真实\
                                             手柄时自动模式会跳过它"
                                                .to_string()
                                        } else {
                                            p.kind_label().to_string()
                                        };
                                        vstack((
                                            text_block(p.name.clone()).semibold(),
                                            text_block(sub)
                                                .font_size(11.0)
                                                .foreground(ThemeRef::SecondaryText),
                                        ))
                                        .spacing(1.0)
                                        .into()
                                    })
                                    .collect::<Vec<Element>>(),
                            )
                            .spacing(8.0)
                            .into()
                        };
                        described_labeled(
                            "已检测到的手柄",
                            inventory,
                            "插入手柄或配对手柄后会显示在这里。",
                        )
                    }),
                    // Whether ANY controller is forwarded — profileable, so it renders in
                    // both scopes (a "Work" profile can decline what "Game" forwards),
                    // unlike the device-fact picker below it.
                    Some(described_overridable(
                        (rev, set_rev),
                        scope,
                        "gamepad_forwarding",
                        "转发手柄",
                        over.gamepad_forwarding,
                        pad_forward_toggle,
                        "将连接到本 PC 的手柄发送到主机。如果你的手柄已通过\
                         其他方式到达主机\u{2014}\u{2014}例如 VirtualHere 等 USB\
                         透传工具，或直接插在主机上\u{2014}\u{2014}请关闭此项，\
                         避免游戏检测到两个手柄。关闭后，本 PC 完全不会\
                         打开手柄，透传工具才能独占它。",
                    )),
                    // NOT Apple's wording: Apple forwards ONE pad as player 1, this client
                    // forwards every controller as its own player. Same picker, different rule.
                    // Which physical pad this device forwards is a device fact (tier G), so it
                    // renders only in the defaults scope; the EMULATED type below is profileable.
                    (!profile_mode).then(|| {
                        described_labeled(
                        "转发的手柄",
                        forward_combo,
                        "默认转发所有已连接的手柄，各为独立玩家。选定一个\
                         则强制单人模式\u{2014}\u{2014}只有它会到达主机。",
                    )
                    }),
                    Some(described_overridable(
                        (rev, set_rev),
                        scope,
                        "gamepad",
                        "手柄类型",
                        over.gamepad,
                        pad_combo,
                        "在主机上创建的虚拟手柄。自动模式匹配你的手柄\
                         \u{2014}\u{2014}DualSense 会保留自适应扳机、灯条、\
                         触控板和体感。",
                    )),
                    Some(described_overridable(
                        (rev, set_rev),
                        scope,
                        "system_buttons",
                        "Steam / 导航键",
                        over.system_buttons,
                        sysbtn_combo,
                        "串流时导航键（Xbox/PS）和快捷菜单按键的去向。\
                         自动模式发送到主机\u{2014}\u{2014}除非设备自身的浮层\
                         响应同一按键（游戏模式），此时按键留在本机，\
                         由下方手势转发到主机。",
                    )),
                    Some(described_overridable(
                        (rev, set_rev),
                        scope,
                        "guide_gesture",
                        "长按 Select 触发导航键",
                        over.guide_gesture,
                        gesture_combo,
                        "单独长按 Select 可按下主机的导航键\u{2014}\u{2014}持续\
                         按住则打开游戏模式主机的快捷菜单。点按 Select\
                         仍会生效，只是稍有延迟。自动模式仅在真实\
                         按键无法到达主机时启用此手势。",
                    )),
                ]
                .into_iter()
                .flatten()
                .collect(),
                Some("将在下次会话时生效。"),
            ),
        ),
        "audio" => (
            "音频",
            group(
                None,
                [
                    Some(described_overridable(
                        (rev, set_rev),
                        scope,
                        "audio_channels",
                        "音频声道",
                        over.audio_channels,
                        channels_combo,
                        "向主机请求的扬声器布局。主机自身输出声道较少时\
                         会自动混音降级。",
                    )),
                    // The endpoint picks are facts about THIS device's hardware — never
                    // per profile, like Decoder/GPU.
                    (!profile_mode)
                        .then(|| {
                            speaker_combo.map(|c| {
                                described_labeled(
                                    "扬声器",
                                    c,
                                    "主机音频在此播放\u{2014}\u{2014}系统默认跟随\
                                     Windows 输出设备。",
                                )
                            })
                        })
                        .flatten(),
                    Some(described_overridable(
                        (rev, set_rev),
                        scope,
                        "mic_enabled",
                        "将麦克风串流到主机",
                        over.mic_enabled,
                        mic_toggle,
                        "本设备的麦克风将输入到主机的虚拟麦克风。\
                         串流时按 Ctrl+Alt+Shift+V 可静音/取消静音。",
                    )),
                    (!profile_mode)
                        .then(|| {
                            mic_dev_combo.map(|c| {
                                described_labeled(
                                    "麦克风",
                                    c,
                                    "为主机虚拟麦克风提供音频的输入设备。",
                                )
                            })
                        })
                        .flatten(),
                    Some(described_overridable(
                        (rev, set_rev),
                        scope,
                        "echo_cancel",
                        "回声消除",
                        over.echo_cancel,
                        echo_toggle,
                        "防止本机扬声器播放的主机音频被麦克风拾取并\
                         回传。如果你的麦克风自带处理功能，\
                         可关闭此项。",
                    )),
                ]
                .into_iter()
                .flatten()
                .collect(),
                Some("将在下次会话时生效。"),
            ),
        ),
        "about" => (
            "关于",
            group(
                None,
                vec![
                    about_identity.into(),
                    described_labeled(
                        "诊断",
                        logs_button,
                        "客户端日志（client.log，以及会话的完整接收/解码/\
                         呈现记录）\u{2014}\u{2014}提交问题时请附上它。",
                    ),
                    licenses_button.into(),
                ],
                None,
            ),
        ),
        // "general" and anything unrecognized.
        _ => {
            let mut out = group(
                Some("会话"),
                vec![described_overridable(
                    (rev, set_rev),
                    scope,
                    "fullscreen_on_stream",
                    "全屏开始串流",
                    over.fullscreen_on_stream,
                    fullscreen_toggle,
                    "会话开始时进入全屏；F11 或 Alt+Enter 可随时切回。",
                )]
                .into_iter()
                // Auto-wake is about this host and this network, not about "Game vs Work" —
                // it stays global in v1 (design §3, tier H/G).
                .chain((!profile_mode).then(|| {
                    described_labeled(
                        "连接时自动唤醒",
                        auto_wake_toggle,
                        "连接到离线的已保存主机时，自动发送网络唤醒并\
                         等待其启动。如果 VPN 后的主机误显示为离线，\
                         可关闭此项。",
                    )
                }))
                .collect(),
                None,
            );
            out.extend(group(
                Some("统计"),
                vec![described_overridable(
                    (rev, set_rev),
                    scope,
                    "stats_verbosity",
                    "统计浮层（HUD）",
                    over.stats_verbosity,
                    hud_combo,
                    "在角落浮层中显示实时会话统计\u{2014}\u{2014}紧凑模式为\
                     单行胶囊，详细模式增加延迟分阶段明细。随时按\
                     Ctrl+Alt+Shift+S 循环切换。",
                )],
                None,
            ));
            // The library browser is an app-level toggle for this device, not a per-profile one.
            out.extend(group(
                Some("游戏库"),
                if profile_mode {
                    Vec::new()
                } else {
                    vec![described_labeled(
                    "显示游戏库（实验性）",
                    library_toggle,
                    "为已配对主机添加\u{201C}浏览游戏库\u{2026}\u{201D}\u{2014}\u{2014}列出\
                     其 Steam 和自定义游戏并直接启动。主机无需额外设置。",
                )]
                },
                None,
            ));
            ("常规", out)
        }
    };

    // The stock WinUI sidebar (Windows-Settings pattern): pane on the left, the section's card
    // as content, the NavigationView's own back arrow returning to the host list. Auto display
    // mode collapses the pane on a narrow window, exactly like Windows Settings.
    // Category order mirrors the Apple client's sidebar exactly.
    let items = vec![
        NavViewItem::new("常规")
            .tag("general")
            .icon(Symbol::Setting),
        NavViewItem::new("显示")
            .tag("display")
            .icon(Symbol::FullScreen),
        NavViewItem::new("输入")
            .tag("input")
            .icon(Symbol::Keyboard),
        NavViewItem::new("音频").tag("audio").icon(Symbol::Volume),
        NavViewItem::new("手柄")
            .tag("controllers")
            .icon(Symbol::Play),
        NavViewItem::new("关于").tag("about").icon(Symbol::Help),
    ];
    // The card is KEYED by section so switching panes REMOUNTS it instead of diffing one
    // section's controls into another's: an in-place diff re-sets a reused ComboBox's items
    // (which clears WinUI's selection) but skips `selected_index` whenever the two sections'
    // values compare equal — the combo then renders with no selected option. A fresh mount
    // applies every prop, so the selection always displays.
    //
    // The content column (not the NavigationView — the sidebar must stay put) carries the
    // section-switch entrance: fade + slide-up from the root-driven tween.
    // No max-width cap here (unlike the other pages): the NavigationView already spends the
    // left third on its pane, so a 640-wide column left the cards as a narrow ribbon.
    // The category title is rendered HERE, not via NavigationView's Header: that header's
    // left inset belongs to WinUI's own template (a string prop is all we can set), so it
    // sat noticeably right of the cards under it. In the content column it shares the cards'
    // left edge by construction.
    // The scope switcher is a slim BAR ABOVE the whole NavigationView — visible from every
    // section, at every window size, in every pane state — and the switcher itself is ONE
    // native control: a DropDownButton whose label is the scope in play and whose menu
    // holds the choices, "New profile…", and "Edit …". Faking a fused combo+pencil out of
    // separate controls looked exactly like what it was (the toolkit exposes no per-corner
    // radius to build a real input group, though WinUI itself has one) — the native
    // dropdown IS the coherent element, with one hover state and no seams. It also retires
    // the ComboBox items/selected_index remount hazard: a button label is one plain prop.
    let catalog = ProfilesFile::load();
    let scope_pairs: Vec<(String, String)> = catalog
        .profiles
        .iter()
        .map(|p| (p.id.clone(), p.name.clone()))
        .collect();
    const SCOPE_DEFAULT: &str = "默认设置";
    const SCOPE_NEW: &str = "新建配置方案\u{2026}";
    // The Edit entry's prefix — the suffix is the profile's display name.
    const SCOPE_EDIT: &str = "编辑 \u{201c}";
    let scope_bar: Element = {
        let scope_label = match &active {
            Some(p) => p.name.clone(),
            None => SCOPE_DEFAULT.to_string(),
        };
        let switcher = {
            let (set_scope, set_edit) = (set_scope.clone(), set_edit.clone());
            let pairs = scope_pairs.clone();
            let mut items = vec![menu_item(SCOPE_DEFAULT)];
            for (_, name) in &pairs {
                items.push(menu_item(name.clone()));
            }
            items.push(menu_separator());
            items.push(menu_item(SCOPE_NEW));
            if let Some(p) = &active {
                items.push(menu_item(format!("{SCOPE_EDIT}{}\u{201d}\u{2026}", p.name)));
            }
            drop_down_button(&scope_label)
                .menu_flyout(items)
                .on_item_clicked(move |item: String| {
                    // Fixed entries first — a profile could share their text.
                    if item == SCOPE_NEW {
                        // A new profile takes an auto-numbered name and lands straight in
                        // the sheet to be named — creation and naming are one gesture, and
                        // there is no half-created state a Cancel would have to unwind.
                        let mut catalog = ProfilesFile::load();
                        let name = (1..)
                            .map(|n| format!("配置方案 {n}"))
                            .find(|n| !catalog.name_taken(n, None))
                            .unwrap_or_else(|| "配置方案".to_string());
                        let profile = StreamProfile::new(name);
                        let new_id = profile.id.clone();
                        catalog.profiles.push(profile);
                        if catalog.save().is_ok() {
                            set_scope.call(new_id);
                            set_edit.call(true);
                        }
                        return;
                    }
                    if item.starts_with(SCOPE_EDIT) {
                        set_edit.call(true);
                        return;
                    }
                    if item == SCOPE_DEFAULT {
                        set_scope.call(String::new());
                        return;
                    }
                    if let Some((id, _)) = pairs.iter().find(|(_, n)| n == &item) {
                        set_scope.call(id.clone());
                    }
                })
        };
        let mut row: Vec<Element> = vec![text_block("正在编辑")
            .font_size(13.0)
            .foreground(ThemeRef::SecondaryText)
            .vertical_alignment(VerticalAlignment::Center)
            .into()];
        // The profile's colour, right where the choice is made (menu items are plain
        // strings in this toolkit, so the chip cannot ride inside the menu).
        if let Some(c) = active
            .as_ref()
            .and_then(|p| p.accent.as_deref())
            .and_then(hex_color)
        {
            row.push(
                border(vstack(Vec::<Element>::new()))
                    .width(12.0)
                    .height(12.0)
                    .background(c)
                    .corner_radius(6.0)
                    .vertical_alignment(VerticalAlignment::Center)
                    .into(),
            );
        }
        row.push(Element::from(switcher).vertical_alignment(VerticalAlignment::Center));
        hstack(row)
            .spacing(12.0)
            .margin(edges(24.0, 12.0, 28.0, 8.0))
            .into()
    };

    let titled: Vec<Element> = std::iter::once(
        text_block(title)
            .font_size(28.0)
            .semibold()
            .horizontal_alignment(HorizontalAlignment::Left)
            .margin(edges(0.0, 0.0, 0.0, 6.0))
            .into(),
    )
    .chain(groups)
    .collect();
    // The keyed column MUST sit inside a panel's child list, not directly under the
    // scroll_view: `ScrollView::children()` is `Children::PositionalSingle`, which
    // reconciles its one child POSITIONALLY and ignores keys outright. Keyed straight onto
    // the scroll_view's child, the section switch silently diffs one section's controls into
    // another's — which re-sets each reused ComboBox's items (clearing WinUI's selection)
    // but skips `selected_index` whenever the two sections' values compare equal, so the
    // combos render blank until touched. A panel (vstack) takes the keyed path, so the key
    // remounts the whole column and every prop is applied fresh.
    let scrolled = scroll_view(
        // ⚠️ Keyed on (scope, section), not section alone: switching SCOPE re-renders the same
        // section's controls with different values, and an in-place diff re-sets each reused
        // ComboBox's items (clearing WinUI's selection) while skipping `selected_index`
        // wherever the two scopes' values compare equal — the combo then renders blank. A
        // fresh mount applies every prop. Same reason the section key exists.
        vstack(vec![vstack(titled)
            .spacing(10.0)
            .with_key(format!("{scope}/{section}"))
            .into()])
        .margin(edges(24.0, 20.0, 28.0, 40.0)),
    )
    .opacity(progress)
    .margin(edges(0.0, (1.0 - progress) * 22.0, 0.0, 0.0));
    let content: Element = scrolled.into();
    // The delete confirmation. Declarative like every dialog in this shell — but ALWAYS
    // MOUNTED, with `is_open` doing the arming: a ContentDialog is a "phantom" child in the
    // reactor backend (tracked logically, never attached to the panel), and unmounting one
    // destroys its handle before `remove_child` runs, so the backend stops recognising it
    // as phantom and RemoveAt()s a visual child that does not exist — E_BOUNDS, main-thread
    // panic ("Daten außerhalb des gültigen Bereichs"), reliably on every delete. A mounted
    // dialog is never removed, so the bug has nothing to bite. (Upstream report material —
    // the third windows-reactor bug this client documents.)
    let confirm: Element = {
        let pending = delete_pending
            .as_ref()
            .and_then(|id| ProfilesFile::load().find_by_id(id).cloned());
        // The warning counts what actually breaks: hosts that fall back to the defaults,
        // and pinned cards that disappear (design §6).
        let body = pending
            .as_ref()
            .map(|p| {
                let known = KnownHosts::load();
                let bound = known
                    .hosts
                    .iter()
                    .filter(|h| h.profile_id.as_deref() == Some(p.id.as_str()))
                    .count();
                let pinned = known
                    .hosts
                    .iter()
                    .filter(|h| h.pinned_profiles.iter().any(|x| x == &p.id))
                    .count();
                let mut body = format!("\u{201c}{}\u{201d}将被移除。", p.name);
                if bound > 0 {
                    body.push_str(&format!(" {bound} 台主机将回退到默认设置。"));
                }
                if pinned > 0 {
                    body.push_str(&format!(" {pinned} 张固定卡片将消失。"));
                }
                body
            })
            .unwrap_or_default();
        let (id, set_scope, set_delete, set_edit) = (
            pending.as_ref().map(|p| p.id.clone()),
            set_scope.clone(),
            set_delete.clone(),
            set_edit.clone(),
        );
        ContentDialog::new("删除配置方案？")
            .content(body)
            .primary_button_text("删除")
            .close_button_text("取消")
            .is_open(pending.is_some())
            .on_closed(move |r: ContentDialogResult| {
                set_delete.call(None);
                if r != ContentDialogResult::Primary {
                    return;
                }
                let Some(id) = id.clone() else {
                    return;
                };
                let mut catalog = ProfilesFile::load();
                catalog.profiles.retain(|p| p.id != id);
                // Bindings and pins are left dangling on purpose: they resolve as "no
                // profile" everywhere, and rewriting every host record here would be a
                // second, racier source of truth.
                if catalog.save().is_ok() {
                    set_scope.call(String::new());
                    // The profile the sheet was showing is gone — without this, the
                    // still-armed flag would pop the sheet open on the NEXT profile pick.
                    set_edit.call(false);
                }
            })
            .into()
    };
    let nav = NavigationView::new(items, content)
        .pane_title("设置")
        .selected_tag(section)
        .on_selection_changed({
            let ss = set_section.clone();
            move |tag: String| ss.call(tag)
        })
        .settings_visible(false)
        .back_enabled(true)
        .on_back_requested({
            let ss = set_screen.clone();
            move || ss.call(Screen::Hosts)
        });
    // Overlay layers fill the NAV's cell (grids stretch children; a vstack would hand the
    // NavigationView its desired height — clipped short, floating tall). The layer list is
    // STABLE — always [nav, sheet slot, dialog] — so no pass ever removes a grid child:
    // removals are where the reconciler's phantom-dialog bookkeeping breaks (see `confirm`
    // above), and a closed sheet leaves a same-kind, background-less Border in its slot
    // (invisible, and per style.rs a null background is not hit-testable, so it swallows
    // no clicks).
    let sheet_slot: Element = if edit_open && profile_mode {
        // The profile sheet — "Edit profile…" in the bar. The bar owns the scope choice,
        // so the sheet carries only the profile being edited.
        edit_profile_modal(
            active.as_ref(),
            None,
            set_scope,
            set_delete,
            set_edit,
            rev,
            set_rev,
        )
    } else {
        border(vstack(Vec::<Element>::new())).into()
    };
    // Every save on this page is fire-and-forget by design — a failed settings write must
    // never take a stream down — so a client whose config store rejects writes looks entirely
    // normal: toggles move, profiles appear, and NOTHING survives a restart. That is exactly
    // how it reached us from the field ("it's in read-only mode"), with no log file to send
    // either. When the store is refusing writes, say so, name the path, and stop pretending.
    //
    // Same always-mounted-slot discipline as `sheet_slot`: one child in both states, and the
    // SAME KIND in both (a Border wrapping the bar, versus an empty background-less Border —
    // which per style.rs is not hit-testable, so it swallows no clicks). Neither a grid child
    // nor a vstack child is ever added or removed, which is where this reconciler's phantom
    // bookkeeping breaks.
    let store_slot: Element = match pf_client_core::trust::store_health::last_error() {
        Some(err) => border(
            InfoBar::new("你的更改不会被保存")
                .message(format!(
                    "Punktfunk 无法写入其设置文件夹，此页面上的任何更改在重启后\
                     都会丢失。{err}"
                ))
                .error()
                .is_closable(false),
        )
        .margin(edges(24.0, 12.0, 28.0, 0.0))
        .into(),
        None => border(vstack(Vec::<Element>::new())).into(),
    };
    // The bar rides an Auto row above the nav's Star row, so the nav (and the sheet's scrim
    // over it) still fills the rest of the window.
    grid(vec![
        Element::from(vstack(vec![store_slot, scope_bar])).grid_row(0),
        Element::from(grid(vec![nav.into(), sheet_slot, confirm])).grid_row(1),
    ])
    .rows([GridLength::Auto, GridLength::STAR])
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_client_core::profiles::SettingsOverlay;

    /// Every overlay field maps to its row flag — including the tri-state resolution
    /// (any of width/height/match_window marks the one Resolution row) and the 4:4:4
    /// switch added for GTK parity. A field that records without marking its row is the
    /// original Overridden-row bug wearing a new face.
    #[test]
    fn override_flags_mirror_the_overlay() {
        let none = OverrideFlags::of(None);
        assert!(!none.resolution && !none.enable_444 && !none.codec);

        let mut p = StreamProfile::new("t".to_string());
        p.overrides = SettingsOverlay {
            match_window: Some(true),
            enable_444: Some(true),
            codec: Some("hevc".into()),
            bitrate_kbps: Some(20000),
            ..Default::default()
        };
        let f = OverrideFlags::of(Some(&p));
        assert!(f.resolution, "match_window alone marks the Resolution row");
        assert!(f.enable_444);
        assert!(f.codec);
        assert!(f.bitrate_kbps);
        assert!(!f.hdr_enabled && !f.compositor && !f.render_scale);

        let mut p2 = StreamProfile::new("t2".to_string());
        p2.overrides = SettingsOverlay {
            width: Some(3840),
            height: Some(2160),
            ..Default::default()
        };
        assert!(OverrideFlags::of(Some(&p2)).resolution);

        // The audio pair: the mic and its echo canceller are separate overrides, so a profile
        // can pin one without claiming the other.
        let mut p3 = StreamProfile::new("t3".to_string());
        p3.overrides = SettingsOverlay {
            echo_cancel: Some(false),
            ..Default::default()
        };
        let f3 = OverrideFlags::of(Some(&p3));
        assert!(f3.echo_cancel);
        assert!(!f3.mic_enabled);

        // The presentation pair, likewise independent: pinning the intent doesn't claim
        // the buffer (a "Smoothness, whatever the global buffer is" profile is valid).
        let mut p4 = StreamProfile::new("t4".to_string());
        p4.overrides = SettingsOverlay {
            present_priority: Some("smooth".into()),
            ..Default::default()
        };
        let f4 = OverrideFlags::of(Some(&p4));
        assert!(f4.present_priority);
        assert!(!f4.smooth_buffer);

        // V-Sync and VRR are independent of each other and of the intent pair.
        let mut p5 = StreamProfile::new("t5".to_string());
        p5.overrides = SettingsOverlay {
            vsync: Some(false),
            ..Default::default()
        };
        let f5 = OverrideFlags::of(Some(&p5));
        assert!(f5.vsync);
        assert!(!f5.allow_vrr && !f5.present_priority);
    }
}
