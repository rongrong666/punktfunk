//! The stream status page: streams run in the spawned `punktfunk-session` child's own window,
//! so the shell shows a status card in the app's card language — host header, the child's live
//! `stats:` line as a chip row + stage lines, the in-window shortcuts, and a Disconnect.

use super::style::{edges, uniform};
use std::sync::Arc;
use windows_reactor::*;

/// One HUD refresh: the session child's latest formatted `stats:` line, mirrored into root state
/// by the poll thread (`pf-hud`) and passed down as a prop.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct HudSample {
    /// The session child's latest formatted `stats:` line, for the status page. Empty before the
    /// child's first stats window.
    pub(crate) stats_line: String,
}

/// Spawn mode's Stream screen: the stream runs in the punktfunk-session child's own
/// window, so the shell shows a status card in the app's card language — monogram +
/// host header, the child's live `stats:` line as a chip row + stage lines, the
/// in-window shortcuts, and a Disconnect that kills the child (its exit event routes
/// the app back to the host list, same as the child's window closing). No hooks.
pub(crate) fn session_page(ctx: &Arc<super::AppCtx>, hud: &HudSample) -> Element {
    use super::style::{avatar, card, pill, Pill};
    let host = ctx.shared.target.lock().unwrap().name.clone();
    let browse = ctx.shared.browse.load(std::sync::atomic::Ordering::SeqCst);
    let title = match (browse, host.is_empty()) {
        (true, true) => "控制台游戏库".to_string(),
        (true, false) => format!("控制台游戏库 \u{00B7} {host}"),
        (false, true) => "串流中".to_string(),
        (false, false) => format!("正在串流到 {host}"),
    };

    // Header: monogram + title + the one thing worth knowing (where the video went).
    let header: Element = grid((
        avatar(&host)
            .grid_column(0)
            .vertical_alignment(VerticalAlignment::Center),
        vstack((
            text_block(&title).font_size(18.0).semibold(),
            text_block(
                "串流有独立窗口\u{2014}\u{2014}会话结束后会回到此窗口。",
            )
            .font_size(12.0)
            .foreground(ThemeRef::SecondaryText),
        ))
        .spacing(2.0)
        .grid_column(1)
        .vertical_alignment(VerticalAlignment::Center)
        .margin(edges(12.0, 0.0, 0.0, 0.0)),
    ))
    .columns([GridLength::Auto, GridLength::Star(1.0)])
    .into();

    // The child prints one formatted stats line per 1 s window:
    // "<mode> · <fps> · <Mb/s> · <path> [· HDR] | e2e … | …" — the first segment becomes
    // a chip row (the decode path gets the status colour), the rest dim stage lines.
    let mut body: Vec<Element> = vec![header];
    if hud.stats_line.is_empty() {
        // The child prints `stats:` lines only while its stats view is on (the Settings
        // toggle / Ctrl+Alt+Shift+S) — say so instead of waiting forever. Browse idles in
        // the library between launches, so no stats there is simply normal: no line.
        if !browse {
            let msg = if ctx.settings.lock().unwrap().show_stats {
                "等待首个统计窗口数据\u{2026}"
            } else {
                "统计信息已关闭\u{2014}\u{2014}在串流窗口中按 Ctrl+Alt+Shift+S 开启。"
            };
            body.push(
                text_block(msg)
                    .font_size(11.0)
                    .foreground(ThemeRef::SecondaryText)
                    .into(),
            );
        }
    } else {
        let mut segments = hud.stats_line.split(" | ");
        if let Some(first) = segments.next() {
            let chips: Vec<Element> = first
                .split(" \u{00B7} ")
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(|c| {
                    // The `stats:` decode-path tags (see pf-client-core's session
                    // pump). M10 removed the `vulkan`/`vaapi`/`d3d11va` tags with their
                    // rungs; a hardware rung is now always a `native-*` one.
                    let kind = match c {
                        "native-vulkan" | "native-vaapi" | "native-d3d11va" | "pyrowave" => {
                            Pill::Good
                        }
                        "software" => Pill::Info,
                        _ => Pill::Neutral,
                    };
                    pill(c, kind).into()
                })
                .collect();
            body.push(hstack(chips).spacing(6.0).into());
        }
        for seg in segments {
            body.push(
                text_block(seg.trim())
                    .font_size(11.0)
                    .foreground(ThemeRef::SecondaryText)
                    .into(),
            );
        }
    }

    body.push(
        text_block(
            "Ctrl+Alt+Shift+Q 释放输入 \u{00B7} Ctrl+Alt+Shift+D 断开连接 \u{00B7} \
             Ctrl+Alt+Shift+S 统计信息 \u{00B7} F11 全屏",
        )
        .font_size(11.0)
        .wrap()
        .foreground(ThemeRef::SecondaryText)
        .margin(edges(0.0, 4.0, 0.0, 0.0))
        .into(),
    );
    body.push({
        let ctx = ctx.clone();
        button("断开连接")
            .icon(Symbol::Cancel)
            .on_click(move || {
                // Kill the child; its exit event (the reader thread) navigates to the
                // host list, exactly like the session window closing.
                ctx.shared.session.lock().unwrap().kill();
            })
            .margin(edges(0.0, 6.0, 0.0, 0.0))
            .into()
    });

    // One centred card, sized like the app's dialogs — Stretch + max_width (the `page`
    // pattern) instead of a fixed width, so a narrow window shrinks the card instead of
    // clipping it while a wide one still centres it at 520.
    border(card(vstack(body).spacing(12.0)))
        .max_width(520.0)
        .margin(uniform(24.0))
        .vertical_alignment(VerticalAlignment::Center)
        .into()
}
