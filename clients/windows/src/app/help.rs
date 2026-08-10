//! The Shortcuts screen: a short note on the in-stream capture model plus a reference of the
//! keyboard shortcuts — reached from the Shortcuts button on the host list. The Windows
//! counterpart of the GTK client's Keyboard Shortcuts window; the bindings themselves live in
//! the session window, so both clients document the same set.

use super::style::*;
use super::Screen;
use windows_reactor::*;

/// The in-stream keyboard shortcuts, in the GTK Shortcuts window's order: the chord, then what it
/// does. Read-only — the keyboard bindings live in the session window (`pf-presenter`'s run
/// loop), the controller chord in its gamepad service.
const STREAM_SHORTCUTS: &[(&str, &str)] = &[
    ("F11 / Alt+Enter", "切换全屏"),
    (
        "Ctrl+Alt+Shift+Q",
        "释放捕获的输入（点击串流画面可重新捕获）",
    ),
    ("Ctrl+Alt+Shift+D", "断开连接"),
    (
        "Ctrl+Alt+Shift+S",
        "循环切换统计浮层（关 \u{00B7} 紧凑 \u{00B7} 标准 \u{00B7} 详细）",
    ),
    (
        "Ctrl+Alt+Shift+V",
        "静音/取消静音你的麦克风（仅在串流包含麦克风时可用）",
    ),
    (
        "LB+RB+Start+Back",
        "手柄：释放输入 / 退出全屏\u{2014}\u{2014}长按可断开连接",
    ),
];

/// A subtle key-cap chip for the shortcuts reference — the chord on a filled, bordered pill.
fn key_chip(keys: &str) -> Element {
    border(text_block(keys).font_size(12.0).semibold())
        .background(ThemeRef::SubtleFill)
        .border_brush(ThemeRef::CardStroke)
        .border_thickness(uniform(1.0))
        .corner_radius(6.0)
        .padding(edges(8.0, 3.0, 8.0, 3.0))
        .horizontal_alignment(HorizontalAlignment::Left)
        .into()
}

/// A read-only reference card listing the in-stream keyboard shortcuts. One grid, chord chip then
/// action, so the actions line up across rows.
fn shortcuts_reference() -> Element {
    let mut children: Vec<Element> = Vec::new();
    for (i, (keys, action)) in STREAM_SHORTCUTS.iter().enumerate() {
        let row = i as i32;
        children.push(key_chip(keys).grid_row(row).grid_column(0));
        let action_cell: Element = text_block(*action)
            .wrap()
            .foreground(ThemeRef::SecondaryText)
            .vertical_alignment(VerticalAlignment::Center)
            .into();
        children.push(action_cell.grid_row(row).grid_column(1));
    }
    let table = grid(children)
        .columns([GridLength::Auto, GridLength::Star(1.0)])
        .rows(vec![GridLength::Auto; STREAM_SHORTCUTS.len()])
        .column_spacing(12.0)
        .row_spacing(6.0);
    card(vstack((
        text_block("串流中的键盘快捷键")
            .semibold()
            .margin(edges(0.0, 0.0, 0.0, 8.0)),
        table,
    )))
    .into()
}

/// The Shortcuts screen: a `page`-column with a Back button to the host list, an intro card on
/// the capture model, and the shortcuts reference. Hook-free — called inline from `root` like
/// the other static screens.
pub(crate) fn help_page(set_screen: &AsyncSetState<Screen>) -> Element {
    let back_btn = button("返回").accent().icon(Symbol::Back).on_click({
        let ss = set_screen.clone();
        move || ss.call(Screen::Hosts)
    });

    let intro = card(
        vstack((
            text_block("串流期间").font_size(15.0).semibold(),
            text_block(
                "点击串流画面即可捕获鼠标和键盘\u{2014}\u{2014}之后下列快捷键在游戏\
                 过程中生效。释放捕获可将光标交还给本机，再次点击串流画面\
                 可重新捕获。",
            )
            .font_size(12.0)
            .wrap()
            .foreground(ThemeRef::SecondaryText),
        ))
        .spacing(8.0),
    );

    page(vec![
        page_header("快捷键", back_btn),
        intro.into(),
        shortcuts_reference(),
    ])
}
