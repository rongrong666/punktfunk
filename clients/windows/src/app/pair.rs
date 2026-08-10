//! The SPAKE2 PIN pairing screen: the host is armed and displays a 4-digit PIN; proving
//! knowledge of it pins the host's certificate (and registers ours) with no offline-guessable
//! transcript. Also offers the no-PIN "request access" (delegated-approval) alternative.

use super::connect::{connect, request_access};
use super::style::*;
use super::{Screen, Svc};
use crate::trust::{self, KnownHost, KnownHosts};
use punktfunk_core::client::NativeClient;
use windows_reactor::*;

pub(crate) fn pair_page(props: &Svc, cx: &mut RenderCx) -> Element {
    let ctx = &props.ctx;
    let set_screen = &props.set_screen;
    let set_status = &props.set_status;
    let (code, set_code) = cx.use_state(String::new());
    // The PIN's live value, read directly by the click handler. This page's props (`Svc`) never
    // change, and root wraps every screen in an animated `border` that compares equal once the
    // entrance tween settles — so the top-down reconcile `can_skip_update`s this subtree and never
    // re-renders the pair component off its *local* `use_state`. A button rebuilt only at mount
    // would forever capture the empty mount-time PIN (pairing then fails as a "wrong PIN"). Mirror
    // every keystroke into this stable ref instead, so the click reads exactly what was typed.
    let live_pin = cx.use_ref(String::new());
    let target = ctx.shared.target.lock().unwrap().clone();

    let pair_btn = {
        let (ctx2, ss, st, live, target2) = (
            ctx.clone(),
            set_screen.clone(),
            set_status.clone(),
            live_pin.clone(),
            target.clone(),
        );
        button("配对并连接")
            .accent()
            .icon(Symbol::Accept)
            .on_click(move || {
                let pin = live.borrow().trim().to_string();
                let (ctx3, ss, st, target3) =
                    (ctx2.clone(), ss.clone(), st.clone(), target2.clone());
                std::thread::spawn(move || {
                    let name =
                        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-client".into());
                    match NativeClient::pair(
                        &target3.addr,
                        target3.port,
                        (&ctx3.identity.0, &ctx3.identity.1),
                        &pin,
                        &name,
                        std::time::Duration::from_secs(90),
                    ) {
                        Ok(fp) => {
                            // The PIN ceremony is an authorised trust decision, so this also
                            // retires a dead record for the same address (a re-keyed host).
                            let mut k = KnownHosts::load();
                            k.upsert_trusted(KnownHost {
                                name: target3.name.clone(),
                                addr: target3.addr.clone(),
                                port: target3.port,
                                fp_hex: trust::hex(&fp),
                                paired: true,
                                mac: target3.mac.clone(),
                                ..Default::default()
                            });
                            let _ = k.save();
                            connect(&ctx3, &target3, Some(fp), &ss, &st);
                        }
                        Err(e) => {
                            // Cause-specific: wrong PIN vs pairing-not-armed vs unreachable —
                            // never blame the PIN for a dead network path (shared wording).
                            st.call(trust::pair_error_message(&e));
                            ss.call(Screen::Hosts);
                        }
                    }
                });
            })
    };
    let cancel_btn = {
        let ss = set_screen.clone();
        button("取消")
            .icon(Symbol::Cancel)
            .on_click(move || ss.call(Screen::Hosts))
    };
    // The no-PIN alternative offered alongside the PIN ceremony: open an identified connect that
    // the host parks until the operator approves this device in its console (delegated approval).
    let request_btn = {
        let (svc, target2) = (props.clone(), target.clone());
        button("免 PIN 请求访问")
            .icon(Symbol::Send)
            .on_click(move || request_access(&svc, &target2))
            .horizontal_alignment(HorizontalAlignment::Stretch)
    };

    let content = card(vstack((
        grid((
            avatar(&target.name)
                .grid_column(0)
                .vertical_alignment(VerticalAlignment::Center),
            vstack((
                text_block(format!("与 {} 配对", target.name))
                    .font_size(20.0)
                    .semibold(),
                text_block(format!("{}:{}", target.addr, target.port))
                    .font_size(12.0)
                    .foreground(ThemeRef::SecondaryText),
            ))
            .spacing(2.0)
            .grid_column(1)
            .vertical_alignment(VerticalAlignment::Center)
            .margin(edges(12.0, 0.0, 0.0, 0.0)),
        ))
        .columns([GridLength::Auto, GridLength::Star(1.0)]),
        InfoBar::new("请在主机上启用配对")
            .message(
                "在主机的主机控制台或 Web 控制台中启动配对——它会显示一个 4 位 PIN 码。\
                 请在 90 秒内输入到下方。",
            )
            .informational()
            .is_closable(false),
        text_box(code)
            .placeholder_text("PIN")
            .font_size(28.0)
            .on_text_changed({
                let live = live_pin.clone();
                move |s: String| {
                    // Record the live value for the click handler (the source of truth for the
                    // PIN), and mirror it into `code` so the field stays correct if anything ever
                    // does re-render this page (theme/DPI change).
                    live.set(s.clone());
                    set_code.call(s);
                }
            }),
        hstack((pair_btn, cancel_btn)).spacing(8.0),
        text_block(
            "没有 PIN 码？可改为请求访问，并在主机上（其控制台或 Web 界面）\
             批准本设备\u{2014}\u{2014}无需 PIN 码。",
        )
        .font_size(12.0)
        .foreground(ThemeRef::SecondaryText),
        request_btn,
    ))
    .spacing(16.0))
    .max_width(480.0)
    .horizontal_alignment(HorizontalAlignment::Center)
    .margin(edges(0.0, 60.0, 0.0, 0.0));

    page(vec![content.into()])
}
