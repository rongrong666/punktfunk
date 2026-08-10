//! Per-host network speed test (the GTK/Swift clients' "Test Network Speed…"): connect over the
//! real data plane, have the host burst probe filler for 2 s up to its 3 Gbps ceiling, and
//! report goodput · loss · a recommended bitrate (≈70 % of measured), applied in one tap.

use super::style::*;
use super::{Screen, Svc};
use crate::probe::run_speed_probe;
use crate::trust::KnownHosts;
use pf_client_core::profiles::ProfilesFile;
use windows_reactor::*;

/// Speed-test lifecycle. Held as ROOT state (the probe worker completes it via
/// `Svc::set_speed`, and thread-driven updates only re-render through a prop change — see the
/// app module docs). The hosts page resets it to `Running` before navigating here.
#[derive(Clone, PartialEq)]
pub(crate) enum SpeedState {
    Running,
    Failed(String),
    Done {
        mbps: f64,
        loss_pct: f32,
        recommended_kbps: u32,
    },
}

/// Props for the speed page: the services plus the probe lifecycle that drives its re-render.
#[derive(Clone)]
pub(crate) struct SpeedProps {
    pub(crate) svc: Svc,
    pub(crate) state: SpeedState,
}

impl PartialEq for SpeedProps {
    fn eq(&self, other: &Self) -> bool {
        self.svc == other.svc && self.state == other.state
    }
}

pub(crate) fn speed_page(props: &SpeedProps, cx: &mut RenderCx) -> Element {
    let ctx = &props.svc.ctx;
    let set_screen = &props.svc.set_screen;
    let target = ctx.shared.target.lock().unwrap().clone();

    // One probe run per mount (navigating here again re-mounts and re-runs).
    cx.use_effect((), {
        let set_speed = props.svc.set_speed.clone();
        let shared = ctx.shared.clone();
        let identity = ctx.identity.clone();
        let target = target.clone();
        move || {
            use std::sync::atomic::Ordering;
            // The generation the hosts page stamped for THIS run; a stale worker (user backed
            // out and started another test) must not publish over the newer run.
            let generation = shared.speed_gen.load(Ordering::SeqCst);
            std::thread::Builder::new()
                .name("pf-speedtest".into())
                .spawn(move || {
                    let outcome = run_speed_probe(
                        &target.addr,
                        target.port,
                        target.fp_hex.as_deref(),
                        identity,
                    );
                    if shared.speed_gen.load(Ordering::SeqCst) != generation {
                        return; // superseded
                    }
                    set_speed.call(match outcome {
                        Ok(r) => {
                            let mbps = f64::from(r.throughput_kbps) / 1000.0;
                            SpeedState::Done {
                                mbps,
                                loss_pct: r.loss_pct,
                                // ≈70 % of measured: headroom for FEC overhead + real-world loss.
                                recommended_kbps: r.throughput_kbps / 10 * 7,
                            }
                        }
                        Err(msg) => SpeedState::Failed(msg),
                    });
                })
                .ok();
        }
    });

    let back_btn = {
        let ss = set_screen.clone();
        button("关闭")
            .icon(Symbol::Back)
            .on_click(move || ss.call(Screen::Hosts))
            .horizontal_alignment(HorizontalAlignment::Center)
    };
    let headline = if target.name.is_empty() {
        "网络速度测试".to_string()
    } else {
        format!("网络速度测试 \u{00B7} {}", target.name)
    };

    match &props.state {
        SpeedState::Running => busy_page(
            &headline,
            "正在通过真实数据平面测量链路\u{2014}\u{2014}2 秒探测突发\u{2026}",
            vec![back_btn.into()],
        ),
        SpeedState::Failed(msg) => {
            let content = vstack((
                text_block(headline)
                    .font_size(18.0)
                    .semibold()
                    .horizontal_alignment(HorizontalAlignment::Center),
                InfoBar::new("速度测试失败")
                    .message(msg.clone())
                    .error()
                    .is_closable(false),
                back_btn,
            ))
            .spacing(16.0)
            .max_width(480.0)
            .horizontal_alignment(HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Center);
            content.into()
        }
        SpeedState::Done {
            mbps,
            loss_pct,
            recommended_kbps,
        } => {
            let recommended_mbps = f64::from(*recommended_kbps) / 1000.0;
            // A measured bitrate belongs in the layer the TESTED host actually reads it from
            // (design/client-settings-profiles.md §5.3) — writing the global here is what made
            // measuring one host re-tune every other one. Resolved the way a connect resolves
            // it: the one-off this test was started with, else the host's binding.
            let target = ctx.shared.target.lock().unwrap().clone();
            let bound = KnownHosts::load()
                .find_by_addr(&target.addr, target.port)
                .and_then(|h| h.profile_id.clone());
            let profile = match target.profile.as_deref() {
                Some("") => None,
                Some(id) => Some(id.to_string()),
                None => bound,
            }
            .and_then(|reference| ProfilesFile::load().resolve(&reference).0.cloned());
            let kbps = *recommended_kbps;
            let write_global = {
                let (ctx, ss) = (ctx.clone(), set_screen.clone());
                move || {
                    // Rebase on the file before the whole-struct save — same discipline as
                    // `commit()`; another writer may have moved it under this snapshot.
                    let mut s = ctx.settings.lock().unwrap();
                    *s = crate::trust::Settings::load();
                    s.bitrate_kbps = kbps;
                    s.save();
                    ss.call(Screen::Hosts);
                }
            };
            let write_profile = |id: String| {
                let ss = set_screen.clone();
                move || {
                    let mut catalog = ProfilesFile::load();
                    if let Some(slot) = catalog.profiles.iter_mut().find(|x| x.id == id) {
                        slot.overrides.bitrate_kbps = Some(kbps);
                        if let Err(e) = catalog.save() {
                            tracing::warn!(error = %format!("{e:#}"),
                                "saving the measured bitrate");
                        }
                    }
                    ss.call(Screen::Hosts);
                }
            };
            // Which button(s): no binding → the global; a binding that already overrides
            // bitrate → that override (it's what this host reads). Bound but INHERITING
            // bitrate could legitimately mean either layer — offer both rather than
            // guessing (the GTK client's Ask tier; this shell used to silently CREATE an
            // override on the profile).
            let mut buttons: Vec<Element> = Vec::new();
            match &profile {
                None => buttons.push(
                    button(format!("使用 {recommended_mbps:.0} Mb/s"))
                        .accent()
                        .icon(Symbol::Accept)
                        .on_click(write_global.clone())
                        .into(),
                ),
                Some(p) if p.overrides.bitrate_kbps.is_some() => buttons.push(
                    button(format!(
                        "在\u{201c}{}\u{201d}中设为 {recommended_mbps:.0} Mb/s",
                        p.name
                    ))
                    .accent()
                    .icon(Symbol::Accept)
                    .on_click(write_profile(p.id.clone()))
                    .into(),
                ),
                Some(p) => {
                    buttons.push(
                        button("设为默认")
                            .icon(Symbol::Accept)
                            .on_click(write_global.clone())
                            .into(),
                    );
                    buttons.push(
                        button(format!("在\u{201c}{}\u{201d}中设置", p.name))
                            .accent()
                            .icon(Symbol::Accept)
                            .on_click(write_profile(p.id.clone()))
                            .into(),
                    );
                }
            }
            buttons.push({
                let ss = set_screen.clone();
                button("关闭")
                    .icon(Symbol::Cancel)
                    .on_click(move || ss.call(Screen::Hosts))
                    .into()
            });
            let results = card(
                vstack((
                    text_block(format!("{mbps:.0} Mbit/s"))
                        .font_size(34.0)
                        .bold()
                        .horizontal_alignment(HorizontalAlignment::Center),
                    text_block(format!("实测 \u{00B7} 丢包率 {loss_pct:.1} %"))
                        .font_size(12.0)
                        .foreground(ThemeRef::SecondaryText)
                        .horizontal_alignment(HorizontalAlignment::Center),
                    text_block(format!(
                    "推荐码率：{recommended_mbps:.0} Mb/s（约为实测值的 70%，\
                     为 FEC 与丢包预留余量）"
                ))
                    .font_size(12.0)
                    .foreground(ThemeRef::SecondaryText)
                    .horizontal_alignment(HorizontalAlignment::Center),
                    hstack(buttons)
                        .spacing(8.0)
                        .horizontal_alignment(HorizontalAlignment::Center),
                ))
                .spacing(12.0),
            );
            vstack((
                text_block(headline)
                    .font_size(18.0)
                    .semibold()
                    .horizontal_alignment(HorizontalAlignment::Center),
                results,
            ))
            .spacing(16.0)
            .max_width(480.0)
            .horizontal_alignment(HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Center)
            .into()
        }
    }
}
