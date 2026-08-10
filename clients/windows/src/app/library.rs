//! The game library page (mouse/keyboard): the target host's library as a responsive
//! poster grid over `pf-client-core::library` — the WinUI counterpart of the GTK shell's
//! `ui_library.rs`, sharing its service layer (mTLS fetch against the host's management
//! API, pre-classified errors, the 3-worker art pipeline) and its four states
//! (loading / error+retry / empty / grid). Reached from a paired host's "…" menu
//! ("Browse library…", behind the Settings "Show game library" experimental toggle);
//! picking a title starts a normal stream carrying `--launch id` — the host launches the
//! app during the connect handshake.
//!
//! Poster bytes land in a small disk cache (`%LOCALAPPDATA%\punktfunk\art-cache`) and the
//! `Image` widget loads `file:///` URIs from it — reactor's `ImageSource` has no
//! from-bytes constructor, and the cache makes revisits (and offline browsing) instant.
//!
//! Re-render discipline: the fetch and the art stream complete on worker threads, so the
//! whole [`LibraryState`] lives in ROOT state (see the app module docs) and arrives here
//! as a prop; `Shared::library_gen` invalidates a superseded fetch exactly like the
//! speed test's generation guard.

use super::connect::initiate_launch;
use super::style::*;
use super::{AppCtx, Screen, Svc};
use pf_client_core::library;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use windows_reactor::*;

/// Poster-grid metrics: minimum poster-column width before dropping a column, the gap,
/// and the 2:3 portrait ratio.
const POSTER_MIN_WIDTH: f64 = 150.0;
const POSTER_GAP: f64 = 12.0;
const POSTER_RATIO: f64 = 1.5;

/// One game, as the grid renders it (the wire `GameEntry` minus the artwork paths, which
/// resolve into `LibraryState::art`).
#[derive(Clone, PartialEq)]
pub(crate) struct Game {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) store: String,
    /// This entry opens the launcher itself (Steam Big Picture, Heroic) rather than a title —
    /// design D4. Reduced from the wire's `role` by `GameEntry::is_launcher`, so "anything that
    /// isn't `launcher` is a game" is decided in one place for every client.
    pub(crate) launcher: bool,
}

#[derive(Clone, PartialEq, Default)]
pub(crate) enum LibraryPhase {
    #[default]
    Loading,
    Failed(String),
    Empty,
    Ready(Vec<Game>),
}

/// The page's whole thread-driven state: the fetch phase plus poster art as it lands
/// (game id → `file:///` URI into the disk cache).
#[derive(Clone, PartialEq, Default)]
pub(crate) struct LibraryState {
    pub(crate) phase: LibraryPhase,
    pub(crate) art: HashMap<String, String>,
}

/// Props for the library page: the services plus the fetch/art state driving re-render.
#[derive(Clone)]
pub(crate) struct LibraryProps {
    pub(crate) svc: Svc,
    pub(crate) state: LibraryState,
}

impl PartialEq for LibraryProps {
    fn eq(&self, other: &Self) -> bool {
        self.svc == other.svc && self.state == other.state
    }
}

/// Fetch the library for `Shared::target` off the UI thread, publishing into root state:
/// phase first, then art entries as the workers stream them in. A newer call (re-open,
/// Retry, another host) bumps `Shared::library_gen`, and a superseded worker stops
/// publishing — the speed test's generation pattern.
pub(crate) fn start_fetch(ctx: &Arc<AppCtx>, set_library: &AsyncSetState<LibraryState>) {
    let target = ctx.shared.target.lock().unwrap().clone();
    let generation = ctx.shared.library_gen.fetch_add(1, Ordering::SeqCst) + 1;
    set_library.call(LibraryState::default()); // Loading, no art
    let (shared, identity, set) = (
        ctx.shared.clone(),
        ctx.identity.clone(),
        set_library.clone(),
    );
    std::thread::Builder::new()
        .name("pf-library".into())
        .spawn(move || {
            let pin = target.fp_hex.as_deref().and_then(crate::trust::parse_hex32);
            let publish = |state: &LibraryState| {
                if shared.library_gen.load(Ordering::SeqCst) == generation {
                    set.call(state.clone());
                }
            };
            let mut state = LibraryState::default();
            let games = match library::fetch_games(
                &target.addr,
                library::DEFAULT_MGMT_PORT,
                &identity,
                pin,
            ) {
                Ok(games) => games,
                Err(e) => {
                    state.phase = LibraryPhase::Failed(e.to_string());
                    return publish(&state);
                }
            };
            if games.is_empty() {
                state.phase = LibraryPhase::Empty;
                return publish(&state);
            }

            // Seed cached posters; queue the art pipeline for the rest.
            let base = library::base_url(&target.addr, library::DEFAULT_MGMT_PORT);
            let cache = art_cache_dir();
            let mut jobs: VecDeque<(String, Vec<String>)> = VecDeque::new();
            for g in &games {
                match cache.as_deref().and_then(|d| cached_art_uri(d, &g.id)) {
                    Some(uri) => {
                        state.art.insert(g.id.clone(), uri);
                    }
                    None => {
                        let candidates = g.art.poster_candidates(&base);
                        if !candidates.is_empty() {
                            jobs.push_back((g.id.clone(), candidates));
                        }
                    }
                }
            }
            state.phase = LibraryPhase::Ready(
                games
                    .iter()
                    .map(|g| Game {
                        id: g.id.clone(),
                        title: g.title.clone(),
                        store: g.store.clone(),
                        launcher: g.is_launcher(),
                    })
                    .collect(),
            );
            publish(&state);

            if jobs.is_empty() {
                return;
            }
            let rx = library::spawn_art_fetch(base, identity, pin, jobs);
            while let Ok((id, bytes)) = rx.recv_blocking() {
                if shared.library_gen.load(Ordering::SeqCst) != generation {
                    return; // superseded — stop touching state (and the cache is shared anyway)
                }
                if let Some(uri) = cache.as_deref().and_then(|d| store_art(d, &id, &bytes)) {
                    state.art.insert(id, uri);
                    publish(&state);
                }
            }
        })
        .ok();
}

/// `%LOCALAPPDATA%\punktfunk\art-cache` — poster bytes by game id, so the `Image` widget
/// has a `file:///` URI to load and revisits skip the network entirely. Small (one poster
/// per library entry); no eviction yet.
fn art_cache_dir() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("punktfunk").join("art-cache"))
}

/// The cache filename for a game id (`steam:570` → `steam_570.img`) — ids are short and
/// store-qualified, so the sanitized form stays unique in practice.
fn art_file(dir: &Path, id: &str) -> PathBuf {
    let safe: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    dir.join(format!("{safe}.img"))
}

fn cached_art_uri(dir: &Path, id: &str) -> Option<String> {
    let p = art_file(dir, id);
    p.exists().then(|| file_uri(&p))
}

fn store_art(dir: &Path, id: &str, bytes: &[u8]) -> Option<String> {
    std::fs::create_dir_all(dir).ok()?;
    let p = art_file(dir, id);
    std::fs::write(&p, bytes).ok()?;
    Some(file_uri(&p))
}

fn file_uri(p: &Path) -> String {
    format!("file:///{}", p.display().to_string().replace('\\', "/"))
}

/// The store badge text — shared spelling with the GTK page and the console UI's posters.
fn store_label(store: &str) -> &'static str {
    match store {
        "steam" => "Steam",
        "custom" => "自定义",
        "heroic" => "Heroic",
        "lutris" => "Lutris",
        "epic" => "Epic",
        "gog" => "GOG",
        "xbox" => "Xbox",
        _ => "游戏",
    }
}

/// Monogram for the placeholder poster: the first letters of the first two words.
fn initials(title: &str) -> String {
    title
        .split_whitespace()
        .take(2)
        .filter_map(|w| w.chars().next())
        .flat_map(char::to_uppercase)
        .collect()
}

/// A small group label above a tile grid ("Launchers" / "Games"). Only drawn when the page shows
/// both groups — a single unlabelled grid is what every launcher-less library looked like before.
fn group_heading(text: &str) -> Element {
    text_block(text)
        .font_size(12.0)
        .semibold()
        .foreground(ThemeRef::SecondaryText)
        .margin(edges(2.0, 8.0, 2.0, 2.0))
        .into()
}

/// One poster tile: the artwork (or a monogram placeholder while it loads) with the store
/// badge overlaid top-left, the title below, tap-to-launch across the whole tile.
fn poster_tile(
    game: &Game,
    art_uri: Option<&str>,
    poster_h: f64,
    on_tap: Box<dyn Fn()>,
) -> Element {
    let poster: Element = match art_uri {
        Some(uri) => Image::new_with_uri(uri)
            .stretch(Stretch::UniformToFill)
            .height(poster_h)
            .into(),
        // A launcher rarely has poster art, and an art-less launcher drawn like an art-less game
        // reads as "a game whose cover failed to load". So it names its launcher instead of
        // showing a title monogram, and the frame below picks up the accent stroke.
        None => border(
            text_block(if game.launcher {
                store_label(&game.store).to_string()
            } else {
                initials(&game.title)
            })
            .font_size(if game.launcher { 18.0 } else { 28.0 })
            .semibold()
            .foreground(ThemeRef::SecondaryText)
            .horizontal_alignment(HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Center),
        )
        .background(ThemeRef::SubtleFill)
        .height(poster_h)
        .into(),
    };
    let framed = border(grid(vec![
        poster,
        // `Pill::Info` rather than a solid accent fill — `style.rs` is explicit that
        // white-on-bright is unreadable here.
        pill(
            store_label(&game.store),
            if game.launcher {
                Pill::Info
            } else {
                Pill::Neutral
            },
        )
        .horizontal_alignment(HorizontalAlignment::Left)
        .vertical_alignment(VerticalAlignment::Top)
        .margin(uniform(6.0))
        .into(),
    ]))
    .corner_radius(8.0)
    .border_brush(if game.launcher {
        ThemeRef::Accent
    } else {
        ThemeRef::CardStroke
    })
    .border_thickness(uniform(1.0));

    border(
        vstack((
            framed,
            text_block(&game.title)
                .font_size(12.0)
                .wrap()
                .margin(edges(2.0, 6.0, 2.0, 0.0)),
        ))
        .spacing(0.0),
    )
    .background(hit_test_backstop())
    .on_tapped(on_tap)
    .into()
}

pub(crate) fn library_page(props: &LibraryProps, cx: &mut RenderCx) -> Element {
    let ctx = &props.svc.ctx;
    let target = ctx.shared.target.lock().unwrap().clone();
    let (ss, st) = (props.svc.set_screen.clone(), props.svc.set_status.clone());

    // Responsive poster columns from the live window width (the hosts page's pattern).
    let window = cx.use_inner_size();
    let content_w = (window.width - 64.0).clamp(POSTER_MIN_WIDTH, 1120.0);
    let cols =
        (((content_w + POSTER_GAP) / (POSTER_MIN_WIDTH + POSTER_GAP)).floor() as usize).clamp(2, 6);
    let tile_w = (content_w - POSTER_GAP * (cols as f64 - 1.0)) / cols as f64;
    let poster_h = tile_w * POSTER_RATIO;

    let back_btn = button("返回").icon(Symbol::Back).on_click({
        let ss = ss.clone();
        move || ss.call(Screen::Hosts)
    });
    let title = if target.name.is_empty() {
        "游戏库".to_string()
    } else {
        format!("游戏库 \u{00B7} {}", target.name)
    };
    let mut body: Vec<Element> = vec![page_header(&title, back_btn)];

    match &props.state.phase {
        LibraryPhase::Loading => body.push(
            card(
                hstack((
                    ProgressRing::indeterminate().width(18.0).height(18.0),
                    text_block("正在加载游戏库\u{2026}").foreground(ThemeRef::SecondaryText),
                ))
                .spacing(12.0),
            )
            .into(),
        ),
        LibraryPhase::Failed(msg) => {
            body.push(
                InfoBar::new("无法加载游戏库")
                    .message(msg.clone())
                    .error()
                    .is_closable(false)
                    .into(),
            );
            let (ctx2, set_library) = (ctx.clone(), props.svc.set_library.clone());
            body.push(
                button("重试")
                    .accent()
                    .icon(Symbol::Refresh)
                    .on_click(move || start_fetch(&ctx2, &set_library))
                    .horizontal_alignment(HorizontalAlignment::Left)
                    .into(),
            );
        }
        LibraryPhase::Empty => body.push(
            card(
                text_block(
                    "还没有游戏\u{2014}\u{2014}在主机的游戏库中（其控制台或 Web 界面）\
                     添加游戏后会显示在这里。",
                )
                .wrap()
                .foreground(ThemeRef::SecondaryText),
            )
            .into(),
        ),
        LibraryPhase::Ready(games) => {
            let tile = |g: &Game| -> Element {
                let (ctx2, ss, st) = (ctx.clone(), ss.clone(), st.clone());
                let (target, id) = (target.clone(), g.id.clone());
                poster_tile(
                    g,
                    props.state.art.get(&g.id).map(String::as_str),
                    poster_h,
                    Box::new(move || initiate_launch(&ctx2, target.clone(), id.clone(), &ss, &st)),
                )
            };
            // Design D4: launcher entries get their own shelf above the titles, never
            // interleaved. `partition` is stable, so the host's title order survives in each
            // group. Headings appear only when both groups exist, so a library without launcher
            // entries renders exactly as it did before.
            let (launchers, titles): (Vec<&Game>, Vec<&Game>) =
                games.iter().partition(|g| g.launcher);
            let both = !launchers.is_empty() && !titles.is_empty();
            if !launchers.is_empty() {
                if both {
                    body.push(group_heading("启动器"));
                }
                body.push(tile_grid(
                    launchers.iter().map(|g| tile(g)).collect(),
                    cols,
                    POSTER_GAP,
                ));
            }
            if !titles.is_empty() {
                if both {
                    body.push(group_heading("游戏"));
                }
                body.push(tile_grid(
                    titles.iter().map(|g| tile(g)).collect(),
                    cols,
                    POSTER_GAP,
                ));
            }
        }
    }

    page_wide(body)
}
