//! The library's launcher-tile brand marks. Reactor's `ImageSource` is `file:///`-URI raster
//! only (no vector element, no icon font with brand glyphs), so the monochrome PNGs under
//! `assets/launchers/` (mid-gray — legible on both WinUI themes; derived from the
//! `assets/launcher-icons` masters, see that README for provenance/licensing) are embedded in
//! the exe and materialized once into `%LOCALAPPDATA%\punktfunk\launcher-icons\`.
//!
//! The same disk-cache-to-URI pattern as [`super::os_icons`], and for the same reason — but
//! baked much taller (128 px vs 32), because this mark fills a poster tile rather than sitting
//! in a status row.

use std::path::PathBuf;
use std::sync::OnceLock;

/// Embedded PNG per icon token. A plugin may name a mark a newer build ships; a tile whose token
/// isn't here falls back to naming its launcher, which is how every launcher tile looked before
/// icons existed.
const ICONS: &[(&str, &[u8])] = &[
    ("steam", include_bytes!("../../assets/launchers/steam.png")),
    (
        "lutris",
        include_bytes!("../../assets/launchers/lutris.png"),
    ),
    (
        "heroic",
        include_bytes!("../../assets/launchers/heroic.png"),
    ),
    (
        "playnite",
        include_bytes!("../../assets/launchers/playnite.png"),
    ),
    ("epic", include_bytes!("../../assets/launchers/epic.png")),
    ("gog", include_bytes!("../../assets/launchers/gog.png")),
    ("xbox", include_bytes!("../../assets/launchers/xbox.png")),
];

fn dir() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("punktfunk").join("launcher-icons"))
}

/// Materialize the embedded PNGs to disk (idempotent; size mismatch rewrites, so an icon refresh
/// in a newer build lands). Called once at GUI startup, before any tile renders.
pub fn install() {
    let Some(dir) = dir() else { return };
    if std::fs::create_dir_all(&dir).is_err() {
        return; // tiles just render without the mark
    }
    for (token, bytes) in ICONS {
        let p = dir.join(format!("{token}.png"));
        let fresh = std::fs::metadata(&p)
            .map(|m| m.len() != bytes.len() as u64)
            .unwrap_or(true);
        if fresh {
            let _ = std::fs::write(&p, bytes);
        }
    }
}

/// The `file:///` URI of the mark for an entry's `icon` token, or `None` — draw the launcher's
/// name instead — when the entry carries no token or names one we ship no art for.
///
/// The token is matched against [`ICONS`] before it reaches a path join, so nothing a host sends
/// can steer this at a file of its choosing.
#[allow(dead_code)] // only the removed library page rendered launcher marks
pub fn uri(token: Option<&str>) -> Option<String> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    let dir = DIR.get_or_init(dir).as_ref()?;
    let token = token.filter(|t| ICONS.iter().any(|(name, _)| name == t))?;
    let p = dir.join(format!("{token}.png"));
    p.exists()
        .then(|| format!("file:///{}", p.display().to_string().replace('\\', "/")))
}
