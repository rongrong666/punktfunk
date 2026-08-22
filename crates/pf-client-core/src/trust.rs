//! Client identity, the known-hosts (pinned fingerprint) store, and app settings.
//!
//! The identity shares `~/.config/punktfunk/client-{cert,key}.pem` (Linux; on Windows
//! `%APPDATA%\punktfunk`, the WinUI shell's directory) with `punktfunk-probe` so a box
//! pairs once whichever client it uses. On Windows the session binary reads the SAME
//! stores the WinUI shell writes — pairing there makes the session connect silently,
//! mirroring the GTK-shell arrangement on Linux. The WinUI shell re-exports THIS module
//! (`clients/windows/src/trust.rs`), so both processes share one `Settings` shape; the
//! shell stays the settings file's only writer (the session only reads). Pre-unification
//! shell files (≤ 0.8.4: `show_hud`, `engine`) still load — see the migration test below.

use crate::profiles::{ProfilesFile, Resolution, StreamProfile};
use anyhow::{anyhow, Context, Result};
use punktfunk_core::client::NativeClient;
use punktfunk_core::quic::endpoint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Read one of this client's JSON config files, or its `Default` — tolerating a byte order
/// mark, and SAYING SO when the file is there but will not parse.
///
/// Both halves are the same bug seen twice.
///
/// **The BOM.** PowerShell's `Set-Content -Encoding UTF8` writes a UTF-8 BOM, and every
/// Windows how-to reaches for it, so `%APPDATA%\punktfunk\client-windows-settings.json`
/// edited from a shell arrives with `EF BB BF` in front of the `{`. `serde_json` rejects
/// that at byte 0 — correctly, JSON has no BOM — and the old
/// `.and_then(|s| from_str(&s).ok())` then turned the whole file into `Default`. Cost an
/// hour on 2026-08-07: a `codec: "av1"` edit was ignored and the client negotiated HEVC,
/// with the file plainly right on screen. So the mark is stripped, which is what every
/// other JSON consumer on Windows does.
///
/// **The silence.** The `.ok()` that hid the BOM hides everything else too: a trailing
/// comma, a truncated write, a hand-edit with a typo. Every one of them presents as "the
/// app forgot all my settings", with nothing anywhere to say why. A parse failure now costs
/// one `warn!` naming the file and serde's own line/column. The RESULT is unchanged —
/// `Default`, never an error — because nothing about streaming may hinge on this file
/// being readable, and refusing to start because a settings file is malformed would be a
/// worse failure than the one being fixed.
///
/// A missing file is not a parse failure and stays silent: that is just first run. Every
/// OTHER read failure is reported, which is not pedantry — `Set-Content -Encoding Unicode`
/// writes UTF-16LE, `read_to_string` rejects it as invalid UTF-8, and that lands in exactly
/// the same "the app forgot my settings, and said nothing" hole the BOM did.
pub(crate) fn load_json_or_default<T: serde::de::DeserializeOwned + Default>(path: &Path) -> T {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return T::default(),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "config file could not be read — every setting in it is being IGNORED \
                 (a UTF-16 file reads as invalid UTF-8 here; re-save it as UTF-8)"
            );
            return T::default();
        }
    };
    match serde_json::from_str(raw.strip_prefix('\u{feff}').unwrap_or(&raw)) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "config file did not parse — falling back to defaults for it, and the \
                 settings in it are being IGNORED (fix or delete the file)"
            );
            T::default()
        }
    }
}

pub fn config_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let appdata = std::env::var("APPDATA").context("APPDATA unset")?;
        Ok(PathBuf::from(appdata).join("punktfunk"))
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").context("HOME unset")?;
        Ok(PathBuf::from(home).join(".config/punktfunk"))
    }
}

/// This client's persistent identity, generated on first use — presented on every connect
/// so hosts can recognize it once paired.
pub fn load_or_create_identity() -> Result<(String, String)> {
    let dir = config_dir()?;
    let (cp, kp) = (dir.join("client-cert.pem"), dir.join("client-key.pem"));
    if let (Ok(c), Ok(k)) = (std::fs::read_to_string(&cp), std::fs::read_to_string(&kp)) {
        // An older build wrote the key with a plain `fs::write`, which honors the umask and
        // typically lands 0644 — world-readable. Re-lock an existing store on load so upgrades
        // get fixed, not just fresh installs. Best-effort (a read-only store keeps what it has).
        #[cfg(unix)]
        lock_identity_perms(&dir, &kp);
        return Ok((c, k));
    }
    let (c, k) = endpoint::generate_identity().map_err(|e| anyhow!("generate identity: {e}"))?;
    std::fs::create_dir_all(&dir)?;
    // The private key authorizes this client for full remote control of a paired host, so it must
    // never be world-readable: lock the dir to the owner (0700) and create the key 0600 from the
    // start (`fs::write` alone honors the umask → typically 0644). The certificate is public. On
    // non-Unix the %APPDATA% profile ACL already scopes the dir to the user, so std perms suffice.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::write(&cp, &c)?;
    write_private_key(&kp, k.as_bytes())?;
    tracing::info!(cert = %cp.display(), "generated client identity");
    Ok((c, k))
}

/// Write the client's mTLS private key owner-only. On Unix the file is created with mode 0600 from
/// the outset — an `fs::write` + later `chmod` would briefly expose it at the umask default. On
/// other platforms std's default perms plus the %APPDATA% profile ACL scope it to the user.
fn write_private_key(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Best-effort re-lock of an already-present identity (dir 0700, key 0600) — for stores written by
/// an older build that left the key world-readable. Errors are ignored: the worst case is the
/// pre-existing perms, which this never loosens.
#[cfg(unix)]
fn lock_identity_perms(dir: &std::path::Path, key: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600));
}

/// A sibling temp path unique to this process. The stores below have five whole-file writers
/// (WinUI shell, session, console UI, CLI, Decky) and a single shared `.json.tmp` lets two of
/// them interleave: on Windows the second `fs::write` hits a sharing violation, and worse, one
/// process can rename the OTHER's half-written bytes over the target. The pid keeps each
/// writer on its own scratch file; the rename below removes it, so a leftover only survives a
/// hard kill.
fn temp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

/// Write a config file the safe way: a sibling temp file, then a rename over the target. A
/// plain `fs::write` truncates first, so a crash, a full disk or a power cut between truncate
/// and the last byte leaves an empty/half file — and these stores are what a client needs to
/// find its hosts at all. Rename is atomic within a directory on both Unix and Windows
/// (`MoveFileEx` with replace), so a reader ever sees the old file or the new one, never a
/// torn one. Same discipline as the host's `session_settings.rs`.
///
/// **But the rename is not always available, and losing the write is far worse than a torn
/// one.** The Windows client ships as an MSIX package, so every path here is rewritten by the
/// container's AppData virtualization before it reaches the filesystem — and when the package
/// is installed to a secondary drive (Settings ▸ Storage ▸ "New apps will save to: D:"),
/// Windows stores that redirected AppData on the *package's* volume, under
/// `D:\WpSystem\<SID>\AppData\`. The literal path we name still says `C:\Users\…`, so a rename
/// can end up straddling two volumes, and `std::fs::rename` is `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING` and *not* `MOVEFILE_COPY_ALLOWED` — a cross-volume move fails
/// outright with `ERROR_NOT_SAME_DEVICE`. Creating and writing files works fine, which is why
/// such an install starts, streams and pairs happily while every setting and profile silently
/// evaporates (field report 2026-08-05: "it's in read-only mode").
///
/// So a failed rename falls back to writing the target in place. That is exactly what the
/// identity files already do a few lines up — and those demonstrably work on the affected
/// installs — so the fallback is a path we know resolves. It gives up crash-atomicity for that
/// one write and nothing else: the temp+rename stays the normal route everywhere it works.
///
/// Writes and reads of one literal path cannot disagree under that redirection — Microsoft
/// documents a single private-location-first resolution order for both, so whichever layer a
/// write lands in is the layer the next read finds. The fallback still verifies by reading
/// back: a silent write is the exact bug being fixed here, and this path only runs on an
/// install that has already proven it does something unusual.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_sibling(path);
    let atomic = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    let Err(e) = atomic else {
        store_health::clear();
        return Ok(());
    };
    // Don't leave the temp behind to confuse the next writer (or a backup tool).
    let _ = std::fs::remove_file(&tmp);
    match std::fs::write(path, bytes) {
        Ok(()) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "atomic replace unavailable in this install; wrote the config in place instead",
            );
            // Read it straight back. This whole bug was a write that reported success and
            // vanished, so the fallback does not get to claim success on the strength of an
            // `Ok(())` alone — on the one layered filesystem we know we run on, that is the
            // failure mode to be paranoid about. Only on the degraded path, so the normal
            // route pays nothing.
            match std::fs::read(path) {
                Ok(back) if back == bytes => {
                    store_health::clear();
                    Ok(())
                }
                Ok(_) => {
                    let e = std::io::Error::other(
                        "the file read back different from what was just written",
                    );
                    store_health::record(path, &e);
                    Err(e)
                }
                Err(reread) => {
                    store_health::record(path, &reread);
                    Err(reread)
                }
            }
        }
        // Both routes are gone: the store really is unwritable. Report the direct write's
        // error — it describes the actual permission/space problem, where the rename's may
        // only say the two paths landed on different volumes.
        Err(direct) => {
            store_health::record(path, &direct);
            Err(direct)
        }
    }
}

/// Whether the config store is accepting writes, so a front-end can *say so* when it is not.
///
/// Every persistence call site in this crate is deliberately fire-and-forget — a failed
/// settings write must never take a stream down — which historically meant a client whose
/// store was unwritable looked completely normal: toggles moved, profiles appeared, and
/// nothing survived a restart. The field report that produced this module had no log file to
/// send either, so there was no signal anywhere. Recording the last failure centrally lets the
/// UI surface it without unpicking ~15 `let _ = …save()` call sites.
pub mod store_health {
    use std::path::Path;
    use std::sync::Mutex;

    static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

    pub(crate) fn record(path: &Path, err: &std::io::Error) {
        let msg = format!("{}: {err}", path.display());
        tracing::error!(store = %path.display(), error = %err, "cannot persist client config");
        if let Ok(mut slot) = LAST_ERROR.lock() {
            *slot = Some(msg);
        }
    }

    pub(crate) fn clear() {
        if let Ok(mut slot) = LAST_ERROR.lock() {
            *slot = None;
        }
    }

    /// The most recent failure to persist a config file, if the last attempt failed.
    ///
    /// Tracks the last *attempt*, not a per-file verdict: a store that cannot be written fails
    /// every file, so this latches for as long as the problem lasts and goes quiet the moment
    /// any write gets through.
    pub fn last_error() -> Option<String> {
        LAST_ERROR.lock().ok().and_then(|s| s.clone())
    }
}

pub fn hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// WireGuard tunnel config for a host (`pf-wgtunnel`): when set, the session dials an embedded
/// loopback relay that carries QUIC + the video data plane INSIDE one WireGuard UDP flow to the
/// host's single public port. `server_pub` pins the host at the WG layer; the QUIC certificate
/// pin (`fp_hex`) is still learned (TOFU over the authenticated tunnel) and enforced afterwards.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeer {
    /// The host gate's base64 x25519 public key (`pf-wgtunnel genkey` on the host).
    pub server_pub: String,
    /// THIS client's base64 x25519 private key, generated per host at add time; the host's
    /// `--wg-peers` file carries the matching public key.
    pub client_priv: String,
}

/// One trusted host: its pinned certificate fingerprint plus how we got there (TOFU or a
/// PIN ceremony) and where we last reached it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownHost {
    pub name: String,
    pub addr: String,
    pub port: u16,
    /// SHA-256 of the host certificate, lowercase hex — the pin for every later connect.
    pub fp_hex: String,
    /// True if trust came from the SPAKE2 PIN ceremony (vs. trust-on-first-use).
    pub paired: bool,
    /// Unix seconds of the last successful connect — the hosts page marks the
    /// most-recent card with the accent bar. `default` so pre-existing stores load.
    #[serde(default)]
    pub last_used: Option<u64>,
    /// Wake-on-LAN MAC(s) (`aa:bb:cc:dd:ee:ff`) learned from the host's mDNS `mac` TXT while it
    /// was online, so we can wake it once it sleeps and stops advertising. `default` so
    /// pre-existing stores load; empty until first learned.
    #[serde(default)]
    pub mac: Vec<String>,
    /// The host's OS-identity chain (`windows` | `macos` | `linux[/<family>][/<id>]`) learned
    /// from its mDNS `os` TXT while online, so the card's OS icon survives the host going to
    /// sleep. `default` (and elided when empty) so pre-existing stores load unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    /// The host's management-API port (mDNS `mgmt` TXT), where the game library is served —
    /// distinct from `port`, which is the native QUIC plane. Learned from the advert while the
    /// host is online and persisted here for the same reason as `mac` and `os`: so it survives the
    /// advert going away.
    ///
    /// That is not a cosmetic loss like a missing OS icon. A host that moved its mgmt port off
    /// 47990 — the supported fix for sharing a machine with a Sunshine fork, whose web UI owns
    /// that port — was reachable only for as long as mDNS was: on a VPN, a routed subnet, or a
    /// multicast-dead network the library silently went blank, because the port the client had
    /// already been told was never written down. `None` = never learned, resolve via
    /// [`KnownHost::effective_mgmt_port`]. Optional + `default` so pre-existing stores load
    /// (the Apple client's `StoredHost.mgmtPort` is the same field for the same reason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mgmt_port: Option<u16>,
    /// Share this machine's clipboard with THIS host (design/clipboard-and-file-transfer.md
    /// §5.3 — the Apple client's `StoredHost.clipboardSync`). Per-host, not global: handing a
    /// host your clipboard is a trust decision about that host. Default off; the host must
    /// also advertise `HOST_CAP_CLIPBOARD` and have its own policy enabled.
    #[serde(default)]
    pub clipboard_sync: bool,
    /// This host's default settings profile (design/client-settings-profiles.md §4.1) — the
    /// one a plain click uses. `None`, or an id whose profile was deleted, means the global
    /// defaults, i.e. exactly today's behavior; a dangling binding never errors and never
    /// blocks a connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Profiles pinned as extra cards for this host (design §5.2a); order = card order.
    /// Presentation only — NOT the default (that's `profile_id`) — and duplicates/dangling
    /// ids are dropped when the list is resolved against the catalog.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_profiles: Vec<String>,
    /// Stable record identity (design §4.5): minted lazily for records that predate it, never
    /// changed afterwards, so a deep link or a future cross-reference has something to point
    /// at that survives a rename or a new DHCP lease. **No lookup in this crate is keyed by
    /// it** — `fp_hex`/`addr:port` stay the lookup keys; this is groundwork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// WireGuard tunnel config — see [`WgPeer`]. `None` = plain direct connect (unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg: Option<WgPeer>,
}

impl Default for KnownHost {
    /// A blank record with a fresh stable id — the base every construction site builds on
    /// (`KnownHost { name, addr, port, ..Default::default() }`), so adding a field here can't
    /// silently produce records that lack it. That is not hypothetical: `clipboard_sync`
    /// survives today only because [`KnownHosts::upsert`] happens to skip it.
    fn default() -> KnownHost {
        KnownHost {
            name: String::new(),
            addr: String::new(),
            port: 9777,
            fp_hex: String::new(),
            paired: false,
            last_used: None,
            mac: Vec::new(),
            os: String::new(),
            mgmt_port: None,
            clipboard_sync: false,
            profile_id: None,
            pinned_profiles: Vec::new(),
            id: Some(crate::profiles::new_record_uuid()),
            wg: None,
        }
    }
}

impl KnownHost {
    /// Where this host's management API actually is: the port learned from its advert, else the
    /// compiled-in 47990. The twin of the Apple client's `StoredHost.effectiveMgmtPort`.
    ///
    /// Every library/art call resolves through this rather than reaching for
    /// [`crate::library::DEFAULT_MGMT_PORT`] directly — that constant is the FALLBACK, not the
    /// answer, and call sites that treated it as the answer are why a moved port only worked while
    /// mDNS was up.
    pub fn effective_mgmt_port(&self) -> u16 {
        self.mgmt_port.unwrap_or(crate::library::DEFAULT_MGMT_PORT)
    }

    /// This host's pinned profiles that still exist, in card order, without duplicates — what
    /// a grid renders. Dangling pins (the profile was deleted) simply disappear, per design
    /// §5.2a: a pin is presentation state, never a reason to show an error.
    pub fn resolved_pins<'a>(&self, catalog: &'a ProfilesFile) -> Vec<&'a StreamProfile> {
        let mut out: Vec<&StreamProfile> = Vec::new();
        for id in &self.pinned_profiles {
            if out.iter().any(|p| p.id == *id) {
                continue;
            }
            if let Some(p) = catalog.find_by_id(id) {
                out.push(p);
            }
        }
        out
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct KnownHosts {
    pub hosts: Vec<KnownHost>,
}

impl KnownHosts {
    fn path() -> Result<PathBuf> {
        Ok(config_dir()?.join("client-known-hosts.json"))
    }

    /// The store, with any pre-[`KnownHost::id`] records given one. The mint is written back
    /// best-effort right here rather than "on the next save" so the id a caller sees is the
    /// id that is on disk — an identity that changed every load would be worse than none.
    /// A read-only config dir just keeps re-minting in memory, which harms nothing: no lookup
    /// is keyed by the id yet (design §4.5).
    pub fn load() -> KnownHosts {
        let mut k = Self::read();
        if k.mint_missing_ids() {
            let _ = k.save();
        }
        k
    }

    /// The store exactly as it is on disk — no mint, and so no write.
    ///
    /// For a consumer that only needs to LOOK at the records (annotating a discovery result
    /// against them, say) and never dials one by id. [`KnownHosts::load`]'s mint is a write, and
    /// two processes started together against a pre-mint store will each mint a *different* id
    /// for the same record and race to save it — after which whichever one already handed its
    /// ids to a caller has handed out references that no longer resolve. A read that stays a
    /// read cannot take part in that.
    pub fn read() -> KnownHosts {
        Self::path()
            .map(|p| load_json_or_default(&p))
            .unwrap_or_default()
    }

    /// Give every record still missing one a stable id; returns true if anything changed
    /// (i.e. whether this needs persisting). Idempotent — a store that has been through it
    /// once is left byte-identical.
    pub fn mint_missing_ids(&mut self) -> bool {
        let mut minted = false;
        for h in &mut self.hosts {
            if h.id.as_deref().is_none_or(str::is_empty) {
                h.id = Some(crate::profiles::new_record_uuid());
                minted = true;
            }
        }
        minted
    }

    pub fn save(&self) -> Result<()> {
        let p = Self::path()?;
        std::fs::create_dir_all(p.parent().unwrap())?;
        // Temp+rename: losing this file to a torn write costs the user every pairing.
        write_atomic(&p, serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }

    pub fn find_by_fp(&self, fp_hex: &str) -> Option<&KnownHost> {
        self.hosts.iter().find(|h| h.fp_hex == fp_hex)
    }

    /// The record an address-keyed lookup resolves to, by index (so callers that go on to
    /// mutate the store don't fight the borrow checker).
    ///
    /// One address cannot host two live identities at once, but the store can still hold more
    /// than one record claiming `addr:port`: an fp-less placeholder waiting for its first
    /// ceremony, or — before [`KnownHosts::upsert_trusted`] existed — a re-keyed host whose new
    /// record was appended beside the dead one. Resolving that positionally is what turned a
    /// host reinstall into a permanent lockout: the dead pin, written first, won every later
    /// connect, including right after a successful re-pair.
    ///
    /// So the rule is "the newest trust decision wins": a real fingerprint beats a placeholder,
    /// and among real ones the LAST record — records are only ever appended by an explicit
    /// trust decision, so the last one is the most recent thing the user actually authorised.
    /// That is a lookup order, never an authorisation: whichever record this picks, the pin it
    /// yields still has to match the certificate the host presents, or the connect fails closed.
    pub fn index_by_addr(&self, addr: &str, port: u16) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (i, h) in self.hosts.iter().enumerate() {
            if h.addr != addr || h.port != port {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => !h.fp_hex.is_empty() || self.hosts[b].fp_hex.is_empty(),
            };
            if better {
                best = Some(i);
            }
        }
        best
    }

    pub fn find_by_addr(&self, addr: &str, port: u16) -> Option<&KnownHost> {
        self.index_by_addr(addr, port).map(|i| &self.hosts[i])
    }

    /// Forget the entry with this fingerprint. Returns true if one was removed (the user
    /// will have to pair/trust again to reconnect).
    pub fn remove_by_fp(&mut self, fp_hex: &str) -> bool {
        let before = self.hosts.len();
        self.hosts.retain(|h| h.fp_hex != fp_hex);
        self.hosts.len() != before
    }

    /// Insert or refresh an entry, keyed by fingerprint. `paired` only ever upgrades
    /// (a later TOFU connect must not demote a PIN-paired host).
    pub fn upsert(&mut self, entry: KnownHost) {
        if let Some(h) = self.hosts.iter_mut().find(|h| h.fp_hex == entry.fp_hex) {
            h.name = entry.name;
            h.addr = entry.addr;
            h.port = entry.port;
            h.paired |= entry.paired;
            // A refresh without a timestamp must not erase the stored one.
            if entry.last_used.is_some() {
                h.last_used = entry.last_used;
            }
            // Likewise a trust-decision upsert (which carries no MAC) must not wipe learned MACs.
            if !entry.mac.is_empty() {
                h.mac = entry.mac;
            }
            // Same rule for the learned OS chain: only an upsert that carries one moves it.
            if !entry.os.is_empty() {
                h.os = entry.os;
            }
            // And for the learned mgmt port. Stated explicitly rather than left to the
            // does-not-mention-it rule below: this one is load-bearing (a host that moved off
            // 47990 is unreachable for the library without it), so a reconnect upsert that
            // carries `None` must visibly not clear what a discovery taught us.
            if entry.mgmt_port.is_some() {
                h.mgmt_port = entry.mgmt_port;
            }
            // Everything below is state the user set ON this record, which a refresh (a
            // reconnect, a re-pair, a rediscovery) never carries and therefore must never
            // clear: the per-host clipboard decision — which survives today only because this
            // function happens not to mention it — plus the profile binding, its pinned
            // cards, and the stable id. Only an upsert that actually carries a value moves
            // one of them.
            if entry.clipboard_sync {
                h.clipboard_sync = true;
            }
            if entry.profile_id.is_some() {
                h.profile_id = entry.profile_id;
            }
            if !entry.pinned_profiles.is_empty() {
                h.pinned_profiles = entry.pinned_profiles;
            }
            if h.id.as_deref().is_none_or(str::is_empty) {
                h.id = entry.id;
            }
        } else {
            self.hosts.push(entry);
        }
    }

    /// [`upsert`](Self::upsert) for an **authorised trust decision** — a PIN ceremony, a
    /// delegated approval, a TOFU accept, a headless pair — which additionally retires every
    /// other record claiming the same `addr:port`.
    ///
    /// `upsert` alone keys on the fingerprint, deliberately: that is how a host which moved
    /// address keeps its record and the fields the user set on it. The cost was that a host
    /// which changed IDENTITY — a reinstall, a wiped `ProgramData`, a re-key — matched nothing
    /// and got a SECOND record appended for the address it already had, and every later
    /// connect then pinned the dead fingerprint from the older one. No way out from the UI,
    /// and re-pairing didn't help: the ceremony succeeded and appended yet another record.
    ///
    /// A record retired here carries what describes the BOX rather than the identity onto the
    /// record that survives — its MAC, its OS chain, the profile bound to it, its pinned cards,
    /// when it was last used — so a reinstall doesn't quietly cost the user their setup.
    /// Deliberately NOT carried: `paired` and `clipboard_sync`, which are decisions about one
    /// specific certificate and have to be made again for a new one, and the stable record id
    /// (a deep link written from the retired record falls through to the `host=` recovery the
    /// link grammar already specifies, rather than silently pointing at a new identity).
    ///
    /// **Only trust decisions may call this.** Everything that merely LEARNS something about a
    /// host — a rediscovery, the wake path's address re-key — stays on plain `upsert`: those
    /// are driven by unauthenticated mDNS, and letting an advert delete a saved host by
    /// claiming its address would trade this bug for a much worse one.
    pub fn upsert_trusted(&mut self, entry: KnownHost) {
        let (addr, port, fp_hex) = (entry.addr.clone(), entry.port, entry.fp_hex.clone());
        self.upsert(entry);
        // Nothing to supersede *with*: an fp-less record is a placeholder, not an identity.
        if fp_hex.is_empty() {
            return;
        }
        let (keep, retired): (Vec<KnownHost>, Vec<KnownHost>) = std::mem::take(&mut self.hosts)
            .into_iter()
            .partition(|h| !(h.addr == addr && h.port == port && h.fp_hex != fp_hex));
        self.hosts = keep;
        if retired.is_empty() {
            return;
        }
        let Some(h) = self.hosts.iter_mut().find(|h| h.fp_hex == fp_hex) else {
            return;
        };
        for old in retired {
            tracing::info!(
                addr = %addr, port,
                retired_fp = %old.fp_hex, kept_fp = %fp_hex,
                "host re-keyed — retiring the superseded record for this address"
            );
            if h.mac.is_empty() {
                h.mac = old.mac;
            }
            if h.os.is_empty() {
                h.os = old.os;
            }
            if h.mgmt_port.is_none() {
                h.mgmt_port = old.mgmt_port;
            }
            if h.profile_id.is_none() {
                h.profile_id = old.profile_id;
            }
            if h.pinned_profiles.is_empty() {
                h.pinned_profiles = old.pinned_profiles;
            }
            if h.last_used.is_none() {
                h.last_used = old.last_used;
            }
        }
    }
}

/// Load-upsert-save in one step — the pin every trust decision (TOFU accept, PIN
/// ceremony, delegated approval, headless pairing) ends in.
pub fn persist_host(name: &str, addr: &str, port: u16, fp_hex: &str, paired: bool) {
    let mut known = KnownHosts::load();
    // `..Default::default()` deliberately: this builds a record from a trust decision only,
    // so every user-set field (clipboard, profile binding, pins) must arrive as "not carried"
    // — `upsert` then leaves an existing host's own settings alone. A hand-written literal
    // here is how those fields would get silently reset on the next re-pair.
    //
    // `upsert_trusted`, not `upsert`: this IS the authorised decision, so it is also the point
    // at which a host that re-keyed retires its own dead record for this address.
    known.upsert_trusted(KnownHost {
        name: name.to_string(),
        addr: addr.to_string(),
        port,
        fp_hex: fp_hex.to_string(),
        paired,
        ..Default::default()
    });
    let _ = known.save();
}

/// This machine's name — the label a host files this client under in its paired-devices list.
/// Now owned by punktfunk-core (`client::device_name`) so the connect path and the C ABI share
/// the same default; re-exported here for the existing pairing-path callers.
pub fn device_name() -> String {
    punktfunk_core::client::device_name()
}

/// Drop an fp-less placeholder entry for `addr:port`. A host added by address before any
/// ceremony (`--add-host` with no `--fp`) is stored keyed by address with an empty fingerprint;
/// once pairing yields the real one, [`persist_host`] writes a second, fp-keyed entry — so the
/// placeholder has to go or the host list shows the same box twice. No-op (and no disk write)
/// when there is none, which is the usual case.
pub fn forget_placeholder(addr: &str, port: u16) {
    let mut known = KnownHosts::load();
    let before = known.hosts.len();
    known
        .hosts
        .retain(|h| !((h.fp_hex.is_empty() || is_pending_fp(&h.fp_hex)) && h.addr == addr && h.port == port));
    if known.hosts.len() != before {
        let _ = known.save();
    }
}

/// The record an advert's lesson should land on: the fingerprint match if there is one, else
/// whatever the address resolves to. Fingerprint FIRST — a single pass that took "either" would
/// hand a stale record at the same address the data the live host advertised, purely because it
/// came earlier in the file.
fn learn_target<'a>(
    known: &'a mut KnownHosts,
    fp_hex: &str,
    addr: &str,
    port: u16,
) -> Option<&'a mut KnownHost> {
    let i = (!fp_hex.is_empty())
        .then(|| known.hosts.iter().position(|h| h.fp_hex == fp_hex))
        .flatten()
        .or_else(|| known.index_by_addr(addr, port))?;
    known.hosts.get_mut(i)
}

/// Copy everything an advert can teach onto a saved record — wake MAC(s), OS-identity chain,
/// management port — and report whether anything actually moved, so the caller writes only when
/// there is something to write. Pure (no disk, no clock), which is what makes it testable.
///
/// A field the advert does not carry is left alone, never cleared: an older host simply omits the
/// TXT, and forgetting a MAC already learned would cost the user their wake.
fn apply_advert(h: &mut KnownHost, mac: &[String], os: &str, mgmt_port: Option<u16>) -> bool {
    let mut changed = false;
    if !mac.is_empty() && h.mac != mac {
        h.mac = mac.to_vec();
        changed = true;
    }
    if !os.is_empty() && h.os != os {
        h.os = os.to_string();
        changed = true;
    }
    // 0 is how "not advertised" reaches us from a caller whose own type has no `Option`.
    if mgmt_port.is_some_and(|p| p != 0 && h.mgmt_port != Some(p)) {
        h.mgmt_port = mgmt_port;
        changed = true;
    }
    changed
}

/// Write down everything a live advert teaches the saved record it matched — wake MAC(s), OS
/// chain, management port — matched by fingerprint or address. No-op, and no disk write, when
/// the record already says all three, so a surface can call this on every discovery tick.
///
/// ONE call rather than three. Each field used to be learned by its own function, which meant
/// every front-end had to remember all three, and only the two desktop hosts pages ever did:
/// the console home and the headless CLI learned the management port alone. On a Steam Deck,
/// whose Gaming Mode runs nothing but those two, that left every saved host with no MAC forever
/// — and every wake gate in the codebase reads `!mac.is_empty()` against this record, so
/// Wake-on-LAN there could not fire at all, with no error to show for it (#322).
///
/// [`KnownHosts::read`], not [`KnownHosts::load`]: `punktfunk discover` calls this, and that verb
/// is deliberately not an id-minter (see [`KnownHosts::read`] for the race that avoids). Learning
/// a MAC is no reason to become one.
///
/// Takes the three learned fields rather than a `DiscoveredHost` because there are two of those
/// — core's and the WinUI shell's verbatim port — and this has to serve both.
pub fn learn_from_advert(
    fp_hex: &str,
    addr: &str,
    port: u16,
    mac: &[String],
    os: &str,
    mgmt_port: Option<u16>,
) {
    let mut known = KnownHosts::read();
    let Some(h) = learn_target(&mut known, fp_hex, addr, port) else {
        return;
    };
    if apply_advert(h, mac, os, mgmt_port) {
        let _ = known.save();
    }
}

/// Re-key a saved host's address/port after it rediscovered on a new DHCP lease (matched by
/// fingerprint). No-op — and no disk write — when unchanged. Called from the wake-and-wait flow when
/// a woken host reappears on a different IP than the stored one, so this and future connects dial the
/// live address instead of the stale one.
pub fn rekey_addr(fp_hex: &str, addr: &str, port: u16) {
    if fp_hex.is_empty() {
        return;
    }
    let mut known = KnownHosts::load();
    let Some(h) = known.hosts.iter_mut().find(|h| h.fp_hex == fp_hex) else {
        return;
    };
    if h.addr == addr && h.port == port {
        return;
    }
    h.addr = addr.to_string();
    h.port = port;
    let _ = known.save();
}

/// Stamp "now" as this host's last successful connect (drives the hosts page's
/// most-recent accent). No-op when the fingerprint isn't stored.
pub fn touch_last_used(fp_hex: &str) {
    let mut known = KnownHosts::load();
    if let Some(h) = known.hosts.iter_mut().find(|h| h.fp_hex == fp_hex) {
        h.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok();
        let _ = known.save();
    }
}

/// Save a host's management-API port learned from the **session's own `Welcome`**, keyed by
/// fingerprint alone — the identity a just-connected client is certain of.
///
/// This is the mDNS-free path, and the one that matters most: [`learn_from_advert`] can only fire
/// where an advert is visible, whereas this fires on any successful connect, including a host
/// added by IP on a network where discovery has never worked. No-op — and no disk write — when
/// the fingerprint isn't stored or the value is unchanged, so it is safe on every connect.
pub fn learn_mgmt_port_by_fp(fp_hex: &str, mgmt_port: u16) {
    if fp_hex.is_empty() || mgmt_port == 0 {
        return;
    }
    let mut known = KnownHosts::load();
    let Some(h) = known.hosts.iter_mut().find(|h| h.fp_hex == fp_hex) else {
        return;
    };
    if h.mgmt_port == Some(mgmt_port) {
        return;
    }
    h.mgmt_port = Some(mgmt_port);
    let _ = known.save();
}

/// Placeholder fingerprint prefix for a host saved BEFORE any connect — the WG-mode
/// "add host" flow writes the record (with its tunnel keys) before the TLS fingerprint
/// can be learned, and the shell keys every host row by `fp_hex`. An EMPTY fp for more
/// than one such host collapses them into one row (edit/forget/menus all hit the first
/// match), so each gets a unique `pending-…` id instead. A pending fp behaves like an
/// empty one everywhere trust is concerned (it never parses as hex32 and is never sent
/// as `--fp`); [`learn_fp_by_addr`] overwrites it with the real fingerprint on the first
/// successful connect.
pub const PENDING_FP_PREFIX: &str = "pending-";

/// True for a placeholder minted at add time — see [`PENDING_FP_PREFIX`].
pub fn is_pending_fp(fp_hex: &str) -> bool {
    fp_hex.starts_with(PENDING_FP_PREFIX)
}

/// Mint a unique placeholder fingerprint from an add-time seed (addr/port/keys).
pub fn mint_pending_fp(seed: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut h);
    format!("{PENDING_FP_PREFIX}{:016x}", h.finish())
}

/// Repair stores written before pending ids existed: every record still carrying an
/// EMPTY (or duplicated) fp gets a unique pending id, so host rows are addressable
/// again. Returns true when it changed anything (the caller then saves).
pub fn repair_pending_fps(known: &mut KnownHosts) -> bool {
    let mut seen = std::collections::HashSet::new();
    let mut changed = false;
    for h in known.hosts.iter_mut() {
        if !h.fp_hex.is_empty() && !is_pending_fp(&h.fp_hex) {
            seen.insert(h.fp_hex.clone());
            continue;
        }
        if !h.fp_hex.is_empty() && seen.insert(h.fp_hex.clone()) {
            continue; // a unique pending id is already fine
        }
        let seed = format!(
            "{}:{}:{}",
            h.addr,
            h.port,
            h.wg.as_ref().map(|w| w.client_priv.as_str()).unwrap_or("")
        );
        let mut fp = mint_pending_fp(&seed);
        let mut n = 0u32;
        while seen.contains(&fp) {
            n += 1;
            fp = mint_pending_fp(&format!("{seed}#{n}"));
        }
        seen.insert(fp.clone());
        h.fp_hex = fp;
        changed = true;
    }
    changed
}

/// Learn a host's certificate fingerprint after a WireGuard-mode first connect, keyed by the
/// saved record's addr:port: the WG static key authenticated the host at the tunnel layer, so
/// the cert pin the session just observed is safe to persist (and is enforced from then on).
/// No-op when the record already carries a pin or none exists.
pub fn learn_fp_by_addr(addr: &str, port: u16, fp_hex: &str) {
    if fp_hex.is_empty() {
        return;
    }
    let mut known = KnownHosts::load();
    let Some(h) = known
        .hosts
        .iter_mut()
        .find(|h| h.addr == addr && h.port == port)
    else {
        return;
    };
    // A pending placeholder is not a pin: overwrite it with the learned fingerprint.
    if !h.fp_hex.is_empty() && !is_pending_fp(&h.fp_hex) {
        return;
    }
    h.fp_hex = fp_hex.to_string();
    let _ = known.save();
}

/// Run the SPAKE2 PIN ceremony against a host. `device_name` is the label the HOST
/// stores this client under (its paired-devices list); the 90 s budget covers a
/// human-typed PIN. Returns the host's now-verified certificate fingerprint to pin.
pub fn pair_with_host(
    addr: &str,
    port: u16,
    identity: &(String, String),
    pin: &str,
    device_name: &str,
) -> std::result::Result<[u8; 32], punktfunk_core::PunktfunkError> {
    NativeClient::pair(
        addr,
        port,
        (&identity.0, &identity.1),
        pin.trim(),
        device_name,
        std::time::Duration::from_secs(90),
    )
}

/// User-facing sentence for a failed connect / request-access, keyed on the actual cause —
/// shared by every desktop/console surface so "the host declined this device" never renders
/// as "connection timed out". Reason-specific text for a typed host rejection
/// ([`punktfunk_core::reject::RejectReason`]); the caller keeps its own wording for
/// non-rejection errors.
pub fn connect_reject_message(reason: punktfunk_core::reject::RejectReason) -> String {
    use punktfunk_core::reject::RejectReason as R;
    match reason {
        R::Denied => "主机拒绝了本设备的请求。".into(),
        R::ApprovalTimeout => {
            "主机上无人及时批准请求——请在主机的控制台或 Web 界面中批准本设备，\
             然后重新请求访问。"
                .into()
        }
        R::Superseded => {
            "本设备发送了更新的请求并取代了此请求——请在主机上批准最新的请求。"
                .into()
        }
        R::IdentityRequired => {
            "主机要求配对——请先配对本设备（PIN 或请求访问）。".into()
        }
        R::PairingNotArmed => {
            "主机未启用配对——请在主机的「配对」页面启用配对后重试。"
                .into()
        }
        R::PairingBoundToOtherDevice => {
            "主机的配对窗口是为另一台设备启用的——请为本设备重新启用。"
                .into()
        }
        R::PairingRateLimited => {
            "配对尝试过于频繁——请稍等几秒后重试。".into()
        }
        R::WireVersionMismatch => {
            "客户端与主机版本不匹配——请将两端更新到同一版本。".into()
        }
        R::Busy => "主机正忙于另一个会话。".into(),
        R::SetupFailed => {
            "主机已接受连接，但无法启动串流——原因见主机日志\
             （Web 控制台 → 日志）。"
                .into()
        }
        R::AccessExpired => {
            "Your access to this host has expired — ask the host's owner to grant it again.".into()
        }
        R::LaunchNotPermitted => {
            "This device isn't permitted to launch games on the host — connect without picking \
             a game, or ask the host's owner to allow launching."
                .into()
        }
    }
}

/// User-facing sentence for a failed PIN pairing ceremony ([`pair_with_host`]) — distinguishes
/// a wrong PIN (the SPAKE2 proof failed) from an unreachable host and from the host's typed
/// rejections, so a dead network path or a disarmed host is never reported as a bad PIN.
pub fn pair_error_message(err: &punktfunk_core::PunktfunkError) -> String {
    use punktfunk_core::PunktfunkError as E;
    match err {
        E::Crypto => "PIN 码错误——请核对主机「配对」页面上显示的 PIN 码后重试。".into(),
        E::Rejected(reason) => connect_reject_message(*reason),
        E::Timeout => "主机未响应。请确认它正在运行且网络可达。".into(),
        E::Io(_) => {
            "无法连接到主机——请检查本设备与主机是否在同一网络\
             （本设备未连接 VPN，无访客 Wi-Fi / AP 隔离）。"
                .into()
        }
        other => format!("配对失败：{other:?}"),
    }
}

/// Probe several hosts for reachability in parallel — one thread each, so the wall-clock cost is
/// ~one `timeout`, not the sum. Each element of the returned vec corresponds by index to
/// `targets`. Wraps the single-host [`NativeClient::probe`] (a bounded, trust-agnostic,
/// mDNS-independent QUIC handshake); used by the hosts page's presence pips and the headless
/// `--list-hosts --probe`.
pub fn probe_reachable_many(
    targets: Vec<(String, u16)>,
    timeout: std::time::Duration,
) -> Vec<bool> {
    let handles: Vec<_> = targets
        .into_iter()
        .map(|(addr, port)| std::thread::spawn(move || NativeClient::probe(&addr, port, timeout)))
        .collect();
    handles
        .into_iter()
        .map(|h| h.join().unwrap_or(false))
        .collect()
}

/// How much the on-stream statistics overlay shows — the Android client's tiers, shared
/// across every client (design/stats-unification.md): each tier is a strict superset of
/// the previous. Ctrl+Alt+Shift+S cycles Off → Compact → Normal → Detailed live.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatsVerbosity {
    Off,
    /// One glanceable line: fps · end-to-end ms · Mb/s.
    Compact,
    /// Stream mode plus the end-to-end latency percentiles and loss counters.
    Normal,
    /// Everything: decoder path, HDR tags, and the per-stage latency equation.
    Detailed,
}

impl StatsVerbosity {
    /// Cycle order (also the settings pickers' option order).
    pub const ALL: [StatsVerbosity; 4] = [
        StatsVerbosity::Off,
        StatsVerbosity::Compact,
        StatsVerbosity::Normal,
        StatsVerbosity::Detailed,
    ];

    /// The next tier in the live cycle, wrapping back to Off.
    pub fn next(self) -> StatsVerbosity {
        match self {
            StatsVerbosity::Off => StatsVerbosity::Compact,
            StatsVerbosity::Compact => StatsVerbosity::Normal,
            StatsVerbosity::Normal => StatsVerbosity::Detailed,
            StatsVerbosity::Detailed => StatsVerbosity::Off,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            StatsVerbosity::Off => "关",
            StatsVerbosity::Compact => "紧凑",
            StatsVerbosity::Normal => "标准",
            StatsVerbosity::Detailed => "详细",
        }
    }
}

/// How a touchscreen's fingers drive the host — the cross-client touch-input model (Android
/// `TouchMode`, Apple `TouchInputMode`). Stored stringly in [`Settings::touch_mode`] so the
/// file stays readable; parsed with [`TouchMode::from_name`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TouchMode {
    /// Relative cursor like a laptop touchpad: the cursor stays put on touch-down and moves
    /// by the finger's delta (with mild acceleration), tap to click. The default — a cursor
    /// is the universally workable model on a screen the host isn't sized for.
    Trackpad,
    /// Direct pointing: the cursor jumps to the finger and follows it (absolute).
    Pointer,
    /// Real multi-touch passthrough: every finger is a host touchscreen contact, no gesture
    /// interpretation — only helps hosts/apps that actually understand touch.
    Touch,
}

impl TouchMode {
    /// Cycle/picker order (also the settings pickers' option order).
    pub const ALL: [TouchMode; 3] = [TouchMode::Trackpad, TouchMode::Pointer, TouchMode::Touch];

    /// Parse the persisted name, defaulting to `Trackpad` for unset/unknown values.
    pub fn from_name(s: &str) -> TouchMode {
        match s {
            "pointer" => TouchMode::Pointer,
            "touch" => TouchMode::Touch,
            _ => TouchMode::Trackpad,
        }
    }

    /// The persisted name (the inverse of [`from_name`](Self::from_name)).
    pub fn as_name(self) -> &'static str {
        match self {
            TouchMode::Trackpad => "trackpad",
            TouchMode::Pointer => "pointer",
            TouchMode::Touch => "touch",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TouchMode::Trackpad => "Trackpad",
            TouchMode::Pointer => "Direct pointer",
            TouchMode::Touch => "Touch passthrough",
        }
    }
}

/// How a physical mouse drives the host — the desktop-sweep mouse model
/// (design/remote-desktop-sweep.md M1). Stored stringly in [`Settings::mouse_mode`] so the
/// file stays readable; parsed with [`MouseMode::from_name`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MouseMode {
    /// Pointer lock (relative deltas, hidden cursor) — the game model, and the default:
    /// the only cursor you see is the host's.
    Capture,
    /// Absolute pointer, uncaptured: the cursor enters and leaves the stream freely and
    /// motion goes on the wire as absolute positions through the letterbox. The remote
    /// desktop model. Requires a host injector with absolute support (not gamescope).
    Desktop,
}

impl MouseMode {
    /// Cycle/picker order (also the settings pickers' option order).
    pub const ALL: [MouseMode; 2] = [MouseMode::Capture, MouseMode::Desktop];

    /// Parse the persisted name, defaulting to `Capture` for unset/unknown values.
    pub fn from_name(s: &str) -> MouseMode {
        match s {
            "desktop" => MouseMode::Desktop,
            _ => MouseMode::Capture,
        }
    }

    /// The persisted name (the inverse of [`from_name`](Self::from_name)).
    pub fn as_name(self) -> &'static str {
        match self {
            MouseMode::Capture => "capture",
            MouseMode::Desktop => "desktop",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MouseMode::Capture => "Capture (games)",
            MouseMode::Desktop => "Desktop (absolute)",
        }
    }
}

/// Presentation intent — what the presenter optimizes for
/// (design/desktop-presentation-rebuild.md; the Apple/Android clients' shared
/// `present_priority`/`smooth_buffer` pair). Stored stringly in
/// [`Settings::present_priority`] + [`Settings::smooth_buffer`]; resolved with
/// [`PresentPriority::resolve`], whose rules match the Android reference
/// (`decode/presenter.rs`): anything but an explicit `"smooth"` is latency, and a
/// smooth buffer outside 1..=3 (including 0 = Automatic) becomes 2.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PresentPriority {
    /// Every frame presents the moment the display can take it; a network hiccup is an
    /// occasional repeated or skipped frame. The default.
    Latency,
    /// A small frame buffer (1–3 frames) evens out network/decode jitter, at the
    /// buffer's worth of added display latency.
    Smooth { buffer: u8 },
}

impl PresentPriority {
    /// The shared cross-client resolution rule — pure, so every embedder agrees on what
    /// a foreign profile's values mean.
    pub fn resolve(name: &str, buffer: u8) -> PresentPriority {
        if name == "smooth" {
            PresentPriority::Smooth {
                buffer: if (1..=3).contains(&buffer) { buffer } else { 2 },
            }
        } else {
            PresentPriority::Latency
        }
    }

    /// Frames the smoothing store holds; `0` = newest-wins (the latency intent).
    pub fn fifo_capacity(self) -> u8 {
        match self {
            PresentPriority::Latency => 0,
            PresentPriority::Smooth { buffer } => buffer,
        }
    }
}

/// App settings, persisted as JSON. Stringly-typed gamepad/compositor prefs so the file
/// stays readable; parsed with `*Pref::from_name` at connect time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Stream mode; `0` = the native size/refresh of the monitor the window is on,
    /// resolved at connect time.
    pub width: u32,
    pub height: u32,
    pub refresh_hz: u32,
    /// Requested encoder bitrate (kbps); 0 = host default.
    pub bitrate_kbps: u32,
    /// Render-resolution multiplier: the client asks the host to render/encode at
    /// `resolved mode × render_scale` and the presenter downscales the larger decoded frame to the
    /// window (`> 1` supersamples for sharpness, at more bandwidth AND decode; `< 1` renders under
    /// native for a lighter host/link). `1.0` = Native (the prior behaviour). Applied at connect
    /// (and each match-window resize) via [`punktfunk_core::render_scale`], clamped even + to the
    /// codec's max dimension. Missing in a pre-existing store → the `Default` (1.0) via the
    /// container `#[serde(default)]`.
    pub render_scale: f64,
    pub gamepad: String,
    /// Forward this device's controllers to the host at all. Default ON — that was the
    /// unconditional behaviour before this became a setting.
    ///
    /// Off is for the couch whose controller reaches the host by some *other* route: a USB
    /// passthrough tool (VirtualHere and friends), or a pad simply plugged into the host
    /// itself. Leaving forwarding on there gives the host two controllers for one pair of
    /// hands, and games read both.
    ///
    /// It is deliberately stronger than "send no input": with it off the client never
    /// *opens* the controller, and opening is what grabs the hardware (SDL's HIDAPI drivers
    /// take the hidraw node) — a held device is one a passthrough tool cannot bind. Menu
    /// navigation in the launcher still opens the active pad, and the session releases it;
    /// see [`crate::gamepad::GamepadService::set_forwarding`].
    #[serde(default = "default_true")]
    pub gamepad_forwarding: bool,
    /// Stable identity (`vid:pid:name`, see `PadInfo::key`) of the physical controller
    /// forwarded as pad 0; empty = automatic (most recently connected). Applied to the
    /// gamepad service at startup so the choice survives restarts.
    pub forward_pad: String,
    /// What a controller's SYSTEM buttons — guide (Xbox/PS/Steam) and the Deck's QAM `…` —
    /// do while streaming: `"auto"` (default), `"forward"` (raw presses go to the host,
    /// the pre-setting behaviour), or `"local"` (they stay with this device; the host's
    /// are reached via the hold-Select gesture instead). Auto resolves per platform in
    /// [`Settings::system_buttons_forward`]: forward everywhere EXCEPT under Gaming Mode,
    /// where the local Steam UI always reacts to the same physical press — forwarding
    /// there opens BOTH overlays, the local one on top of the stream.
    #[serde(default = "default_auto")]
    pub system_buttons: String,
    /// The hold-Select guide gesture: holding Select/Back alone ≥ ~350 ms sends the HOST
    /// the guide button (down for as long as it's held, so a long hold is the host's
    /// long-press — the QAM on a Gaming-Mode host). `"auto"` (default) / `"on"` / `"off"`,
    /// resolved in [`Settings::guide_gesture_enabled`]: auto = on only where the raw
    /// guide press can't reach the host cleanly (Gaming Mode; iOS/tvOS resolve their own
    /// auto in the Apple client). While armed, a Select TAP is delivered on release —
    /// costing it up to the hold threshold in latency — and a Select held as part of a
    /// combo (any other button already down) passes through untouched.
    #[serde(default = "default_auto")]
    pub guide_gesture: String,
    /// Which host compositor backend to request (advisory; the host falls back to
    /// auto-detect when unavailable).
    pub compositor: String,
    /// How a touchscreen's fingers drive the host (Deck/tablet): a [`TouchMode`] name —
    /// `"trackpad"` (default), `"pointer"`, or `"touch"`. Read at connect via
    /// [`Settings::touch_mode`]; irrelevant on a mouse-only client. `default` so pre-existing
    /// stores load as trackpad.
    #[serde(default = "default_touch_mode")]
    pub touch_mode: String,
    /// How a physical mouse drives the host: a [`MouseMode`] name — `"capture"` (default,
    /// pointer lock + relative) or `"desktop"` (uncaptured absolute pointer). Read at
    /// connect via [`Settings::mouse_mode`]. `default` so pre-existing stores load as
    /// capture — today's behavior.
    #[serde(default = "default_mouse_mode")]
    pub mouse_mode: String,
    /// Send system chords (Alt+Tab, Super / the Windows key) to the host while input is
    /// captured under the `capture` mouse model; off leaves them with the local shell.
    /// Read at connect into the presenter's session opts, which turns it into an SDL
    /// keyboard grab (a low-level hook on Windows, shortcuts-inhibit or `XGrabKeyboard`
    /// on Linux). The `desktop` mouse model never grabs, whatever this says.
    pub inhibit_shortcuts: bool,
    /// Stream the default microphone to the host's virtual mic source.
    pub mic_enabled: bool,
    /// Run the mic uplink through the platform's echo cancellation (the Apple/Android clients'
    /// "Echo cancellation" toggle, same `echo_cancel` key). On Linux that means preferring an
    /// echo-cancelled PipeWire source; on Windows, asking WASAPI for the Communications stream
    /// category so the endpoint's own canceller engages. Default ON — without it, a laptop
    /// speaker playing the host's audio is heard by this device's mic and sent straight back.
    /// Only meaningful while `mic_enabled`. `PUNKTFUNK_NO_AEC=1` overrides it off (see
    /// `audio::aec_enabled`). `default` so pre-existing stores load with it on.
    #[serde(default = "default_true")]
    pub echo_cancel: bool,
    /// Requested audio channel count: 2 (stereo), 6 (5.1) or 8 (7.1). The host clamps to what it
    /// can capture; the resolved count drives the decoder + playback layout.
    pub audio_channels: u8,
    /// Requested audio format — the cross-client `audio_format` key, whose stored values are shared
    /// verbatim with the Apple and Android clients (`crate::audio_format::AUDIO_FORMATS`):
    /// [`crate::audio_format::AUDIO_FORMAT_OPUS`] (the default, and byte for byte the session every
    /// build before the lossless plane ran), `..._LOSSLESS_48` or `..._LOSSLESS_96`.
    ///
    /// Off by default and deliberately: lossless takes 2.3–4.6 Mbps off the top of the link,
    /// OUTSIDE the ABR loop that manages the video budget, against the ~256 kbps Opus it replaces —
    /// so a user has to pick it. Since 2026-08-17 this setting is the ONLY opt-in: the host's half
    /// (`PUNKTFUNK_AUDIO_HIRES`) defaults ON and is an opt-OUT (`=0`), so this choice is enough on
    /// any host that has not deliberately turned the plane off. A REQUEST, never a fact: the host
    /// runs a five-condition gate and may answer
    /// Opus anyway, and this client downgrades it further if the output device will not open the
    /// rate. What actually happened is the OSD's `audio lossless …` line, and the log's
    /// "negotiated audio format".
    ///
    /// Stereo-only: a lossless surround frame does not fit one QUIC datagram at the default MTU
    /// and the host declines it (`design/hi-res-audio.md` §4.2). Both desktop settings UIs take
    /// the picker away under 5.1/7.1 — GTK greys the row (its per-row profile Reset lives on the
    /// row, and an insensitive row is the idiom its mic-dependent rows already use), the WinUI
    /// shell drops it from the rendered card (its idiom for a row that does not apply). The
    /// session filters the pair AGAIN whatever either UI did, because the two fields are
    /// independent profile overrides and can disagree — and the env override answers to no UI.
    ///
    /// A `String`, not an enum, for the same reason [`codec`](Self::codec) is: it is read out of a
    /// file a newer client may have written, and an unrecognized value resolves to Opus rather than
    /// ending a session over a dropdown. `default` so pre-existing stores load on the Opus plane.
    #[serde(default = "default_audio_format")]
    pub audio_format: String,
    /// Preferred video codec: `"auto"` (host decides), `"hevc"`, `"h264"`, or `"av1"`. A soft
    /// preference — the host honors it when it can emit it, else falls back to the best shared codec.
    #[serde(default = "default_codec")]
    pub codec: String,
    /// Video decoder preference: `"auto"` (vendor-ordered native ladder — pf-vkdecode over
    /// Vulkan Video, then the platform's own rung, then software; see `video::Decoder::new`
    /// for the per-vendor order), `"native-vulkan"`, `"native-vaapi"`, `"native-d3d11va"`,
    /// or `"software"`.
    ///
    /// ⚠ A STORED value is not a validated one — this is a plain `String` read out of a
    /// user's settings file, and the pre-M10 spellings `"vulkan"`/`"vaapi"`/`"d3d11va"`
    /// (which every desktop Settings UI offered) named libavcodec's rungs, deleted at
    /// M10. `video::migrate_decoder_pref` maps each onto the native rung for the same
    /// hardware family, at `warn`, so an upgrade does not end a session over a dropdown
    /// the user picked long ago. Nothing rewrites the STORE — the value is migrated on
    /// every read, so downgrading to an older client still works.
    /// The `PUNKTFUNK_DECODER` env var overrides this (see `video::Decoder::new`).
    pub decoder: String,
    /// Decode/present GPU (multi-GPU boxes): the adapter's marketing name, as the WinUI
    /// shell's GPU picker stores it; empty = automatic. The session maps it onto the
    /// presenter's device pick (`PUNKTFUNK_VK_ADAPTER`). `default` so pre-existing
    /// stores (and the Linux shells, which have no picker yet) load.
    #[serde(default)]
    pub adapter: String,
    /// Ask the host for full-chroma **4:4:4** video (`quic::VIDEO_CAP_444`). Default off: it
    /// costs bandwidth and encode headroom, and only lands when everything lines up — HEVC,
    /// the host's own policy, and a GPU that can actually encode 4:4:4. It is what makes small
    /// text and thin UI lines crisp on a remote desktop, which is why this is a per-profile
    /// choice rather than a global one (a "Work" profile wants it; "Game" usually doesn't).
    #[serde(default)]
    pub enable_444: bool,
    /// Advertise 10-bit + HDR10 so the host upgrades HDR content to a Main10/PQ stream.
    /// The presenter handles the display side dynamically either way (HDR10 swapchain
    /// where offered, tonemap where not) — off means "never send me 10-bit".
    /// `default = true`: the Linux stores never carried this and always advertised.
    #[serde(default = "default_true")]
    pub hdr_enabled: bool,
    /// Presentation intent: `"latency"` (default) or `"smooth"` — the Apple/Android
    /// clients' shared `present_priority` profile key, resolved with
    /// [`PresentPriority::resolve`] (via [`Settings::present_priority`]). Anything
    /// unknown reads as latency, so a newer client's future value degrades safely.
    #[serde(default = "default_present_priority")]
    pub present_priority: String,
    /// Smoothness buffer size in frames: `0` = Automatic (resolves to 2), else 1–3.
    /// Only meaningful under `present_priority = "smooth"` (the shared `smooth_buffer`
    /// key). Each buffered frame absorbs about one refresh of jitter and adds one
    /// refresh of display latency.
    #[serde(default)]
    pub smooth_buffer: u8,
    /// Tear-free presentation (default ON = today's behavior: MAILBOX, FIFO fallback).
    /// Off asks for a tearing present mode (IMMEDIATE) for the lowest possible latch
    /// latency — best-effort: platforms/drivers without tearing silently stay tear-free
    /// and the active mode is visible in the detailed stats. The shared `vsync` profile
    /// key; the desktop default differs from macOS's (`false` there) deliberately —
    /// sync-off means something different on each platform, the key is the contract.
    #[serde(default = "default_true")]
    pub vsync: bool,
    /// Let a variable-refresh display follow the stream cadence: prefers the present
    /// mode that drives VRR panels directly when fullscreen. Inert on fixed-refresh
    /// displays (detection is measured from on-glass timestamps, not queried). The
    /// shared `allow_vrr` profile key. Default ON, like the Apple client.
    #[serde(default = "default_true")]
    pub allow_vrr: bool,
    /// Legacy on/off for the stats overlay — superseded by `stats_verbosity` but kept
    /// written in sync (`set_stats_verbosity`) so pre-tier binaries reading the same
    /// file keep working. `alias`: the pre-unification WinUI shell (≤ 0.8.4) persisted
    /// this as `show_hud`.
    #[serde(alias = "show_hud")]
    pub show_stats: bool,
    /// Stats overlay tier. `None` = a pre-tier store; resolve through
    /// [`Settings::stats_verbosity`], which falls back to `show_stats`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_verbosity: Option<StatsVerbosity>,
    /// Enter fullscreen when a stream starts (F11 / the controller chord / the top-edge
    /// header reveal exit it). Gaming-Mode launches (`--fullscreen`) fullscreen regardless.
    pub fullscreen_on_stream: bool,
    /// Which colour family the gamepad UI's living backdrop drifts through — the shared
    /// `ui_palette` key (`"violet"` = the brand default, then `oled`/`nebula`/`abyss`/
    /// `ember`/`moss`/`graphite`, then the six pale fields; see `pf-console-ui`'s palette
    /// table, and the Apple/Android clients' twins). Presentation only: nothing about a
    /// stream depends on it, which is why it is a device preference and never part of a
    /// settings profile. An unknown name reads as the default rather than erroring — a
    /// newer client may have shipped a palette this binary doesn't know.
    #[serde(default = "default_ui_palette")]
    pub ui_palette: String,
    /// Suppress the gamepad UI's decorative motion: the living backdrop freezes, screen
    /// transitions become a plain fade, entrances stop staggering, and refused moves keep
    /// their haptic but drop the recoil travel. Presentation only, exactly like
    /// [`ui_palette`](Self::ui_palette) — a device preference, never part of a settings
    /// profile.
    ///
    /// A console setting rather than a mirror of an OS one, because there is no
    /// system "reduce motion" SDL can read portably across Linux and Windows. It also
    /// doubles as the OLED-friendly mode: a frozen backdrop is a static image.
    /// `default` so pre-existing stores load with the full motion they have today.
    #[serde(default)]
    pub reduce_motion: bool,
    /// How the console's game library orders titles within a group: `""`/unknown (the
    /// host's own order — today's shelf, byte for byte), `"title"`, `"platform"` or
    /// `"store"`. See `pf-console-ui`'s `collate` module, which is the portable spec the
    /// Apple and Android ports implement.
    ///
    /// Presentation only, like [`ui_palette`](Self::ui_palette), so it is a device
    /// preference and never part of a settings profile. Parsed leniently — an unrecognized
    /// value is a newer client's key, and the right answer to one is the default shelf.
    #[serde(default)]
    pub library_sort: String,
    /// How the console's game library is arranged: `"shelf"` (the coverflow — the default,
    /// and unknown values read as it) or `"grid"`. Presentation only, same rules as
    /// [`library_sort`](Self::library_sort).
    #[serde(default)]
    pub library_view: String,
    /// Open a host's library on its COLLECTIONS — platforms and stores as tiles — instead of
    /// the whole shelf. Presentation only, same rules as [`library_sort`](Self::library_sort).
    ///
    /// Ignored by a library with fewer than two collections (see `pf-console-ui`'s
    /// `collate::worth_browsing`): a screen that opens onto a single tile is a press the user
    /// pays for nothing, so that library opens on its shelf whatever this says. Default off,
    /// like every key in this family — an existing install must not have the screen its
    /// deep links land on changed under it.
    #[serde(default)]
    pub library_collections: bool,
    /// Send Wake-on-LAN before connecting to a saved host and wait for it to boot (the
    /// Apple client's "Auto-wake on connect"). Default ON — that was the unconditional
    /// behavior before this became a setting. Off is for hosts reached over a VPN, where
    /// an offline-looking host is really just unreachable by broadcast and the wake +
    /// wait only adds a delay.
    #[serde(default = "default_true")]
    pub auto_wake: bool,
    /// Reverse the wheel/trackpad scroll direction sent to the host (the Apple client's
    /// "Invert scroll direction"). Default off = the host scrolls the way this machine does.
    #[serde(default)]
    pub invert_scroll: bool,
    /// Playback endpoint for stream audio — on Linux the PipeWire `node.name` the
    /// playback stream targets (`target.object`); on Windows the WASAPI `IMMDevice`
    /// endpoint id; empty = the OS default (the Apple client's Speaker picker). The
    /// session maps it onto `PUNKTFUNK_AUDIO_SINK`. A picked endpoint that's gone
    /// falls back to the default on both OSes.
    #[serde(default)]
    pub speaker_device: String,
    /// Capture endpoint for the mic uplink (same semantics as `speaker_device`;
    /// `PUNKTFUNK_AUDIO_SOURCE`).
    #[serde(default)]
    pub mic_device: String,
    /// Render the host's per-pad DualSense voice-coil haptics stream (the 0xD1 plane, kind 0)
    /// on a WIRED physical DualSense's own audio device (tier A — Bluetooth pads expose no
    /// audio device). Gates the `CLIENT_CAP_PAD_AUDIO` advertisement and the per-pad arrival
    /// capability bit; wire rumble is suppressed for a pad whose haptics stream is live (the
    /// stream carries the feedback — see `gamepad.rs`, the SDL disable-bit trap). Default ON:
    /// the capable-and-agreed negotiation means it changes nothing without a capable host AND
    /// a wired DS5. `default` so pre-existing stores load with it on.
    #[serde(default = "default_true")]
    pub pad_haptics: bool,
    /// Where the DualSense built-in-speaker stream (0xD1 kind 1) is rendered: `"pad"` (default
    /// — the physical pad's own speaker), `"mix"` (fold it into the main stream audio — a
    /// declared TODO that renders as `"off"` today; see `pad_audio::speaker_active`), or
    /// `"off"`. `default` so pre-existing stores load as `"pad"`.
    #[serde(default = "default_pad_speaker")]
    pub pad_speaker: String,
    /// Match-window resolution policy (design/midstream-resolution-resize.md D1): the
    /// stream mode follows the session window — the connect asks for the window's pixel
    /// size and a mid-session resize renegotiates the host's virtual display + encoder
    /// (`Reconfigure`), so windowed sessions stream native-resolution pixels instead of
    /// scaling. Overrides `width`/`height` while on; on fullscreen it degenerates to the
    /// display's native mode. Default off (Auto-native stays the shipped default until
    /// the per-backend validation matrix is green).
    pub match_window: bool,
    /// The session window's last logical size under `match_window`: the next launch
    /// opens its window at this size, so the first connect's mode already matches what
    /// the user will be looking at. `0` = never stored → the 1280×720 default.
    pub last_window_w: u32,
    pub last_window_h: u32,
    /// Settings keys this build doesn't model (a newer client's field), carried through a
    /// load→save round-trip untouched — [`crate::profiles::SettingsOverlay`]'s `extra`
    /// pattern extended to the globals. Without it, every whole-file writer of this store
    /// (two shells, the console settings screen, the session's resize callback, Decky)
    /// running as an OLDER binary silently drops what a newer one persisted. Empty on
    /// every existing store, and an empty map serializes to nothing, so files don't churn.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

fn default_codec() -> String {
    "auto".into()
}

/// The Opus plane — every session before the lossless one existed, and the one a store written by
/// an older client must load as. Named from `session` so the default and the menu's first row can
/// never be two different strings.
fn default_audio_format() -> String {
    crate::audio_format::AUDIO_FORMAT_OPUS.into()
}

fn default_auto() -> String {
    "auto".into()
}

fn default_touch_mode() -> String {
    "trackpad".into()
}

fn default_mouse_mode() -> String {
    "capture".into()
}

fn default_present_priority() -> String {
    "latency".into()
}

fn default_true() -> bool {
    true
}

fn default_ui_palette() -> String {
    "violet".into()
}

fn default_pad_speaker() -> String {
    "pad".into()
}

impl Settings {
    /// The stats-overlay tier, resolving pre-tier stores: an old `show_stats = false`
    /// reads as Off, everything else as Normal (≈ what the pre-tier overlay showed).
    pub fn stats_verbosity(&self) -> StatsVerbosity {
        self.stats_verbosity.unwrap_or(if self.show_stats {
            StatsVerbosity::Normal
        } else {
            StatsVerbosity::Off
        })
    }

    /// Set the tier, keeping the legacy `show_stats` bool coherent for pre-tier
    /// binaries that read the same settings file.
    pub fn set_stats_verbosity(&mut self, v: StatsVerbosity) {
        self.stats_verbosity = Some(v);
        self.show_stats = v != StatsVerbosity::Off;
    }

    /// The touch-input model for this session (parsed from the stored name).
    pub fn touch_mode(&self) -> TouchMode {
        TouchMode::from_name(&self.touch_mode)
    }

    pub fn mouse_mode(&self) -> MouseMode {
        MouseMode::from_name(&self.mouse_mode)
    }

    /// The presentation intent for this session (the resolved
    /// `present_priority` × `smooth_buffer` pair).
    pub fn present_priority(&self) -> PresentPriority {
        PresentPriority::resolve(&self.present_priority, self.smooth_buffer)
    }

    /// Whether raw system-button presses (guide + QAM) are forwarded to the host.
    /// `game_mode` = this client runs as the embedded Gaming-Mode stream (gamescope),
    /// where the local Steam UI reacts to the same physical buttons no matter what we
    /// do — auto keeps them local there and forwards everywhere else.
    pub fn system_buttons_forward(&self, game_mode: bool) -> bool {
        match self.system_buttons.as_str() {
            "forward" => true,
            "local" => false,
            _ => !game_mode,
        }
    }

    /// Whether the hold-Select guide gesture is armed ([`Settings::guide_gesture`]).
    /// Auto = on only under Gaming Mode, where it is the sole controller route to the
    /// host's guide once raw presses stay local.
    pub fn guide_gesture_enabled(&self, game_mode: bool) -> bool {
        match self.guide_gesture.as_str() {
            "on" => true,
            "off" => false,
            _ => game_mode,
        }
    }

    /// The `codec` setting as a `quic::CODEC_*` preference bit (`0` = auto).
    pub fn preferred_codec(&self) -> u8 {
        match self.codec.as_str() {
            "h264" | "avc" => punktfunk_core::quic::CODEC_H264,
            "hevc" | "h265" => punktfunk_core::quic::CODEC_HEVC,
            "av1" => punktfunk_core::quic::CODEC_AV1,
            // The wired-LAN wavelet codec: preference-only by design (resolve_codec never
            // auto-picks it), and harmless on a build/device that doesn't advertise the
            // bit — the ladder falls back to HEVC.
            "pyrowave" => punktfunk_core::quic::CODEC_PYROWAVE,
            _ => 0,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            width: 0,
            height: 0,
            refresh_hz: 0,
            bitrate_kbps: 0,
            render_scale: 1.0,
            gamepad: "auto".into(),
            gamepad_forwarding: true,
            forward_pad: String::new(),
            system_buttons: "auto".into(),
            guide_gesture: "auto".into(),
            compositor: "auto".into(),
            touch_mode: "trackpad".into(),
            mouse_mode: "capture".into(),
            inhibit_shortcuts: true,
            mic_enabled: false,
            echo_cancel: true,
            audio_channels: 2,
            audio_format: default_audio_format(),
            codec: "auto".into(),
            decoder: "auto".into(),
            adapter: String::new(),
            enable_444: false,
            hdr_enabled: true,
            present_priority: "latency".into(),
            smooth_buffer: 0,
            vsync: true,
            allow_vrr: true,
            show_stats: true,
            stats_verbosity: None,
            fullscreen_on_stream: true,
            ui_palette: default_ui_palette(),
            reduce_motion: false,
            library_sort: String::new(),
            library_view: String::new(),
            library_collections: false,
            auto_wake: true,
            invert_scroll: false,
            speaker_device: String::new(),
            mic_device: String::new(),
            pad_haptics: true,
            pad_speaker: "pad".into(),
            match_window: false,
            last_window_w: 0,
            last_window_h: 0,
            extra: BTreeMap::new(),
        }
    }
}

impl Settings {
    fn path() -> Result<PathBuf> {
        // The shell's settings file on each OS: the GTK shell's on Linux, the WinUI
        // shell's on Windows. The desktop shells AND the session binary's console
        // settings screen write it (load-modify-save per change — Gaming Mode has no
        // other editor); a plain `--connect` stream only ever reads.
        #[cfg(windows)]
        return Ok(config_dir()?.join("client-windows-settings.json"));
        #[cfg(not(windows))]
        Ok(config_dir()?.join("client-gtk-settings.json"))
    }

    pub fn load() -> Settings {
        Self::path()
            .map(|p| load_json_or_default(&p))
            .unwrap_or_default()
    }

    /// Fire-and-forget by design (a failed settings write must never take a stream down),
    /// but temp+rename: this file has five whole-file writers, and a torn one loads as
    /// `Default` — i.e. silently resets every setting the user has.
    pub fn save(&self) {
        let Ok(p) = Self::path() else { return };
        let _ = std::fs::create_dir_all(p.parent().unwrap());
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = write_atomic(&p, s.as_bytes());
        }
    }
}

/// The one settings resolver every front-end and the session binary go through
/// (design/client-settings-profiles.md §4.4/§4.6): global defaults, with the profile this
/// connect uses overlaid.
///
/// ```text
/// effective = overlay(profile).apply(global)
/// profile   = one-off override  ??  host binding  ??  none
/// ```
///
/// `one_off` is the "Connect with ▸ X" / `--profile` / `profile=` pick, by id or unique name;
/// `Some("")` forces the global defaults on a bound host. It never rebinds anything — the
/// host's default is changed only by an explicit act in the UI.
///
/// Nothing here fails: an unknown one-off falls back to the *defaults* (not to the host's
/// binding — a connect that was explicitly asked for "Work" must not silently run "Game"),
/// and a dangling binding resolves as none, exactly today's behavior. The host is looked up
/// by `addr:port`, the same match the per-host clipboard decision has always used —
/// consistency with the shipped precedent beats purity here (§4.6).
pub fn effective_settings(
    addr: &str,
    port: u16,
    one_off: Option<&str>,
) -> (Settings, Option<StreamProfile>) {
    let base = Settings::load();
    let catalog = ProfilesFile::load();
    let known = KnownHosts::load();
    let bound = known
        .find_by_addr(addr, port)
        .and_then(|h| h.profile_id.clone());

    match resolve_profile(&catalog, bound.as_deref(), one_off) {
        Some(p) => (p.overrides.apply(&base), Some(p)),
        None => (base, None),
    }
}

/// The profile half of [`effective_settings`], split out so the precedence rules are testable
/// without touching the config directory: one-off pick ?? host binding ?? none.
fn resolve_profile(
    catalog: &ProfilesFile,
    bound: Option<&str>,
    one_off: Option<&str>,
) -> Option<StreamProfile> {
    match one_off {
        // `--profile ""` — "Connect with ▸ Default settings" on a bound host.
        Some("") => None,
        Some(reference) => match catalog.resolve(reference) {
            (Some(p), _) => Some(p.clone()),
            (_, res) => {
                tracing::warn!(
                    profile = %reference,
                    ambiguous = res == Resolution::Ambiguous,
                    "no such settings profile — streaming with the default settings"
                );
                None
            }
        },
        // A binding is an id, never a name: it was written by a picker, and resolving it by
        // name would let renaming another profile hijack it. Dangling → the defaults.
        None => bound.and_then(|id| catalog.find_by_id(id).cloned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-hex fingerprint of one repeated digit — readable in an assertion, and distinct
    /// per letter, which is all the known-hosts tests need one to be.
    fn fp(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    /// WG add-before-connect stored every such host with an EMPTY fp, and host rows are
    /// keyed by fp — two never-connected hosts became one row (edit/forget hit the first).
    /// The repair must give each a unique pending id and leave real pins untouched.
    #[test]
    fn repair_pending_fps_uniques_empty_and_duplicate_fps() {
        let mut known = KnownHosts::default();
        let host = |addr: &str, port: u16, fp_hex: &str| KnownHost {
            name: addr.to_string(),
            addr: addr.to_string(),
            port,
            fp_hex: fp_hex.to_string(),
            ..Default::default()
        };
        known.hosts.push(host("10.0.0.1", 9777, ""));
        known.hosts.push(host("10.0.0.2", 9777, ""));
        known.hosts.push(host("10.0.0.3", 9777, &fp('a')));
        assert!(repair_pending_fps(&mut known));
        let fps: Vec<String> = known.hosts.iter().map(|h| h.fp_hex.clone()).collect();
        assert!(fps.iter().all(|f| !f.is_empty()));
        assert!(is_pending_fp(&fps[0]) && is_pending_fp(&fps[1]));
        assert_ne!(fps[0], fps[1]);
        assert_eq!(fps[2], fp('a'));
        // Idempotent: a second pass changes nothing.
        assert!(!repair_pending_fps(&mut known));
        // Pending fps are never real pins.
        assert!(parse_hex32(&fps[0]).is_none());
    }

    /// **A byte order mark must not silently erase every setting in the file.**
    ///
    /// PowerShell's `Set-Content -Encoding UTF8` writes one, so this is what a settings
    /// file edited from a Windows shell actually looks like on disk. `serde_json` refuses
    /// `EF BB BF` at byte 0, and the loader used to swallow that refusal and return
    /// `Default` — which on 2026-08-07 cost an hour: a `codec: "av1"` edit was ignored and
    /// the client negotiated HEVC, with the correct file open on screen. Nothing was
    /// logged, because there was nothing in the code to log it.
    ///
    /// Asserts the three cases together, because the middle one is the whole point: a BOM
    /// must LOAD, not merely fail loudly.
    #[test]
    fn a_bom_does_not_turn_a_settings_file_into_defaults() {
        let dir = std::env::temp_dir().join(format!(
            "pf-client-core-bom-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let body = r#"{"codec":"av1","bitrate_kbps":42000}"#;

        let plain = dir.join("plain.json");
        std::fs::write(&plain, body).unwrap();
        let s: Settings = load_json_or_default(&plain);
        assert_eq!(s.codec, "av1");
        assert_eq!(s.bitrate_kbps, 42000);

        // The same bytes with a UTF-8 BOM in front must load identically.
        let bom = dir.join("bom.json");
        std::fs::write(&bom, format!("\u{feff}{body}")).unwrap();
        let s: Settings = load_json_or_default(&bom);
        assert_eq!(s.codec, "av1", "a BOM must not discard the settings file");
        assert_eq!(s.bitrate_kbps, 42000);

        // Genuinely broken JSON still falls back to defaults (never an error — nothing
        // about streaming may hinge on this file), and a missing file is not a failure
        // at all, it is first run.
        let broken = dir.join("broken.json");
        std::fs::write(&broken, r#"{"codec":"av1",}"#).unwrap();
        let d: Settings = load_json_or_default(&broken);
        assert_eq!(d.codec, Settings::default().codec);
        let gone: Settings = load_json_or_default(&dir.join("nope.json"));
        assert_eq!(gone.codec, Settings::default().codec);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A settings file predating the touch-input model loads as `trackpad` (the shipped
    /// default), and the name round-trips through the enum both ways.
    #[test]
    fn settings_touch_mode_defaults_trackpad() {
        let old = r#"{"width":1280,"height":720,"gamepad":"auto","compositor":"auto"}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(s.touch_mode, "trackpad");
        assert_eq!(s.touch_mode(), TouchMode::Trackpad);
        // Explicit values parse; an unknown name falls back to trackpad.
        assert_eq!(TouchMode::from_name("pointer"), TouchMode::Pointer);
        assert_eq!(TouchMode::from_name("touch"), TouchMode::Touch);
        assert_eq!(TouchMode::from_name("bogus"), TouchMode::Trackpad);
        for m in TouchMode::ALL {
            assert_eq!(TouchMode::from_name(m.as_name()), m);
        }
    }

    /// A settings file predating the presentation cluster loads with the shipped
    /// defaults (latency intent, Automatic buffer, tear-free, VRR allowed), and the
    /// resolution rules match the Apple/Android reference: anything but an explicit
    /// `"smooth"` is latency, and a smooth buffer outside 1..=3 becomes 2.
    #[test]
    fn settings_presentation_defaults_and_resolution() {
        let old = r#"{"width":1280,"height":720,"gamepad":"auto","compositor":"auto"}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(s.present_priority, "latency");
        assert_eq!(s.smooth_buffer, 0);
        assert!(s.vsync);
        assert!(s.allow_vrr);
        assert_eq!(s.present_priority(), PresentPriority::Latency);

        assert_eq!(
            PresentPriority::resolve("smooth", 0),
            PresentPriority::Smooth { buffer: 2 },
            "Automatic resolves to 2"
        );
        assert_eq!(
            PresentPriority::resolve("smooth", 3),
            PresentPriority::Smooth { buffer: 3 }
        );
        assert_eq!(
            PresentPriority::resolve("smooth", 9),
            PresentPriority::Smooth { buffer: 2 },
            "out-of-range pins to the Automatic resolution"
        );
        assert_eq!(
            PresentPriority::resolve("balanced-from-the-future", 2),
            PresentPriority::Latency,
            "unknown intents degrade to latency"
        );
        assert_eq!(PresentPriority::Latency.fifo_capacity(), 0);
        assert_eq!(PresentPriority::Smooth { buffer: 3 }.fifo_capacity(), 3);
    }

    /// A pre-`forward_pad` settings file (≤ 0.5.0) loads with the pin on automatic.
    #[test]
    fn settings_forward_pad_defaults_empty() {
        let old = r#"{"width":1280,"height":720,"refresh_hz":60,"bitrate_kbps":0,
            "gamepad":"auto","compositor":"auto","inhibit_shortcuts":true,"mic_enabled":true}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(s.forward_pad, "");
        let round: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(round.forward_pad, "");
    }

    /// A pre-unification WinUI shell settings file (≤ 0.8.4, when the shell had its own
    /// `Settings` struct) still loads: `show_hud` migrates onto `show_stats` via the serde
    /// alias, the dropped `engine` knob is ignored, fields that file never carried
    /// (forward_pad, fullscreen_on_stream, …) default, and the D3D11VA-era
    /// `decoder: "hardware"` survives as-is (video::Decoder::new reads it as auto).
    #[test]
    fn settings_reads_winui_shell_shape() {
        let shell = r#"{
            "width": 2560, "height": 1440, "refresh_hz": 120, "bitrate_kbps": 20000,
            "gamepad": "dualsense", "compositor": "auto",
            "inhibit_shortcuts": true, "mic_enabled": true, "audio_channels": 6,
            "hdr_enabled": true, "decoder": "hardware", "codec": "av1",
            "adapter": "NVIDIA GeForce RTX 4080", "show_hud": false, "engine": "builtin"
        }"#;
        let s: Settings = serde_json::from_str(shell).unwrap();
        assert_eq!((s.width, s.height, s.refresh_hz), (2560, 1440, 120));
        assert_eq!(s.bitrate_kbps, 20000);
        assert_eq!(s.audio_channels, 6);
        assert!(s.mic_enabled);
        assert_eq!(s.decoder, "hardware");
        assert_eq!(s.preferred_codec(), punktfunk_core::quic::CODEC_AV1);
        let mut pw = s.clone();
        pw.codec = "pyrowave".into();
        assert_eq!(pw.preferred_codec(), punktfunk_core::quic::CODEC_PYROWAVE);
        assert_eq!(s.adapter, "NVIDIA GeForce RTX 4080");
        assert!(s.hdr_enabled);
        // The old shell's `show_hud` lands on `show_stats` (the user's preference survives).
        assert!(!s.show_stats);
        // Fields the old file doesn't carry take this struct's defaults.
        assert_eq!(s.forward_pad, "");
        assert!(s.fullscreen_on_stream);
        // Echo cancellation post-dates every stored file: it must load ON, or an upgrade
        // would silently turn a user's echo protection off.
        assert!(s.echo_cancel);
    }

    /// A key this build doesn't model (a newer client's setting) survives a load→save
    /// round trip instead of being dropped by the next whole-file write — the same
    /// contract `SettingsOverlay.extra` gives profiles. And when there are no unknown
    /// keys, the flatten map adds nothing, so existing files don't churn.
    #[test]
    fn settings_unknown_keys_survive_round_trip() {
        let newer = r#"{"width":1920,"height":1080,"frob_mode":"fancy","frob_level":3}"#;
        let s: Settings = serde_json::from_str(newer).unwrap();
        assert_eq!((s.width, s.height), (1920, 1080));
        assert_eq!(
            s.extra.get("frob_mode").and_then(|v| v.as_str()),
            Some("fancy")
        );
        let out = serde_json::to_string(&s).unwrap();
        assert!(out.contains(r#""frob_mode":"fancy""#), "{out}");
        assert!(out.contains(r#""frob_level":3"#), "{out}");
        // No unknown keys → no artifact of the passthrough field in the file.
        let plain = serde_json::to_string(&Settings::default()).unwrap();
        assert!(!plain.contains("extra"), "{plain}");
        assert!(!plain.contains("frob"), "{plain}");
    }

    /// The same contract seen from the other side: a key this build RETIRED. `library_enabled`
    /// gated "Browse library…" in the GTK and WinUI shells and defaulted off, so dropping the
    /// field is what finally shows the library to everyone who never found the toggle. The
    /// stored `false` must not fail the load — that would lock a user out of their whole
    /// settings file over a setting that no longer exists — and it must survive the next
    /// whole-file write, so a downgrade still reads the value it wrote.
    #[test]
    fn settings_retired_library_key_loads_and_survives() {
        let stored = r#"{"width":1920,"height":1080,"library_enabled":false}"#;
        let s: Settings = serde_json::from_str(stored).unwrap();
        assert_eq!((s.width, s.height), (1920, 1080));
        assert_eq!(
            s.extra.get("library_enabled").and_then(|v| v.as_bool()),
            Some(false)
        );
        let out = serde_json::to_string(&s).unwrap();
        assert!(out.contains(r#""library_enabled":false"#), "{out}");
    }

    /// Stats-tier resolution: a pre-tier store falls back to `show_stats` (off → Off,
    /// on/absent → Normal), an explicit tier wins, and setting a tier keeps the legacy
    /// bool in sync so pre-tier binaries reading the same file agree on off vs on.
    #[test]
    fn stats_verbosity_migrates_and_round_trips() {
        let mut s: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(s.stats_verbosity(), StatsVerbosity::Normal);
        let off: Settings = serde_json::from_str(r#"{"show_stats":false}"#).unwrap();
        assert_eq!(off.stats_verbosity(), StatsVerbosity::Off);

        s.set_stats_verbosity(StatsVerbosity::Compact);
        assert!(s.show_stats);
        s.set_stats_verbosity(StatsVerbosity::Off);
        assert!(!s.show_stats);

        s.set_stats_verbosity(StatsVerbosity::Detailed);
        let round: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(round.stats_verbosity(), StatsVerbosity::Detailed);
        // The tier serializes lowercase — the file stays human-readable.
        assert!(serde_json::to_string(&s).unwrap().contains("\"detailed\""));
    }

    /// The WinUI shell's known-hosts shape (no `last_used` field) loads losslessly — same
    /// filename, same directory, so on Windows the two clients genuinely share the store.
    #[test]
    fn known_hosts_reads_winui_shell_shape() {
        let shell = r#"{"hosts":[{
            "name": "Gaming PC", "addr": "192.168.1.50", "port": 9777,
            "fp_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "paired": true, "mac": ["aa:bb:cc:dd:ee:ff"]
        }]}"#;
        let k: KnownHosts = serde_json::from_str(shell).unwrap();
        let h = k.find_by_addr("192.168.1.50", 9777).unwrap();
        assert!(h.paired);
        assert_eq!(h.last_used, None);
        assert_eq!(h.mac, vec!["aa:bb:cc:dd:ee:ff".to_string()]);
        assert!(parse_hex32(&h.fp_hex).is_some());
        // A store predating the `os` field loads with it empty, and serializes back without
        // the key (an older client reading the same file sees exactly what it wrote).
        assert_eq!(h.os, "");
        assert!(!serde_json::to_string(&k).unwrap().contains("\"os\""));
    }

    /// The learned OS chain round-trips, and an absent key stays absent — the same
    /// back-compat contract as every late `KnownHost` field.
    #[test]
    fn known_hosts_os_chain_round_trips() {
        let k = KnownHosts {
            hosts: vec![KnownHost {
                name: "HTPC".into(),
                addr: "192.168.1.181".into(),
                port: 9777,
                os: "linux/fedora/bazzite".into(),
                ..Default::default()
            }],
        };
        let text = serde_json::to_string(&k).unwrap();
        let back: KnownHosts = serde_json::from_str(&text).unwrap();
        assert_eq!(back.hosts[0].os, "linux/fedora/bazzite");
    }

    /// A pre-profiles known-hosts file loads unchanged — no binding, no pins — and its
    /// records serialize back without the new keys, so an older client reading the same file
    /// sees exactly what it wrote. The id is minted only when `load()` runs (the migration
    /// step), not by deserialization.
    #[test]
    fn known_hosts_migration_is_a_no_op_on_a_pre_profiles_store() {
        let old = r#"{"hosts":[{
            "name": "Gaming PC", "addr": "192.168.1.50", "port": 9777,
            "fp_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "paired": true, "clipboard_sync": true
        }]}"#;
        let mut k: KnownHosts = serde_json::from_str(old).unwrap();
        let h = &k.hosts[0];
        assert_eq!(h.profile_id, None);
        assert!(h.pinned_profiles.is_empty());
        assert_eq!(h.id, None);
        assert!(h.clipboard_sync);
        let text = serde_json::to_string(&k).unwrap();
        assert!(!text.contains("profile_id"));
        assert!(!text.contains("pinned_profiles"));
        assert!(!text.contains("\"id\""));

        // Minting is idempotent: the second pass reports nothing to persist and leaves the
        // id it handed out alone.
        assert!(k.mint_missing_ids());
        let minted = k.hosts[0].id.clone().unwrap();
        assert_eq!(minted.len(), 36);
        assert!(!k.mint_missing_ids());
        assert_eq!(k.hosts[0].id.as_deref(), Some(minted.as_str()));
        // An empty-string id (a hand-edited store) counts as missing, not as an identity.
        k.hosts[0].id = Some(String::new());
        assert!(k.mint_missing_ids());
        assert_ne!(k.hosts[0].id.as_deref(), Some(""));
    }

    /// `upsert` refreshes what a reconnect actually knows and preserves what the user set:
    /// the profile binding, the pinned cards, the clipboard decision and the stable id all
    /// survive a trust-decision upsert that carries none of them (the bug `clipboard_sync`
    /// only ever avoided by accident).
    #[test]
    fn upsert_preserves_user_set_host_state() {
        let fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut k = KnownHosts {
            hosts: vec![KnownHost {
                name: "Desk".into(),
                addr: "192.168.1.50".into(),
                port: 9777,
                fp_hex: fp.into(),
                paired: true,
                last_used: Some(1000),
                mac: vec!["aa:bb:cc:dd:ee:ff".into()],
                os: "linux/fedora/bazzite".into(),
                // Deliberately NOT 47990: a host that moved its mgmt port is the case this field
                // exists for, so the default would make the assertions below pass vacuously.
                mgmt_port: Some(47991),
                clipboard_sync: true,
                profile_id: Some("aaaaaaaaaaaa".into()),
                pinned_profiles: vec!["bbbbbbbbbbbb".into()],
                id: Some("11111111-2222-4333-8444-555555555555".into()),
                wg: None,
            }],
        };
        // What `persist_host` builds: a trust decision, nothing else.
        k.upsert(KnownHost {
            name: "Desk".into(),
            addr: "192.168.1.51".into(), // new lease
            port: 9777,
            fp_hex: fp.into(),
            paired: false, // must not demote
            ..Default::default()
        });
        let h = &k.hosts[0];
        assert_eq!(k.hosts.len(), 1);
        assert_eq!(h.addr, "192.168.1.51");
        assert!(h.paired);
        assert_eq!(h.last_used, Some(1000));
        assert_eq!(h.mac, vec!["aa:bb:cc:dd:ee:ff".to_string()]);
        // The learned OS chain rides the same rule as `mac`: a carrier-less upsert keeps it.
        assert_eq!(h.os, "linux/fedora/bazzite");
        // And the learned mgmt port. If a reconnect could reset this to None the host would fall
        // back to 47990 and its library would 404 — the exact regression this rule prevents.
        assert_eq!(h.mgmt_port, Some(47991));
        assert!(h.clipboard_sync);
        assert_eq!(h.profile_id.as_deref(), Some("aaaaaaaaaaaa"));
        assert_eq!(h.pinned_profiles, vec!["bbbbbbbbbbbb".to_string()]);
        assert_eq!(
            h.id.as_deref(),
            Some("11111111-2222-4333-8444-555555555555")
        );

        // A carried value does move the binding (that is how the UI rebinds through upsert).
        k.upsert(KnownHost {
            fp_hex: fp.into(),
            profile_id: Some("cccccccccccc".into()),
            pinned_profiles: vec!["dddddddddddd".into()],
            ..Default::default()
        });
        assert_eq!(k.hosts[0].profile_id.as_deref(), Some("cccccccccccc"));
        assert_eq!(k.hosts[0].pinned_profiles, vec!["dddddddddddd".to_string()]);
    }

    /// The mgmt port a host advertises has to OUTLIVE the advert: a store written before the field
    /// existed must load, resolve to 47990, and then take and keep a learned value. Without the
    /// middle rung a host moved off 47990 (to share a box with a Sunshine fork, whose web UI owns
    /// that port) served its library on the LAN and nowhere else — over a VPN or a routed subnet
    /// there is no advert to read and the client silently went back to a dead port.
    #[test]
    fn mgmt_port_survives_a_store_that_predates_it_and_then_persists() {
        // A store written before the field existed: no `mgmt_port` key at all.
        let old = r#"{"hosts":[{
            "name": "Gaming PC", "addr": "192.168.1.50", "port": 9777,
            "fp_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "paired": true
        }]}"#;
        let mut k: KnownHosts = serde_json::from_str(old).unwrap();
        assert_eq!(k.hosts[0].mgmt_port, None, "absent key decodes to None");
        assert_eq!(
            k.hosts[0].effective_mgmt_port(),
            crate::library::DEFAULT_MGMT_PORT,
            "unknown resolves to the compiled-in default, i.e. today's behaviour"
        );
        // Unset stays out of the serialized form, so an untouched store is byte-stable.
        assert!(!serde_json::to_string(&k).unwrap().contains("mgmt_port"));

        // Learning one (what a discovery tick does) takes effect and round-trips.
        k.hosts[0].mgmt_port = Some(47991);
        assert_eq!(k.hosts[0].effective_mgmt_port(), 47991);
        let round: KnownHosts = serde_json::from_str(&serde_json::to_string(&k).unwrap()).unwrap();
        assert_eq!(round.hosts[0].mgmt_port, Some(47991));

        // A re-key carries it onto the surviving record — otherwise a host that regenerated its
        // identity would silently drop back to 47990.
        let fresh = fp('a');
        let mut k2 = k;
        k2.upsert_trusted(KnownHost {
            name: "Gaming PC".into(),
            addr: "192.168.1.50".into(),
            port: 9777,
            fp_hex: fresh.clone(),
            paired: true,
            ..Default::default()
        });
        let kept = k2.hosts.iter().find(|h| h.fp_hex == fresh).unwrap();
        assert_eq!(kept.mgmt_port, Some(47991), "re-key must not lose the port");
    }

    /// A host that regenerated its identity (reinstall, wiped ProgramData, re-key) ends up with
    /// ONE record for its address — the live one. This is the `.173` lockout: `upsert` keys on
    /// the fingerprint, so the re-paired host used to be appended beside the dead record, and
    /// every later connect pinned the dead one — forever, re-pairing included.
    #[test]
    fn upsert_trusted_supersedes_a_rekeyed_host() {
        let (dead, live) = (fp('c'), fp('a'));
        let mut k = KnownHosts {
            hosts: vec![KnownHost {
                name: "ENRICOS-DESKTOP (local)".into(),
                addr: "127.0.0.1".into(),
                port: 9777,
                fp_hex: dead.clone(),
                paired: true,
                last_used: Some(1000),
                mac: vec!["aa:bb:cc:dd:ee:ff".into()],
                os: "windows".into(),
                mgmt_port: Some(47991),
                clipboard_sync: true,
                profile_id: Some("aaaaaaaaaaaa".into()),
                pinned_profiles: vec!["bbbbbbbbbbbb".into()],
                id: Some("11111111-2222-4333-8444-555555555555".into()),
                wg: None,
            }],
        };
        // The re-pair: same box, same address, a certificate the client has never seen.
        k.upsert_trusted(KnownHost {
            name: "127.0.0.1".into(),
            addr: "127.0.0.1".into(),
            port: 9777,
            fp_hex: live.clone(),
            paired: true,
            ..Default::default()
        });
        assert_eq!(k.hosts.len(), 1);
        let h = &k.hosts[0];
        assert_eq!(h.fp_hex, live);
        // …and the address now resolves to the live pin, which is the whole bug.
        assert_eq!(k.find_by_addr("127.0.0.1", 9777).unwrap().fp_hex, live);
        assert!(k.find_by_fp(&dead).is_none());
        // What describes the BOX rides along, so a reinstall doesn't cost the user their setup.
        assert_eq!(h.mac, vec!["aa:bb:cc:dd:ee:ff".to_string()]);
        assert_eq!(h.os, "windows");
        // The mgmt port describes the BOX, not the retired certificate: a reinstall must not send
        // the library back to 47990 on a host that serves it somewhere else.
        assert_eq!(h.mgmt_port, Some(47991));
        assert_eq!(h.profile_id.as_deref(), Some("aaaaaaaaaaaa"));
        assert_eq!(h.pinned_profiles, vec!["bbbbbbbbbbbb".to_string()]);
        assert_eq!(h.last_used, Some(1000));
        // What described the dead IDENTITY does not: the clipboard grant is a decision about
        // one certificate, and the retired record's stable id must not follow a new one.
        assert!(!h.clipboard_sync);
        assert_ne!(
            h.id.as_deref(),
            Some("11111111-2222-4333-8444-555555555555")
        );
    }

    /// The case fingerprint-keying exists for still works through the trusted path: a host that
    /// only MOVED keeps its one record, its `paired` bit and everything the user set on it —
    /// including the clipboard grant and the stable id, which a same-identity re-pair must not
    /// disturb (that would be the fix trading one silent reset for another).
    #[test]
    fn upsert_trusted_keeps_a_host_that_only_moved_address() {
        let same = fp('a');
        let mut k = KnownHosts {
            hosts: vec![KnownHost {
                name: "Desk".into(),
                addr: "192.168.1.50".into(),
                port: 9777,
                fp_hex: same.clone(),
                paired: true,
                clipboard_sync: true,
                profile_id: Some("aaaaaaaaaaaa".into()),
                id: Some("11111111-2222-4333-8444-555555555555".into()),
                ..Default::default()
            }],
        };
        k.upsert_trusted(KnownHost {
            name: "Desk".into(),
            addr: "192.168.1.51".into(),
            port: 9777,
            fp_hex: same.clone(),
            paired: false, // must not demote
            ..Default::default()
        });
        assert_eq!(k.hosts.len(), 1);
        let h = &k.hosts[0];
        assert_eq!(h.addr, "192.168.1.51");
        assert!(h.paired);
        assert!(h.clipboard_sync);
        assert_eq!(h.profile_id.as_deref(), Some("aaaaaaaaaaaa"));
        assert_eq!(
            h.id.as_deref(),
            Some("11111111-2222-4333-8444-555555555555")
        );
    }

    /// Superseding is scoped to the address the decision was made for, and only ever runs off
    /// one: a trust decision for `.51` leaves a different host saved at `.50` alone, and an
    /// fp-less save (a manual entry, `--add-host` without `--fp`) retires nothing at all — it
    /// carries no identity to supersede anything WITH.
    #[test]
    fn upsert_trusted_leaves_other_addresses_and_placeholders_alone() {
        let mut k = KnownHosts {
            hosts: vec![
                KnownHost {
                    name: "Other box".into(),
                    addr: "192.168.1.50".into(),
                    port: 9777,
                    fp_hex: fp('c'),
                    paired: true,
                    ..Default::default()
                },
                // Same address, DIFFERENT port: a distinct endpoint, not a duplicate.
                KnownHost {
                    name: "Second host".into(),
                    addr: "192.168.1.51".into(),
                    port: 9778,
                    fp_hex: fp('d'),
                    paired: true,
                    ..Default::default()
                },
            ],
        };
        k.upsert_trusted(KnownHost {
            name: "New box".into(),
            addr: "192.168.1.51".into(),
            port: 9777,
            fp_hex: fp('a'),
            paired: true,
            ..Default::default()
        });
        assert_eq!(k.hosts.len(), 3);
        assert_eq!(
            k.find_by_addr("192.168.1.50", 9777).unwrap().fp_hex,
            fp('c')
        );
        assert_eq!(
            k.find_by_addr("192.168.1.51", 9778).unwrap().fp_hex,
            fp('d')
        );

        // An fp-less save alongside a real record: nothing is retired, and the address still
        // resolves to the record that HAS a pin.
        k.upsert_trusted(KnownHost {
            name: "Typed by hand".into(),
            addr: "192.168.1.50".into(),
            port: 9777,
            ..Default::default()
        });
        assert_eq!(k.hosts.len(), 4);
        assert_eq!(
            k.find_by_addr("192.168.1.50", 9777).unwrap().fp_hex,
            fp('c')
        );
    }

    /// A store that ALREADY holds the duplicate (every client shipped so far can have written
    /// one) connects again on the next connect, before any re-pair: an address resolves to the
    /// newest trust decision for it, not to whichever record happens to sit first in the file.
    /// Nothing is deleted at load — which record is live isn't knowable there, and guessing
    /// wrong would throw away the good one; the retirement waits for the next trust decision.
    #[test]
    fn a_duplicated_store_resolves_to_the_newest_record() {
        let (dead, live) = (fp('c'), fp('a'));
        let mut k = KnownHosts {
            hosts: vec![
                KnownHost {
                    name: "ENRICOS-DESKTOP (local)".into(),
                    addr: "127.0.0.1".into(),
                    port: 9777,
                    fp_hex: dead.clone(),
                    paired: true,
                    last_used: Some(9999), // the stale record is the one that HAS connected
                    ..Default::default()
                },
                KnownHost {
                    name: "127.0.0.1".into(),
                    addr: "127.0.0.1".into(),
                    port: 9777,
                    fp_hex: live.clone(),
                    paired: true,
                    ..Default::default()
                },
            ],
        };
        assert_eq!(k.find_by_addr("127.0.0.1", 9777).unwrap().fp_hex, live);
        // Loading is non-destructive: both records are still there to be looked up by pin.
        assert!(k.find_by_fp(&dead).is_some());
        // A placeholder appended later never displaces a real pin.
        k.hosts.push(KnownHost {
            addr: "127.0.0.1".into(),
            port: 9777,
            ..Default::default()
        });
        assert_eq!(k.find_by_addr("127.0.0.1", 9777).unwrap().fp_hex, live);
        // …and the next trust decision cleans the store up.
        k.upsert_trusted(KnownHost {
            name: "127.0.0.1".into(),
            addr: "127.0.0.1".into(),
            port: 9777,
            fp_hex: live.clone(),
            paired: true,
            ..Default::default()
        });
        assert_eq!(k.hosts.len(), 1);
        assert_eq!(k.hosts[0].fp_hex, live);
    }

    /// An advert's learned MAC/OS lands on the record it identified, not on a stale namesake
    /// at the same address that merely came first in the file.
    #[test]
    fn learn_target_prefers_the_fingerprint_match() {
        let (dead, live) = (fp('c'), fp('a'));
        let mut k = KnownHosts {
            hosts: vec![
                KnownHost {
                    addr: "127.0.0.1".into(),
                    port: 9777,
                    fp_hex: dead.clone(),
                    ..Default::default()
                },
                KnownHost {
                    addr: "127.0.0.1".into(),
                    port: 9777,
                    fp_hex: live.clone(),
                    ..Default::default()
                },
            ],
        };
        learn_target(&mut k, &live, "127.0.0.1", 9777).unwrap().os = "windows".into();
        assert_eq!(k.find_by_fp(&live).unwrap().os, "windows");
        assert_eq!(k.find_by_fp(&dead).unwrap().os, "");
        // No fingerprint to go on (an advert that carries none) → the address's own answer.
        learn_target(&mut k, "", "127.0.0.1", 9777).unwrap().os = "linux".into();
        assert_eq!(k.find_by_fp(&live).unwrap().os, "linux");
        assert_eq!(k.find_by_fp(&dead).unwrap().os, "");
        // An advert for a host this store has never seen writes nothing.
        assert!(learn_target(&mut k, &fp('e'), "10.0.0.9", 9777).is_none());
    }

    /// What an advert carries lands on the record; what it omits is left alone; and a repeat of
    /// the same advert reports no change — which is what lets every surface call this on every
    /// discovery tick without churning the store.
    #[test]
    fn apply_advert_learns_what_it_carries_and_keeps_what_it_omits() {
        let mut h = KnownHost::default();
        let mac = vec!["aa:bb:cc:dd:ee:ff".to_string()];
        assert!(apply_advert(&mut h, &mac, "linux/arch", Some(47991)));
        assert_eq!(h.mac, mac);
        assert_eq!(h.os, "linux/arch");
        assert_eq!(h.mgmt_port, Some(47991));
        // The same advert a tick later: nothing moved, so there is nothing to persist.
        assert!(!apply_advert(&mut h, &mac, "linux/arch", Some(47991)));
        // An older host advertises none of the three. Clearing a learned MAC here is exactly what
        // would cost the user their wake, so an absent field must never overwrite a known one.
        assert!(!apply_advert(&mut h, &[], "", None));
        assert_eq!(h.mac, mac);
        assert_eq!(h.os, "linux/arch");
        assert_eq!(h.mgmt_port, Some(47991));
        // 0 is how "not advertised" reaches us from a consumer that has no Option — not a port.
        assert!(!apply_advert(&mut h, &[], "", Some(0)));
        assert_eq!(h.mgmt_port, Some(47991));
        // A host that genuinely moved: the new value wins.
        assert!(apply_advert(&mut h, &[], "", Some(47992)));
        assert_eq!(h.mgmt_port, Some(47992));
    }

    /// Pins render in card order, deduplicated, with deleted profiles simply gone — a pin is
    /// presentation state, so a dangling one is never an error surface.
    #[test]
    fn resolved_pins_drop_duplicates_and_dangling_ids() {
        use crate::profiles::{ProfilesFile, StreamProfile};
        let catalog = ProfilesFile {
            version: 1,
            profiles: vec![
                StreamProfile {
                    id: "aaaaaaaaaaaa".into(),
                    name: "Work".into(),
                    ..StreamProfile::new("")
                },
                StreamProfile {
                    id: "bbbbbbbbbbbb".into(),
                    name: "Game".into(),
                    ..StreamProfile::new("")
                },
            ],
        };
        let h = KnownHost {
            pinned_profiles: vec![
                "bbbbbbbbbbbb".into(),
                "deleted00000".into(),
                "bbbbbbbbbbbb".into(),
                "aaaaaaaaaaaa".into(),
            ],
            ..Default::default()
        };
        let names: Vec<&str> = h
            .resolved_pins(&catalog)
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, vec!["Game", "Work"]);
        assert!(KnownHost::default().resolved_pins(&catalog).is_empty());
    }

    /// The connect-time precedence: a one-off pick beats the host's binding, `""` forces the
    /// defaults, a dangling binding resolves as none, and a one-off that can't be honored
    /// falls back to the DEFAULTS rather than to the host's own profile — "connect with Work"
    /// must never quietly run "Game".
    #[test]
    fn profile_resolution_precedence() {
        use crate::profiles::{ProfilesFile, StreamProfile};
        let catalog = ProfilesFile {
            version: 1,
            profiles: vec![
                StreamProfile {
                    id: "aaaaaaaaaaaa".into(),
                    name: "Game".into(),
                    ..StreamProfile::new("")
                },
                StreamProfile {
                    id: "bbbbbbbbbbbb".into(),
                    name: "Work".into(),
                    ..StreamProfile::new("")
                },
                StreamProfile {
                    id: "cccccccccccc".into(),
                    name: "work".into(),
                    ..StreamProfile::new("")
                },
            ],
        };
        let name_of = |p: Option<StreamProfile>| p.map(|p| p.name);

        // No binding, no pick: today's behavior.
        assert_eq!(resolve_profile(&catalog, None, None), None);
        // The binding drives a plain connect…
        assert_eq!(
            name_of(resolve_profile(&catalog, Some("aaaaaaaaaaaa"), None)),
            Some("Game".into())
        );
        // …a one-off overrides it, by id or by unique name…
        assert_eq!(
            name_of(resolve_profile(
                &catalog,
                Some("aaaaaaaaaaaa"),
                Some("bbbbbbbbbbbb")
            )),
            Some("Work".into())
        );
        assert_eq!(
            name_of(resolve_profile(&catalog, None, Some("GAME"))),
            Some("Game".into())
        );
        // …and `""` forces the defaults on a bound host.
        assert_eq!(
            resolve_profile(&catalog, Some("aaaaaaaaaaaa"), Some("")),
            None
        );
        // A deleted binding is not an error, it is "no profile".
        assert_eq!(resolve_profile(&catalog, Some("deleted00000"), None), None);
        // Unknown and ambiguous one-offs fall back to the defaults, NOT to the binding.
        assert_eq!(
            resolve_profile(&catalog, Some("aaaaaaaaaaaa"), Some("nope")),
            None
        );
        assert_eq!(
            resolve_profile(&catalog, Some("aaaaaaaaaaaa"), Some("work")),
            None
        );
        // A binding resolves by id only — a profile NAMED like the bound id doesn't hijack it.
        assert_eq!(resolve_profile(&catalog, Some("Game"), None), None);
    }

    /// The atomic write replaces the target in one step and leaves no temp behind — the
    /// discipline all three client stores now share.
    #[test]
    fn write_atomic_replaces_and_cleans_up() {
        let _guard = store_health_lock();
        let dir = std::env::temp_dir().join(format!(
            "pf-client-core-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("store.json");
        write_atomic(&p, b"{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"a\":1}");
        write_atomic(&p, b"{\"a\":2}").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"a\":2}");
        assert!(!temp_sibling(&p).exists());
        // Nothing else in the directory either — the scratch file is gone, not renamed aside.
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("store.json")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `store_health` is process-global, so the two tests that read it must not run at the same
    /// time — one's successful write clears the other's recorded failure. Nothing else in the
    /// crate's tests reaches `write_atomic`, so this lock is the whole serialization needed.
    fn store_health_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Two processes saving at once must not share one scratch file — the pid keeps them apart.
    /// (Same-process, so this only proves the name varies with the pid, not the interleaving.)
    #[test]
    fn temp_sibling_is_per_process_and_a_sibling() {
        let p = Path::new("/tmp/pf/client-windows-settings.json");
        let t = temp_sibling(p);
        assert_eq!(t.parent(), p.parent());
        assert_eq!(
            t.file_name().unwrap().to_str().unwrap(),
            format!("client-windows-settings.json.tmp-{}", std::process::id())
        );
        // Must not collide with the store itself, nor look like one to `load()`.
        assert_ne!(t, p.to_path_buf());
    }

    /// **The fix itself.** When the temp+rename route is unavailable, the bytes must still
    /// reach the target — that is the difference between the field's "read-only mode" and a
    /// working client. Simulated by parking a DIRECTORY on the (deterministic) temp sibling
    /// path so the temp leg cannot be written; the field's install fails one step later, at
    /// the rename, but both funnel into the same fallback, which is what this pins.
    #[test]
    fn the_atomic_route_failing_falls_back_to_an_in_place_write() {
        let _guard = store_health_lock();
        let dir = std::env::temp_dir().join(format!(
            "pf-client-core-inplace-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("store.json");
        std::fs::write(&p, b"{\"old\":true}").unwrap();

        // Block the scratch path, so the atomic route cannot complete.
        std::fs::create_dir_all(temp_sibling(&p)).unwrap();
        assert!(temp_sibling(&p).is_dir());

        // The write must still report success AND actually be readable back — a silent
        // `Ok(())` that lost the bytes is the bug, not the fix.
        write_atomic(&p, b"{\"new\":true}").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"new\":true}");
        // Degraded, but not broken: nothing to warn the user about.
        assert_eq!(store_health::last_error(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other end: when the in-place fallback ALSO fails, the error must surface rather
    /// than be swallowed, because at that point nothing the user does on the page will stick.
    #[test]
    fn a_failed_rename_still_persists_the_write() {
        let _guard = store_health_lock();
        let dir = std::env::temp_dir().join(format!(
            "pf-client-core-fallback-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Sanity: the healthy path reports a healthy store.
        let ok = dir.join("store.json");
        write_atomic(&ok, b"{}").unwrap();
        assert_eq!(store_health::last_error(), None);

        // Now the unwritable case: a directory in the target's place defeats BOTH the rename
        // and the in-place write, so the error must surface instead of being swallowed.
        let blocked = dir.join("blocked.json");
        std::fs::create_dir_all(&blocked).unwrap();
        std::fs::write(blocked.join("occupant"), b"x").unwrap();
        assert!(write_atomic(&blocked, b"{\"a\":1}").is_err());
        let reported = store_health::last_error().expect("an unwritable store must be reported");
        assert!(
            reported.contains("blocked.json"),
            "the report names the store: {reported}"
        );
        // No scratch file left behind by the failed attempt.
        assert!(!temp_sibling(&blocked).exists());

        // And a later success clears it, so the UI stops warning once the store recovers.
        write_atomic(&ok, b"{\"a\":2}").unwrap();
        assert_eq!(store_health::last_error(), None);
        assert_eq!(std::fs::read_to_string(&ok).unwrap(), "{\"a\":2}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
