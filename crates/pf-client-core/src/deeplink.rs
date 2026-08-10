//! The `punktfunk://` URL grammar — one parser/emitter for Linux, Windows, the session and
//! the CLI (design/client-deep-links.md §2). Swift (`PunktfunkShared/DeepLink.swift`) and
//! Kotlin keep their own ports; all three are held together by the shared vector file
//! `clients/shared/deeplink-vectors.json`, which this module's tests consume verbatim.
//!
//! ```text
//! punktfunk://connect/<host-ref>[?fp=<64-hex>][&host=<addr[:port]>][&launch=<id>]
//!                               [&profile=<ref>][&name=<label>]
//! ```
//!
//! The invariant the grammar exists to keep: **a URL may only ever do what a click on an
//! existing card could do, minus trust decisions.** So it carries *references* to things that
//! already exist on this device — a host record, a settings profile, a library id — and never
//! values: no resolution, no bitrate, no codec. A web page must not be able to shape a
//! session beyond picking among the user's own configurations. `pair` is deliberately not a
//! route and never will be; pairing stays an interactive ceremony.
//!
//! `pf://` parses as an alias so a hand-typed or legacy link still works, but nothing ever
//! *emits* or registers it (§2: claiming a two-letter scheme on MSIX/Apple is unconditional
//! squatting, and a link that resolves on one platform only is a trap).

use crate::trust::{KnownHost, KnownHosts};

/// Hostile-input caps (§8). The total is generous for a real link and small enough that a
/// pasted megabyte never reaches the decoder.
pub const MAX_URL_LEN: usize = 2048;
pub const MAX_HOST_REF_LEN: usize = 128;
pub const MAX_LAUNCH_LEN: usize = 128;
pub const MAX_PROFILE_LEN: usize = 64;
pub const MAX_NAME_LEN: usize = 64;

/// The default native port, as everywhere else in the clients.
pub const DEFAULT_PORT: u16 = 9777;

/// What the URL asks for. `Wake`/`Browse` are reserved in the grammar and parse today; a
/// front-end that hasn't implemented them refuses with a notice rather than silently
/// connecting — the grammar is the contract, per-platform support is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Route {
    /// The default, and the only route an emitter builds today.
    #[default]
    Connect,
    Wake,
    Browse,
}

impl Route {
    pub fn as_str(self) -> &'static str {
        match self {
            Route::Connect => "connect",
            Route::Wake => "wake",
            Route::Browse => "browse",
        }
    }
}

/// A parsed, validated link. Every field is already length- and charset-checked, so a
/// consumer never has to re-validate hostile input; what it still has to do is *resolve*
/// (§3): the references may name things that don't exist here.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DeepLink {
    pub route: Route,
    /// The host reference as written: a stable record id, a host name, or `addr[:port]`.
    pub host_ref: String,
    /// Expected host certificate fingerprint, lowercase hex (64 chars).
    pub fp: Option<String>,
    /// Recovery address for a stable id that no longer resolves (store wiped, reinstall).
    pub host: Option<(String, u16)>,
    /// A store-qualified library id (`steam:570`) for the host to launch on arrival.
    pub launch: Option<String>,
    /// A settings-profile reference (id, or a unique name) — one-off, never rebinding.
    pub profile: Option<String>,
    /// Display label for the unknown-host confirmation sheet (external emitters).
    pub name: Option<String>,
}

/// Why a URL was rejected. The `code` strings are the cross-language contract (the vector
/// file names them) — Swift and Kotlin report the same code for the same input, which is what
/// keeps three parsers from drifting into three different security postures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Not a `punktfunk://` (or `pf://`) URL at all — the caller should ignore it, not warn.
    NotOurScheme,
    TooLong,
    /// A route this grammar doesn't define.
    UnknownRoute(String),
    /// `punktfunk://pair/…` — pairing is an interactive ceremony, never a link (§2).
    PairRefused,
    MissingHostRef,
    /// A `%` escape that isn't two hex digits, or a decode that isn't UTF-8.
    BadEscape,
    /// A control character survived decoding — no legitimate field contains one.
    ControlChar,
    /// A parameter past its cap; carries the parameter name.
    ParamTooLong(&'static str),
    /// `fp=` that isn't 64 hex characters.
    BadFingerprint,
    /// `host=` that isn't `addr[:port]` with a parsable port.
    BadHostParam,
    /// `launch=` outside the printable, shell-safe id charset the host and Decky agree on.
    BadLaunchId,
}

impl ParseError {
    /// The stable code shared with the Swift/Kotlin ports and the vector file.
    pub fn code(&self) -> &'static str {
        match self {
            ParseError::NotOurScheme => "not-our-scheme",
            ParseError::TooLong => "too-long",
            ParseError::UnknownRoute(_) => "unknown-route",
            ParseError::PairRefused => "pair-refused",
            ParseError::MissingHostRef => "missing-host-ref",
            ParseError::BadEscape => "bad-escape",
            ParseError::ControlChar => "control-char",
            ParseError::ParamTooLong(_) => "param-too-long",
            ParseError::BadFingerprint => "bad-fingerprint",
            ParseError::BadHostParam => "bad-host-param",
            ParseError::BadLaunchId => "bad-launch-id",
        }
    }

    /// A sentence for the notice a refusing front-end shows. Deliberately names the failing
    /// reference: "a shortcut that can't honor its profile says so instead of streaming with
    /// the wrong settings" (§10.6) applies to every refusal here.
    pub fn message(&self) -> String {
        match self {
            ParseError::NotOurScheme => "这不是一个 Punktfunk 链接。".into(),
            ParseError::TooLong => "该链接过长，不是有效链接。".into(),
            ParseError::UnknownRoute(r) => format!("Punktfunk 链接无法执行 \"{r}\"。"),
            ParseError::PairRefused => {
                "无法通过链接完成配对——请先在 Punktfunk 中配对主机。".into()
            }
            ParseError::MissingHostRef => "该链接未指明要使用的主机。".into(),
            ParseError::BadEscape | ParseError::ControlChar => {
                "该链接格式错误，已被忽略。".into()
            }
            ParseError::ParamTooLong(p) => format!("该链接的 \"{p}\" 参数值过长。"),
            ParseError::BadFingerprint => "该链接的主机指纹无效。".into(),
            ParseError::BadHostParam => "该链接的主机地址无效。".into(),
            ParseError::BadLaunchId => "该链接的游戏 ID 无效。".into(),
        }
    }
}

/// Parse a `punktfunk://` (or `pf://`) URL. Everything hostile is rejected here, once, for
/// every front-end: over-long input, malformed escapes, control characters, out-of-charset
/// launch ids and fingerprints that aren't fingerprints.
pub fn parse(url: &str) -> Result<DeepLink, ParseError> {
    if url.len() > MAX_URL_LEN {
        return Err(ParseError::TooLong);
    }
    let (scheme, rest) = url.split_once("://").ok_or(ParseError::NotOurScheme)?;
    if !scheme.eq_ignore_ascii_case("punktfunk") && !scheme.eq_ignore_ascii_case("pf") {
        return Err(ParseError::NotOurScheme);
    }
    // A fragment is never part of this grammar; drop it rather than folding it into the last
    // parameter (where it would smuggle unvalidated text past the caps).
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, q),
        None => (rest, ""),
    };

    let path = path.trim_end_matches('/');
    let (route_word, host_ref_raw) = match path.split_once('/') {
        Some((r, h)) => (r, h),
        // A single segment: Apple's shipped links are always `connect/<uuid>`, but a bare
        // reference is unambiguous as long as it isn't one of the route words — those stay
        // routes (with a missing reference), so `punktfunk://pair` refuses instead of hunting
        // for a host called "pair".
        None if is_route_word(path) => (path, ""),
        None => ("connect", path),
    };
    let route = match route_word.to_ascii_lowercase().as_str() {
        "connect" => Route::Connect,
        "wake" => Route::Wake,
        "browse" => Route::Browse,
        "pair" => return Err(ParseError::PairRefused),
        other => return Err(ParseError::UnknownRoute(other.to_string())),
    };

    let host_ref = decode(host_ref_raw)?;
    if host_ref.is_empty() {
        return Err(ParseError::MissingHostRef);
    }
    if host_ref.chars().count() > MAX_HOST_REF_LEN {
        return Err(ParseError::ParamTooLong("host-ref"));
    }

    let mut link = DeepLink {
        route,
        host_ref,
        ..Default::default()
    };
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(key)?.to_ascii_lowercase();
        let value = decode(value)?;
        if value.is_empty() {
            continue; // `?launch=` with nothing after it is "not given", not an error.
        }
        // First occurrence wins, and unknown keys are ignored: a newer emitter's parameter
        // must not turn an otherwise valid link into a refusal, and appending a second `fp=`
        // must not be able to override the first.
        match key.as_str() {
            "fp" if link.fp.is_none() => {
                let fp = value.to_ascii_lowercase();
                if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(ParseError::BadFingerprint);
                }
                link.fp = Some(fp);
            }
            "host" if link.host.is_none() => {
                link.host = Some(parse_addr_port(&value).ok_or(ParseError::BadHostParam)?);
            }
            "launch" if link.launch.is_none() => {
                if value.len() > MAX_LAUNCH_LEN {
                    return Err(ParseError::ParamTooLong("launch"));
                }
                if !is_safe_launch_id(&value) {
                    return Err(ParseError::BadLaunchId);
                }
                link.launch = Some(value);
            }
            "profile" if link.profile.is_none() => {
                if value.chars().count() > MAX_PROFILE_LEN {
                    return Err(ParseError::ParamTooLong("profile"));
                }
                link.profile = Some(value);
            }
            "name" if link.name.is_none() => {
                if value.chars().count() > MAX_NAME_LEN {
                    return Err(ParseError::ParamTooLong("name"));
                }
                link.name = Some(value);
            }
            _ => {}
        }
    }
    Ok(link)
}

impl DeepLink {
    /// The canonical URL for this link — always `punktfunk://`, never the `pf://` alias.
    /// Self-emitted links carry the stable id AND `host`+`fp`, so a shortcut written today
    /// still resolves after a reinstall wipes the store (§2, §5).
    pub fn to_url(&self) -> String {
        let mut s = format!(
            "punktfunk://{}/{}",
            self.route.as_str(),
            encode(&self.host_ref)
        );
        let mut sep = '?';
        let mut push = |s: &mut String, key: &str, value: &str| {
            s.push(sep);
            sep = '&';
            s.push_str(key);
            s.push('=');
            s.push_str(&encode(value));
        };
        if let Some(fp) = &self.fp {
            push(&mut s, "fp", fp);
        }
        if let Some((addr, port)) = &self.host {
            let host = if *port == DEFAULT_PORT {
                addr.clone()
            } else if addr.contains(':') {
                format!("[{addr}]:{port}") // literal IPv6 needs its brackets back
            } else {
                format!("{addr}:{port}")
            };
            push(&mut s, "host", &host);
        }
        if let Some(launch) = &self.launch {
            push(&mut s, "launch", launch);
        }
        if let Some(profile) = &self.profile {
            push(&mut s, "profile", profile);
        }
        if let Some(name) = &self.name {
            push(&mut s, "name", name);
        }
        s
    }

    /// The self-emitted form for a saved host: id first (address-independent), with the
    /// address and pin alongside so the link degrades to a confirmation sheet instead of a
    /// dead click when the record is gone.
    pub fn for_host(host: &KnownHost, launch: Option<&str>, profile: Option<&str>) -> DeepLink {
        DeepLink {
            route: Route::Connect,
            host_ref: host
                .id
                .clone()
                .unwrap_or_else(|| format!("{}:{}", host.addr, host.port)),
            fp: (!host.fp_hex.is_empty()).then(|| host.fp_hex.clone()),
            host: Some((host.addr.clone(), host.port)),
            launch: launch.map(str::to_string),
            profile: profile.map(str::to_string),
            name: None,
        }
    }

    /// True when this link's `fp` contradicts what we have pinned for that host — the link is
    /// stale or lying, and the only safe answer is a hard refusal (§3.1).
    pub fn pin_conflict(&self, host: &KnownHost) -> bool {
        match (&self.fp, host.fp_hex.is_empty()) {
            (Some(fp), false) => !fp.eq_ignore_ascii_case(&host.fp_hex),
            _ => false,
        }
    }
}

/// What the local host store made of a link's references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostResolution {
    /// Index into `KnownHosts::hosts` — a record we already trust (subject to
    /// [`DeepLink::pin_conflict`]).
    Known(usize),
    /// No record, but the link says where to dial: the confirmation sheet's input, from which
    /// the normal pairing/TOFU flow proceeds under the user's eyes. Never an auto-connect.
    Unknown {
        addr: String,
        port: u16,
        name: Option<String>,
        fp: Option<String>,
    },
    /// The name matched more than one saved host — refuse with a notice, never guess (§8).
    Ambiguous,
    /// A reference that resolves to nothing and carries no address to fall back on.
    Unresolvable,
}

/// Resolve a link's host reference against the local store, in the documented order: stable
/// record id → unique case-insensitive name → `addr[:port]` literal. The `host=` parameter is
/// the recovery path — a self-emitted shortcut that outlived the record it was written from
/// still lands on the right box (degraded to the confirmation sheet).
///
/// Returns an index rather than a borrow so callers can keep mutating the store (rekey,
/// touch-last-used) without fighting the borrow checker.
pub fn resolve_host(link: &DeepLink, known: &KnownHosts) -> HostResolution {
    if let Some(i) = known
        .hosts
        .iter()
        .position(|h| h.id.as_deref().is_some_and(|id| id == link.host_ref))
    {
        return HostResolution::Known(i);
    }
    let by_name: Vec<usize> = known
        .hosts
        .iter()
        .enumerate()
        .filter(|(_, h)| h.name.eq_ignore_ascii_case(&link.host_ref))
        .map(|(i, _)| i)
        .collect();
    match by_name.len() {
        1 => return HostResolution::Known(by_name[0]),
        0 => {}
        _ => return HostResolution::Ambiguous,
    }
    // `addr[:port]` literal, then the `host=` recovery parameter — both matched the way every
    // other per-host lookup in the client matches (addr + port). The literal is only
    // considered when the reference could BE an address: a stale record id must fall through
    // to `host=` (or to a refusal), never be offered as a box to dial.
    let literal = looks_like_address(&link.host_ref)
        .then(|| parse_addr_port(&link.host_ref))
        .flatten();
    for candidate in [literal.clone(), link.host.clone()].into_iter().flatten() {
        if let Some(i) = known.index_by_addr(&candidate.0, candidate.1) {
            return HostResolution::Known(i);
        }
    }
    match literal.or_else(|| link.host.clone()) {
        Some((addr, port)) => HostResolution::Unknown {
            addr,
            port,
            name: link.name.clone(),
            fp: link.fp.clone(),
        },
        None => HostResolution::Unresolvable,
    }
}

/// Could this reference be a network address (an IP literal or a host name) rather than a
/// record id or a display name? Only then may an unmatched reference become "an unknown host
/// at this address" for the confirmation sheet. A stable id that no longer resolves is NOT an
/// address: offering to dial a UUID as a hostname would turn a wiped store into a confusing
/// dead end instead of the `host=`-driven recovery §2 specifies.
fn looks_like_address(s: &str) -> bool {
    let uuid_shaped = s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    !uuid_shaped
        && !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
}

/// The reserved first path segments — everything the grammar routes on, plus `pair`, which is
/// reserved precisely so it can be refused rather than mistaken for a host name.
fn is_route_word(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "connect" | "wake" | "browse" | "pair"
    )
}

/// `addr`, `addr:port`, `[v6]`, `[v6]:port` — `None` when the port isn't a number. A bare
/// IPv6 literal (`::1`) keeps its colons and takes the default port; anything else splits at
/// the last colon, like every other host-parsing site in the clients.
fn parse_addr_port(s: &str) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        if addr.is_empty() {
            return None;
        }
        return match tail {
            "" => Some((addr.to_string(), DEFAULT_PORT)),
            t => Some((addr.to_string(), t.strip_prefix(':')?.parse().ok()?)),
        };
    }
    match s.rsplit_once(':') {
        // `::1` and friends: the head still has a colon, so this isn't a port separator.
        Some((head, _)) if head.contains(':') => Some((s.to_string(), DEFAULT_PORT)),
        Some((addr, port)) if !addr.is_empty() => Some((addr.to_string(), port.parse().ok()?)),
        Some(_) => None,
        None => Some((s.to_string(), DEFAULT_PORT)),
    }
}

/// The launch-id charset the whole product already agrees on: printable, non-space ASCII with
/// no shell metacharacters (Decky rides ids through Steam launch options as an env token, so
/// a quote or a backtick genuinely breaks something downstream). Validation only — the id is
/// opaque and the host matches it verbatim against its own library.
fn is_safe_launch_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !br#""'\$`"#.contains(&b))
}

/// Strict percent-decoding: `%` must be followed by exactly two hex digits, the result must be
/// UTF-8, and no control character may survive. Lenient decoders are how `%00`, a stray `\n`
/// or a half-escape end up inside a filename or a log line.
fn decode(s: &str) -> Result<String, ParseError> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3).ok_or(ParseError::BadEscape)?;
                let hi = (hex[0] as char).to_digit(16).ok_or(ParseError::BadEscape)?;
                let lo = (hex[1] as char).to_digit(16).ok_or(ParseError::BadEscape)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    let text = String::from_utf8(out).map_err(|_| ParseError::BadEscape)?;
    if text.chars().any(|c| c.is_control()) {
        return Err(ParseError::ControlChar);
    }
    Ok(text)
}

/// Percent-encode for emission: unreserved characters plus `:` (legal in a query value and
/// left alone by Apple's `URLComponents`, so the three emitters agree on `steam:570`).
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::KnownHost;

    fn host(name: &str, addr: &str, id: &str, fp: &str) -> KnownHost {
        KnownHost {
            name: name.into(),
            addr: addr.into(),
            port: DEFAULT_PORT,
            fp_hex: fp.into(),
            paired: true,
            id: Some(id.into()),
            ..Default::default()
        }
    }

    /// Every case in the cross-language vector file, which the Swift and Kotlin ports consume
    /// too — this is what keeps three parsers from drifting into three security postures.
    #[test]
    fn shared_vectors() {
        let raw = include_str!("../../../clients/shared/deeplink-vectors.json");
        let file: serde_json::Value = serde_json::from_str(raw).expect("vector file parses");
        let cases = file["cases"].as_array().expect("cases array");
        assert!(
            cases.len() > 20,
            "the vector file is the contract; keep it rich"
        );
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let url = case["url"].as_str().unwrap();
            let got = parse(url);
            match case.get("error").and_then(|e| e.as_str()) {
                Some(code) => {
                    let err = got.expect_err(&format!("{name}: expected {code}, parsed ok"));
                    assert_eq!(err.code(), code, "{name}");
                }
                None => {
                    let link = got.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                    let want = &case["expect"];
                    assert_eq!(
                        link.route.as_str(),
                        want["route"].as_str().unwrap(),
                        "{name}"
                    );
                    assert_eq!(link.host_ref, want["host_ref"].as_str().unwrap(), "{name}");
                    let opt = |k: &str| want.get(k).and_then(|v| v.as_str()).map(str::to_string);
                    assert_eq!(link.fp, opt("fp"), "{name} fp");
                    assert_eq!(link.launch, opt("launch"), "{name} launch");
                    assert_eq!(link.profile, opt("profile"), "{name} profile");
                    assert_eq!(link.name, opt("name"), "{name} name");
                    let (addr, port) = match &link.host {
                        Some((a, p)) => (Some(a.clone()), Some(u64::from(*p))),
                        None => (None, None),
                    };
                    assert_eq!(addr, opt("host_addr"), "{name} host_addr");
                    assert_eq!(
                        port,
                        want.get("host_port").and_then(|v| v.as_u64()),
                        "{name} host_port"
                    );
                    if let Some(emit) = case.get("emit").and_then(|v| v.as_str()) {
                        assert_eq!(link.to_url(), emit, "{name} emit");
                    }
                }
            }
        }
    }

    /// A `Result` from the parser is not enough on its own: the codes are the shared
    /// vocabulary, so they must be exactly what the vector file (and the ports) name.
    #[test]
    fn refusals_are_specific() {
        assert_eq!(parse("https://example.com/"), Err(ParseError::NotOurScheme));
        assert_eq!(parse("punktfunk:/connect/x"), Err(ParseError::NotOurScheme));
        assert_eq!(
            parse(&format!("punktfunk://connect/{}", "a".repeat(MAX_URL_LEN))),
            Err(ParseError::TooLong)
        );
        assert_eq!(parse("punktfunk://pair/1234"), Err(ParseError::PairRefused));
        assert_eq!(
            parse("punktfunk://teardown/host"),
            Err(ParseError::UnknownRoute("teardown".into()))
        );
        assert_eq!(
            parse("punktfunk://connect/"),
            Err(ParseError::MissingHostRef)
        );
        assert_eq!(
            parse(&format!(
                "punktfunk://connect/{}",
                "n".repeat(MAX_HOST_REF_LEN + 1)
            )),
            Err(ParseError::ParamTooLong("host-ref"))
        );
    }

    /// The one-click contract in resolution form: an id beats a name beats an address, an
    /// ambiguous name refuses, and a link whose record is gone still lands on the
    /// confirmation sheet via `host=`+`fp=` instead of dying.
    #[test]
    fn host_resolution_order_and_recovery() {
        let fp = "a".repeat(64);
        let known = KnownHosts {
            hosts: vec![
                host(
                    "Desk",
                    "192.168.1.50",
                    "11111111-2222-4333-8444-555555555555",
                    &fp,
                ),
                host(
                    "Couch",
                    "192.168.1.60",
                    "66666666-7777-4888-8999-aaaaaaaaaaaa",
                    "",
                ),
                host(
                    "Couch",
                    "192.168.1.61",
                    "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
                    "",
                ),
            ],
        };
        let r = |url: &str| resolve_host(&parse(url).unwrap(), &known);

        assert_eq!(
            r("punktfunk://connect/11111111-2222-4333-8444-555555555555"),
            HostResolution::Known(0)
        );
        assert_eq!(r("punktfunk://connect/desk"), HostResolution::Known(0));
        assert_eq!(r("punktfunk://connect/couch"), HostResolution::Ambiguous);
        assert_eq!(
            r("punktfunk://connect/192.168.1.50"),
            HostResolution::Known(0)
        );
        assert_eq!(
            r("punktfunk://connect/192.168.1.50:9777"),
            HostResolution::Known(0)
        );
        // A stale id with the recovery parameters: the address finds the record anyway.
        assert_eq!(
            r("punktfunk://connect/00000000-0000-4000-8000-000000000000?host=192.168.1.50"),
            HostResolution::Known(0)
        );
        // Nothing local matches: the sheet gets the address, the claimed name and the pin —
        // which is what makes the first connect verified rather than blind TOFU.
        assert_eq!(
            r(&format!(
                "punktfunk://connect/10.0.0.9:7000?name=Studio&fp={fp}"
            )),
            HostResolution::Unknown {
                addr: "10.0.0.9".into(),
                port: 7000,
                name: Some("Studio".into()),
                fp: Some(fp.clone()),
            }
        );
        // An unmatched reference that could be an address (an mDNS/DNS name, a new IP) is
        // offered as an unknown host — the sheet, never an auto-connect.
        assert_eq!(
            r("punktfunk://connect/nas.local"),
            HostResolution::Unknown {
                addr: "nas.local".into(),
                port: DEFAULT_PORT,
                name: None,
                fp: None,
            }
        );
        // But a stale record id is not a hostname: without `host=` there is nothing to dial,
        // and dialing "11111111-…" would be a confusing dead end rather than a recovery.
        assert_eq!(
            r("punktfunk://connect/00000000-0000-4000-8000-000000000000"),
            HostResolution::Unresolvable
        );
        // Neither is a display name that can't be an address.
        assert_eq!(
            r("punktfunk://connect/Basement%20PC"),
            HostResolution::Unresolvable
        );

        // A pin that contradicts the stored one is the link lying — the caller hard-refuses.
        let link = parse(&format!("punktfunk://connect/desk?fp={}", "b".repeat(64))).unwrap();
        assert!(link.pin_conflict(&known.hosts[0]));
        assert!(!parse(&format!("punktfunk://connect/desk?fp={fp}"))
            .unwrap()
            .pin_conflict(&known.hosts[0]));
        // No pin stored (an address-only record) → nothing to contradict; the trust flow runs.
        assert!(!link.pin_conflict(&known.hosts[1]));
    }

    /// Self-emitted links round-trip and carry all three references, so they survive both a
    /// re-addressed host and a wiped store.
    #[test]
    fn self_emitted_links_round_trip() {
        let fp = "c".repeat(64);
        let mut h = host(
            "Desk",
            "192.168.1.50",
            "11111111-2222-4333-8444-555555555555",
            &fp,
        );
        h.port = 7777;
        let link = DeepLink::for_host(&h, Some("steam:570"), Some("aaaaaaaaaaaa"));
        let url = link.to_url();
        assert_eq!(
            url,
            "punktfunk://connect/11111111-2222-4333-8444-555555555555\
             ?fp=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\
             &host=192.168.1.50:7777&launch=steam:570&profile=aaaaaaaaaaaa"
        );
        assert_eq!(parse(&url).unwrap(), link);

        // A record with no id yet (pre-migration store) still emits something resolvable.
        let mut plain = h.clone();
        plain.id = None;
        assert_eq!(
            DeepLink::for_host(&plain, None, None).host_ref,
            "192.168.1.50:7777"
        );

        // Names with spaces and non-ASCII survive the round trip.
        let link = DeepLink {
            host_ref: "Wohnzimmer PC".into(),
            name: Some("Büro · Mac".into()),
            ..Default::default()
        };
        assert!(link
            .to_url()
            .starts_with("punktfunk://connect/Wohnzimmer%20PC?"));
        assert_eq!(parse(&link.to_url()).unwrap(), link);
    }

    /// `addr[:port]` parsing, including the bracketed IPv6 forms a link can carry.
    #[test]
    fn addr_port_forms() {
        assert_eq!(
            parse_addr_port("192.168.1.5"),
            Some(("192.168.1.5".into(), 9777))
        );
        assert_eq!(
            parse_addr_port("192.168.1.5:1234"),
            Some(("192.168.1.5".into(), 1234))
        );
        assert_eq!(parse_addr_port("::1"), Some(("::1".into(), 9777)));
        assert_eq!(parse_addr_port("[::1]"), Some(("::1".into(), 9777)));
        assert_eq!(parse_addr_port("[::1]:1234"), Some(("::1".into(), 1234)));
        assert_eq!(parse_addr_port("host:notaport"), None);
        assert_eq!(parse_addr_port("[::1]junk"), None);
        assert_eq!(parse_addr_port(""), None);
        // An emitted IPv6 host parameter comes back bracketed so it parses again.
        let link = DeepLink {
            host_ref: "x".into(),
            host: Some(("::1".into(), 1234)),
            ..Default::default()
        };
        assert_eq!(parse(&link.to_url()).unwrap().host, link.host);
    }
}
