//! pf-wgtunnel CLI.
//!
//!   pf-wgtunnel genkey [--out PREFIX]
//!       Print (or write PREFIX / PREFIX.pub) a fresh keypair.
//!
//!   pf-wgtunnel server --key FILE --peers FILE [--listen 0.0.0.0:9777]
//!                      [--quic 127.0.0.1:9777] [--data 127.0.0.1:9778]
//!       Host gate: the only public UDP port; relays to loopback services.
//!
//!   pf-wgtunnel client --key FILE --server-pub B64 --server HOST:PORT
//!                      [--listen-quic 127.0.0.1:9777] [--listen-data 127.0.0.1:9778]
//!                      [--quic-target-port N] [--data-target-port N]
//!       Client relay: exposes loopback endpoints for the punktfunk client.
//!       The target ports are the host-side service ports written into the
//!       tunnel packets; they default to the listen ports.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use pf_wgtunnel::{client, keys, server};

fn usage() -> ! {
    eprintln!(
        "pf-wgtunnel — one public UDP port for punktfunk, via WireGuard\n\
         \n\
         usage:\n\
         \x20 pf-wgtunnel genkey [--out PREFIX]\n\
         \x20 pf-wgtunnel server --key FILE --peers FILE [--listen 0.0.0.0:9777]\n\
         \x20                    [--quic 127.0.0.1:9777] [--data 127.0.0.1:9778]\n\
         \x20 pf-wgtunnel client --key FILE --server-pub B64 --server HOST:PORT\n\
         \x20                    [--listen-quic 127.0.0.1:9777] [--listen-data 127.0.0.1:9778]\n\
         \x20                    [--quic-target-port N] [--data-target-port N]"
    );
    std::process::exit(2)
}

struct Args(VecDeque<String>);

impl Args {
    fn take(&mut self, name: &str) -> Option<String> {
        let pos = self.0.iter().position(|a| a == name)?;
        self.0.remove(pos);
        self.0.remove(pos)
    }

    fn take_addr(&mut self, name: &str, default: &str) -> Result<SocketAddr, String> {
        self.take(name)
            .unwrap_or_else(|| default.to_string())
            .parse()
            .map_err(|e| format!("{name}: invalid address: {e}"))
    }

    fn need(&mut self, name: &str) -> Result<String, String> {
        self.take(name).ok_or_else(|| format!("missing {name}"))
    }

    fn finish(&self) -> Result<(), String> {
        if let Some(extra) = self.0.front() {
            return Err(format!("unexpected argument: {extra}"));
        }
        Ok(())
    }
}

fn run() -> Result<(), String> {
    let mut argv: VecDeque<String> = std::env::args().skip(1).collect();
    let cmd = argv.pop_front().unwrap_or_default();
    let mut args = Args(argv);
    match cmd.as_str() {
        "genkey" => {
            let out = args.take("--out").map(PathBuf::from);
            args.finish()?;
            let (private, public) = keys::generate_keypair();
            match out {
                Some(prefix) => {
                    let pub_path = PathBuf::from(format!("{}.pub", prefix.display()));
                    keys::save_key(&prefix, &private)
                        .map_err(|e| format!("write {}: {e}", prefix.display()))?;
                    keys::save_key(&pub_path, &public)
                        .map_err(|e| format!("write {}: {e}", pub_path.display()))?;
                    println!("private key: {}", prefix.display());
                    println!("public key:  {} ({public})", pub_path.display());
                }
                None => {
                    println!("private: {private}");
                    println!("public:  {public}");
                }
            }
            Ok(())
        }
        "server" => {
            let key = PathBuf::from(args.need("--key")?);
            let peers = PathBuf::from(args.need("--peers")?);
            let listen = args.take_addr("--listen", "0.0.0.0:9777")?;
            let quic = args.take_addr("--quic", "127.0.0.1:9777")?;
            let data = args.take_addr("--data", "127.0.0.1:9778")?;
            args.finish()?;
            let private_key = keys::load_private_key(&key)
                .map_err(|e| format!("load {}: {e}", key.display()))?;
            let peers = keys::load_peers(&peers)
                .map_err(|e| format!("load {}: {e}", peers.display()))?;
            server::run_server(server::ServerConfig {
                listen,
                private_key,
                peers,
                quic_target: quic,
                data_target: data,
            })
            .map_err(|e| format!("server: {e}"))
        }
        "client" => {
            let key = PathBuf::from(args.need("--key")?);
            let server_pub = args.need("--server-pub")?;
            let server_addr: SocketAddr = args
                .need("--server")?
                .parse()
                .map_err(|e| format!("--server: invalid address: {e}"))?;
            let listen_quic = args.take_addr("--listen-quic", "127.0.0.1:9777")?;
            let listen_data = args.take_addr("--listen-data", "127.0.0.1:9778")?;
            let quic_target_port = args
                .take("--quic-target-port")
                .map(|s| s.parse::<u16>())
                .transpose()
                .map_err(|e| format!("--quic-target-port: {e}"))?
                .unwrap_or_else(|| listen_quic.port());
            let data_target_port = args
                .take("--data-target-port")
                .map(|s| s.parse::<u16>())
                .transpose()
                .map_err(|e| format!("--data-target-port: {e}"))?
                .unwrap_or_else(|| listen_data.port());
            args.finish()?;
            let private_key = keys::load_private_key(&key)
                .map_err(|e| format!("load {}: {e}", key.display()))?;
            let server_public =
                keys::parse_public_key(&server_pub).map_err(|e| format!("--server-pub: {e}"))?;
            client::run_client(client::ClientConfig {
                server: server_addr,
                private_key,
                server_public,
                listen_quic,
                listen_data,
                quic_target_port,
                data_target_port,
            })
            .map_err(|e| format!("client: {e}"))
        }
        _ => usage(),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pf-wgtunnel: {e}");
            ExitCode::FAILURE
        }
    }
}
