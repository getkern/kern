//! HTTPS for the `.localhost` names, after `kern proxy trust` and only then.
//!
//! WHAT IT IS. `kern proxy trust` makes a certificate authority of the user's own, adds it to the
//! certificate stores of that user's browsers, and from then on the `.localhost` router also answers
//! `https://<service>.<project>.localhost:<port>/`: the TLS is ended here and the request goes on to
//! the plain router, so every rule of the router (one host per request, a head nobody can split
//! twice) is the same rule for both. `kern proxy untrust` takes the authority out of every store it
//! was put in and deletes it. Without `trust` nothing here runs: no file, no port, no question.
//!
//! WHAT WAS MEASURED BEFORE A LINE OF THIS WAS WRITTEN (2026-11-21), with a test authority carrying
//! the same constraint and a CONTROL authority without it:
//!
//! * the authority may sign names under `localhost` ONLY (`nameConstraints`, critical, `permitted
//!   DNS:localhost`). A certificate it signs for another name is refused by OpenSSL 3.0.13 and curl
//!   ("permitted subtree violation"), Chrome 157 and Firefox 157 on Linux, and Windows' CryptoAPI
//!   (`HasNotPermittedNameConstraint`); the control's certificate for the same name is accepted by
//!   each. So a stolen key cannot pass for another site in those clients. It is a second line: the
//!   first is that the key lives in a 0700 directory of the user, `0600`, and never leaves it;
//! * `http://*.localhost` is ALREADY a secure context in Chrome 157 and Firefox 157, which is why
//!   this stays opt-in: most of what wants HTTPS works over the plain names already;
//! * an ordinary user may not bind 443 on any host measured (`ip_unprivileged_port_start` 1024 on
//!   Ubuntu 24.04 and in both WSL distros), so the port is 8443 there, and the URLs say so;
//! * NSS's `certutil`, which writes the stores Chrome and Firefox read on Linux, is not installed on a
//!   stock Ubuntu 24.04 desktop; without it kern says what to install and changes nothing.
//!
//! Certificates for the names are made when a browser first asks for one, kept in memory, valid 30
//! days and replaced after 20. A name that is not a `[<port>.]<service>.<project>.localhost` name gets
//! no certificate, so the handshake fails before any byte reaches a service.

use crate::error::Error;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The common name every store lists the authority under, followed by `(<user>@<host>)`.
const AUTHORITY_NAME: &str = "kern local CA";
/// How long the authority is valid. It can sign only `localhost` names and only this user holds
/// its key; ten years is so it does not expire under a working setup.
const AUTHORITY_DAYS: i64 = 3650;
/// How long a name's certificate is valid, and when it is replaced.
const LEAF_DAYS: i64 = 30;
const LEAF_RENEW_AFTER: Duration = Duration::from_secs(20 * 24 * 3600);
/// The certificates kept in memory at most; past it the cache starts over.
const LEAF_CACHE_MAX: usize = 1024;
/// A handshake or a request head that takes longer than this is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection with no byte either way for this long is closed.
const IDLE_TIMEOUT_MS: i32 = 10 * 60 * 1000;
/// Plaintext read from the client and not yet taken by the router, at most.
const PENDING_MAX: usize = 256 * 1024;

/// Where the authority lives: `$XDG_DATA_HOME/kern/local-ca/` (`~/.local/share/kern/local-ca`).
struct Paths {
    dir: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    /// The authority's common name as it was made: what it signs as, and what every store lists it
    /// under, whatever the user or the host is called later.
    name: PathBuf,
    /// Written by `trust`, removed by `untrust`: the stores the authority was added to, one a line.
    trusted: PathBuf,
}

fn paths() -> Option<Paths> {
    let dir = crate::kern_xdg_root("XDG_DATA_HOME", ".local/share")?.join("local-ca");
    Some(Paths {
        cert: dir.join("ca.pem"),
        key: dir.join("ca.key"),
        name: dir.join("ca.name"),
        trusted: dir.join("trusted"),
        dir,
    })
}

/// Whether `kern proxy trust` has been run here and its authority is still in place.
pub(crate) fn trusted() -> bool {
    paths().is_some_and(|p| p.trusted.is_file() && p.cert.is_file() && p.key.is_file())
}

/// `kern local CA (<user>@<host>)`: the name a person finds in a browser's certificate list.
fn authority_name() -> String {
    // SAFETY: getuid takes no arguments.
    let uid = unsafe { libc::getuid() };
    let user = kern_isolation::username(uid).unwrap_or_else(|| uid.to_string());
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    if host.is_empty() {
        format!("{AUTHORITY_NAME} ({user})")
    } else {
        format!("{AUTHORITY_NAME} ({user}@{host})")
    }
}

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

/// The authority's parameters. ONE definition, for making it and for signing with it: what a
/// certificate it signs names as its issuer, and its key identifier, come from these and its key,
/// so the two must not be built twice.
fn authority_params(name: &str) -> Result<rcgen::CertificateParams, rcgen::Error> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, name);
    dn.push(rcgen::DnType::OrganizationName, "kern");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.name_constraints = Some(rcgen::NameConstraints {
        permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("localhost".to_string())],
        excluded_subtrees: Vec::new(),
    });
    params.not_before = now() - time::Duration::hours(1);
    params.not_after = now() + time::Duration::days(AUTHORITY_DAYS);
    Ok(params)
}

/// A new authority: `(certificate PEM, key PEM)`.
fn make_authority(name: &str) -> Result<(String, String), rcgen::Error> {
    let key = rcgen::KeyPair::generate()?;
    let cert = authority_params(name)?.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// The signer for the authority named `name` holding `key_pem`.
fn authority_issuer(
    name: &str,
    key_pem: &str,
) -> Result<rcgen::Issuer<'static, rcgen::KeyPair>, rcgen::Error> {
    let key = rcgen::KeyPair::from_pem(key_pem)?;
    Ok(rcgen::Issuer::new(authority_params(name)?, key))
}

/// The name the authority here was made with: `ca.name`, written beside it.
fn stored_name(p: &Paths) -> String {
    std::fs::read_to_string(&p.name)
        .map(|n| n.trim().to_string())
        .ok()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(authority_name)
}

/// The authority, made the first time: `(certificate PEM, key PEM)`. The directory is created 0700
/// and the key written 0600 before a byte of it is, then renamed into place.
fn ensure_authority(p: &Paths) -> Result<(String, String), Error> {
    if let (Ok(c), Ok(k)) = (
        std::fs::read_to_string(&p.cert),
        std::fs::read_to_string(&p.key),
    ) {
        return Ok((c, k));
    }
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let io = |what: &str, e: std::io::Error| {
        Error::Cli(format!("proxy trust: {what} {}: {e}", p.dir.display()))
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&p.dir)
        .map_err(|e| io("cannot create", e))?;
    let name = authority_name();
    let (cert, key) = make_authority(&name)
        .map_err(|e| Error::Cli(format!("proxy trust: cannot make the local CA: {e}")))?;
    let write = |path: &Path, body: &str, mode: u32| -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write(&p.key, &key, 0o600).map_err(|e| io("cannot write the key in", e))?;
    write(&p.name, &name, 0o644).map_err(|e| io("cannot write the name in", e))?;
    write(&p.cert, &cert, 0o644).map_err(|e| io("cannot write the certificate in", e))?;
    Ok((cert, key))
}

/// The names a certificate is made for: `[<port>.]<service>.<project>.localhost`, the names the
/// router routes, each label by the router's own rule.
fn name_ok(name: &str) -> bool {
    let Some(front) = name.strip_suffix(".localhost") else {
        return false;
    };
    let labels: Vec<&str> = front.split('.').collect();
    matches!(labels.len(), 2 | 3) && labels.iter().all(|l| crate::localrouter::label_ok(l))
}

/// A certificate for `name` signed by the authority: `(certificate DER, key PKCS#8 DER)`.
fn make_leaf(
    name: &str,
    issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
) -> Result<(Vec<u8>, Vec<u8>), rcgen::Error> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()])?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, name);
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    params.not_before = now() - time::Duration::hours(1);
    params.not_after = now() + time::Duration::days(LEAF_DAYS);
    let cert = params.signed_by(&key, issuer)?;
    Ok((cert.der().to_vec(), key.serialize_der()))
}

/// Answers a handshake with a certificate for the name the client asked for (its SNI).
#[derive(Debug)]
struct LocalNames {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    authority_der: Vec<u8>,
    cache: Mutex<HashMap<String, (Instant, Arc<rustls::sign::CertifiedKey>)>>,
}

impl LocalNames {
    fn certified(&self, name: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let (der, key) = make_leaf(name, &self.issuer).ok()?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));
        let signer = rustls::crypto::ring::sign::any_supported_type(&key).ok()?;
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            vec![
                CertificateDer::from(der),
                CertificateDer::from(self.authority_der.clone()),
            ],
            signer,
        )))
    }
}

impl rustls::server::ResolvesServerCert for LocalNames {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = hello.server_name()?.to_ascii_lowercase();
        if !name_ok(&name) {
            return None;
        }
        // The lock is held across the signing on purpose: two first requests for one name make one
        // certificate, not two. It is the cold path, once a name every 20 days.
        let mut cache = self.cache.lock().ok()?;
        if let Some((made, ck)) = cache.get(&name) {
            if made.elapsed() < LEAF_RENEW_AFTER {
                return Some(Arc::clone(ck));
            }
        }
        if cache.len() >= LEAF_CACHE_MAX {
            cache.clear();
        }
        let ck = self.certified(&name)?;
        cache.insert(name, (Instant::now(), Arc::clone(&ck)));
        Some(ck)
    }
}

/// The TLS configuration of the router: `None` when the user has not run `kern proxy trust`, or its
/// authority cannot be read.
pub(crate) fn server_config() -> Option<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    if !trusted() {
        return None;
    }
    let p = paths()?;
    let cert = std::fs::read_to_string(&p.cert).ok()?;
    let key = std::fs::read_to_string(&p.key).ok()?;
    let authority_der = CertificateDer::from_pem_slice(cert.as_bytes())
        .ok()?
        .to_vec();
    let issuer = authority_issuer(&stored_name(&p), &key).ok()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(LocalNames {
            issuer,
            authority_der,
            cache: Mutex::new(HashMap::new()),
        }));
    // HTTP/1.1 only: the router routes a connection by its first request's host, and HTTP/2 would
    // carry requests for several names on one connection.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Some(Arc::new(config))
}

/// One HTTPS connection: the handshake, then the plaintext relayed to the plain router on
/// `plain_port`, both ways, until either side is done.
pub(crate) fn serve(mut sock: TcpStream, config: Arc<rustls::ServerConfig>, plain_port: u16) {
    let Ok(mut conn) = rustls::ServerConnection::new(config) else {
        return;
    };
    let _ = sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    while conn.is_handshaking() {
        if conn.complete_io(&mut sock).is_err() {
            return;
        }
    }
    let Ok(up) = TcpStream::connect(("127.0.0.1", plain_port)) else {
        return;
    };
    relay(&mut conn, sock, up);
}

/// What one read of a non-blocking socket gave.
enum Got {
    Bytes(usize),
    Eof,
    Nothing,
    Failed,
}

fn read_some(r: &mut impl Read, buf: &mut [u8]) -> Got {
    match r.read(buf) {
        Ok(0) => Got::Eof,
        Ok(n) => Got::Bytes(n),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::Interrupted =>
        {
            Got::Nothing
        }
        Err(_) => Got::Failed,
    }
}

/// The relay: one thread, `poll` on both sockets, the TLS state machine driven by hand. Bounded:
/// at most [`PENDING_MAX`] plaintext waits for the router, and the router is read only once the
/// previous answer has gone out to the client, so neither side can make this buffer without end.
fn relay(conn: &mut rustls::ServerConnection, mut sock: TcpStream, mut up: TcpStream) {
    use std::os::fd::AsRawFd;
    if sock.set_nonblocking(true).is_err() || up.set_nonblocking(true).is_err() {
        return;
    }
    let mut buf = [0u8; 16 * 1024];
    let mut to_up: Vec<u8> = Vec::new();
    let (mut client_done, mut up_done, mut up_shut) = (false, false, false);
    loop {
        // Plaintext rustls already holds (it can arrive with the last handshake flight).
        loop {
            match read_some(&mut conn.reader(), &mut buf) {
                Got::Bytes(n) => to_up.extend_from_slice(&buf[..n]),
                Got::Eof | Got::Failed => {
                    client_done = true;
                    break;
                }
                Got::Nothing => break,
            }
            if to_up.len() >= PENDING_MAX {
                break;
            }
        }
        // To the router.
        while !to_up.is_empty() {
            match up.write(&to_up) {
                Ok(0) => return,
                Ok(n) => {
                    to_up.drain(..n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
        if client_done && to_up.is_empty() && !up_shut {
            let _ = up.shutdown(std::net::Shutdown::Write);
            up_shut = true;
        }
        // To the client.
        while conn.wants_write() {
            match conn.write_tls(&mut sock) {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
        if up_done && !conn.wants_write() {
            return;
        }
        if client_done && up_done {
            return;
        }
        let read_client = !client_done && to_up.len() < PENDING_MAX;
        let read_up = !up_done && !conn.wants_write();
        let mut fds = [
            libc::pollfd {
                fd: sock.as_raw_fd(),
                events: (if read_client { libc::POLLIN } else { 0 })
                    | (if conn.wants_write() { libc::POLLOUT } else { 0 }),
                revents: 0,
            },
            libc::pollfd {
                fd: up.as_raw_fd(),
                events: (if read_up { libc::POLLIN } else { 0 })
                    | (if to_up.is_empty() { 0 } else { libc::POLLOUT }),
                revents: 0,
            },
        ];
        if fds[0].events == 0 && fds[1].events == 0 {
            return;
        }
        // SAFETY: two pollfd structs owned by this frame.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, IDLE_TIMEOUT_MS) };
        if n == 0 {
            return; // idle
        }
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        let ready =
            |f: &libc::pollfd| f.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
        if read_client && ready(&fds[0]) {
            match conn.read_tls(&mut sock) {
                Ok(0) => client_done = true,
                Ok(_) => {
                    if conn.process_new_packets().is_err() {
                        let _ = conn.write_tls(&mut sock);
                        return;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
        if read_up && ready(&fds[1]) {
            match read_some(&mut up, &mut buf) {
                Got::Bytes(n) => {
                    if conn.writer().write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
                Got::Eof => {
                    up_done = true;
                    conn.send_close_notify();
                }
                Got::Nothing => {}
                Got::Failed => return,
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// `kern proxy trust | untrust | status`: the user's own stores, and nothing outside them.

/// A certificate store of this user's: what it is called for a person, and its NSS directory.
struct Store {
    label: String,
    dir: PathBuf,
    /// Chrome's store does not exist until Chrome first needs it; made here only when a Chrome-family
    /// browser is installed.
    create: bool,
}

/// The NSS stores of this user: Chrome and Chromium (`~/.pki/nssdb`) and every Firefox profile
/// (classic, snap and Flatpak). The system's store is not one of them: changing it needs root, and
/// kern does not ask for root.
fn stores() -> Vec<Store> {
    let Some(home) = crate::xdg_var("HOME") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let chrome = home.join(".pki/nssdb");
    let chrome_installed = [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "brave-browser",
        "microsoft-edge",
    ]
    .iter()
    .any(|b| crate::doctor::which(b));
    if chrome.join("cert9.db").is_file() || chrome_installed {
        out.push(Store {
            label: "Chrome".to_string(),
            create: !chrome.join("cert9.db").is_file(),
            dir: chrome,
        });
    }
    for base in [
        ".mozilla/firefox",
        "snap/firefox/common/.mozilla/firefox",
        ".var/app/org.mozilla.firefox/.mozilla/firefox",
    ] {
        let Ok(rd) = std::fs::read_dir(home.join(base)) else {
            continue;
        };
        let mut profiles: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.join("cert9.db").is_file())
            .collect();
        profiles.sort();
        for dir in profiles {
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push(Store {
                label: format!("Firefox ({name})"),
                dir,
                create: false,
            });
        }
    }
    out
}

/// Run NSS's `certutil` with `args`; whether it exited 0. Its words are kept from the user unless it
/// failed, when they are the reason.
fn certutil(tool: &Path, args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let out = std::process::Command::new(tool)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn sql(dir: &Path) -> std::ffi::OsString {
    let mut s = std::ffi::OsString::from("sql:");
    s.push(dir);
    s
}

/// NSS's `certutil`, from the system's own directories only (`trusted_helper`): a `certutil`
/// earlier on `PATH` could write anything into the stores. A DEBUG build can be pointed at another
/// one (`KERN_TEST_CERTUTIL`), which is how the tests drive a stock Ubuntu that has none; the
/// variable means nothing to a release build.
fn certutil_tool() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(p) = crate::global_env("KERN_TEST_CERTUTIL") {
        return Some(PathBuf::from(p));
    }
    kern_isolation::trusted_helper("certutil")
}

/// What to install for `certutil`, by distribution.
const CERTUTIL_HINT: &str =
    "NSS's certutil writes the certificate stores Chrome and Firefox read; \
     install it (Debian, Ubuntu: `sudo apt install libnss3-tools`; Fedora: `sudo dnf install \
     nss-tools`; Arch: `sudo pacman -S nss`) and run `kern proxy trust` again";

/// Whether this is kern's own WSL distro, whose browsers are Windows' (`kern.exe` adds the authority
/// to Windows' store of the user).
fn in_kerns_wsl_distro() -> bool {
    Path::new(crate::wslentry::MARKER).exists()
}

/// `kern proxy trust`.
pub(crate) fn trust() -> Result<(), Error> {
    let p = paths().ok_or_else(|| Error::Cli("proxy trust: no home directory".to_string()))?;
    let wsl = in_kerns_wsl_distro();
    let stores = if wsl { Vec::new() } else { stores() };
    let tool = certutil_tool();
    // NOTHING IS MADE when nothing can be trusted: browsers are there and the tool is not.
    if !stores.is_empty() && tool.is_none() {
        return Err(Error::Cli(format!("proxy trust: {CERTUTIL_HINT}")));
    }
    ensure_authority(&p)?;
    let name = stored_name(&p);
    let mut added: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    if let Some(tool) = tool.as_deref() {
        for s in &stores {
            let db = sql(&s.dir);
            if s.create {
                use std::os::unix::fs::DirBuilderExt;
                let made = std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&s.dir)
                    .map_err(|e| e.to_string())
                    .and_then(|()| {
                        certutil(
                            tool,
                            &[
                                "-N".as_ref(),
                                "-d".as_ref(),
                                &db,
                                "--empty-password".as_ref(),
                            ],
                        )
                    });
                if let Err(e) = made {
                    failed.push(format!("{} ({e})", s.label));
                    continue;
                }
            }
            // Again on a store that has it already, replacing it: the same name, the same certificate.
            let _ = certutil(
                tool,
                &[
                    "-D".as_ref(),
                    "-d".as_ref(),
                    &db,
                    "-n".as_ref(),
                    name.as_ref(),
                ],
            );
            match certutil(
                tool,
                &[
                    "-A".as_ref(),
                    "-d".as_ref(),
                    &db,
                    "-n".as_ref(),
                    name.as_ref(),
                    "-t".as_ref(),
                    "C,,".as_ref(),
                    "-i".as_ref(),
                    p.cert.as_os_str(),
                ],
            ) {
                Ok(()) => added.push(s.dir.to_string_lossy().into_owned()),
                Err(e) => failed.push(format!("{} ({e})", s.label)),
            }
        }
    }
    if !failed.is_empty() && added.is_empty() && !stores.is_empty() {
        return Err(Error::Cli(format!(
            "proxy trust: the local CA could not be added to {}",
            failed.join(", ")
        )));
    }
    std::fs::write(&p.trusted, added.join("\n") + "\n")
        .map_err(|e| Error::Cli(format!("proxy trust: {}: {e}", p.trusted.display())))?;
    crate::localrouter::restart();
    let port = crate::localrouter::running_tls_port()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "8443".to_string());
    if wsl {
        // The browsers are Windows': `kern.exe` adds the CA to the user's store right after this when
        // `kern proxy trust` was typed in PowerShell, and says so.
        println!(
            "kern: https://<service>.<project>.localhost:{port}/ is on. Windows' browsers trust it \
             once it is in your Windows store: `kern proxy trust` in PowerShell puts it there."
        );
        return Ok(());
    }
    let into = if added.is_empty() {
        format!(
            "no browser store here; `curl --cacert {}` reaches them",
            p.cert.display()
        )
    } else {
        stores
            .iter()
            .filter(|s| added.iter().any(|a| Path::new(a) == s.dir))
            .map(|s| s.label.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "kern: https://<service>.<project>.localhost:{port}/ is on, trusted in {into}. \
         `kern proxy untrust` takes it back."
    );
    if !failed.is_empty() {
        eprintln!("kern: warning: not added to {}", failed.join(", "));
    }
    Ok(())
}

/// `kern proxy untrust`: out of every store it was added to (and any store that lists it), then
/// deleted. The router stops answering HTTPS.
pub(crate) fn untrust() -> Result<(), Error> {
    let p = paths().ok_or_else(|| Error::Cli("proxy untrust: no home directory".to_string()))?;
    let name = stored_name(&p);
    let mut dirs: Vec<PathBuf> = std::fs::read_to_string(&p.trusted)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(PathBuf::from)
        .collect();
    for s in stores() {
        if !dirs.contains(&s.dir) && !s.create {
            dirs.push(s.dir);
        }
    }
    let mut removed = 0;
    if let Some(tool) = certutil_tool() {
        for dir in &dirs {
            let db = sql(dir);
            // Every copy under this name, in case it was added twice by hand.
            while certutil(
                &tool,
                &[
                    "-D".as_ref(),
                    "-d".as_ref(),
                    &db,
                    "-n".as_ref(),
                    name.as_ref(),
                ],
            )
            .is_ok()
            {
                removed += 1;
            }
        }
    }
    let had = p.cert.is_file();
    for f in [&p.trusted, &p.cert, &p.key, &p.name] {
        let _ = std::fs::remove_file(f);
    }
    let _ = std::fs::remove_dir(&p.dir);
    crate::localrouter::restart();
    if removed > 0 {
        println!(
            "kern: https for the .localhost names is off; the local CA is deleted and out of {removed} \
             store(s)."
        );
    } else if had {
        println!("kern: https for the .localhost names is off; the local CA is deleted.");
    } else {
        println!("kern: there was no local CA to remove.");
    }
    Ok(())
}

/// `kern proxy status`.
pub(crate) fn status() -> Result<(), Error> {
    let Some(p) = paths() else {
        println!("https: off (no home directory)");
        return Ok(());
    };
    if !trusted() {
        println!("https: off (`kern proxy trust` turns it on)");
        return Ok(());
    }
    let stores = std::fs::read_to_string(&p.trusted)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    let port = crate::localrouter::running_tls_port()
        .map(|p| format!("on port {p}"))
        .unwrap_or_else(|| "(the router is not running: no box publishes a port)".to_string());
    let kept = if stores > 0 {
        format!(", trusted in {stores} store(s)")
    } else {
        String::new()
    };
    println!("https: on {port}; local CA {}{kept}", p.cert.display());
    Ok(())
}

/// `kern __local-ca` (hidden): the authority's name and certificate, for `kern.exe`, which adds it to
/// Windows' store of the user. Nothing when there is none.
pub(crate) fn print_authority() -> i32 {
    let Some(p) = paths() else {
        return 1;
    };
    match std::fs::read_to_string(&p.cert) {
        Ok(pem) if trusted() => {
            println!("{}", stored_name(&p));
            print!("{pem}");
            0
        }
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_are_made_only_for_the_names_the_router_routes() {
        for ok in [
            "web.shop.localhost",
            "8080.web.shop.localhost",
            "web-2.my_proj.localhost",
        ] {
            assert!(name_ok(ok), "{ok}");
        }
        for bad in [
            "localhost",
            "web.localhost",
            "a.b.c.d.localhost",
            "example.com",
            "web.shop.localhost.evil.com",
            "w$b.shop.localhost",
            "",
        ] {
            assert!(!name_ok(bad), "{bad}");
        }
    }

    /// The authority carries the constraint, critical, and signs a certificate for a routed name.
    #[test]
    fn the_authority_is_constrained_to_localhost_and_signs_a_name() {
        let Ok((cert, key)) = make_authority("kern local CA (test)") else {
            panic!("authority");
        };
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        let Ok(issuer) = authority_issuer("kern local CA (test)", &key) else {
            panic!("issuer");
        };
        let Ok((leaf, leaf_key)) = make_leaf("web.shop.localhost", &issuer) else {
            panic!("leaf");
        };
        assert!(!leaf.is_empty() && !leaf_key.is_empty());
        // The constraint is in the authority's DER, under the nameConstraints OID 2.5.29.30, marked
        // critical (the BOOLEAN TRUE that follows the OID).
        use rustls::pki_types::pem::PemObject;
        let Ok(der) = rustls::pki_types::CertificateDer::from_pem_slice(cert.as_bytes()) else {
            panic!("der");
        };
        let oid = [0x06u8, 0x03, 0x55, 0x1d, 0x1e];
        let at = der.windows(oid.len()).position(|w| w == oid);
        let Some(at) = at else {
            panic!("no nameConstraints extension");
        };
        assert_eq!(
            &der[at + oid.len()..at + oid.len() + 3],
            &[0x01, 0x01, 0xff],
            "critical"
        );
        assert!(der.windows(9).any(|w| w == b"localhost"));
    }
}
