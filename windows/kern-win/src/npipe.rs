//! `kern compat docker pipe`: the Docker API for WINDOWS programs (Testcontainers for Java or .NET,
//! the `docker` CLI with `-H npipe:...`), on the named pipe `\\.\pipe\kern-docker`.
//!
//! NO TCP, ON PURPOSE. A port on localhost without authentication (Docker's old 2375) is open to
//! every process of every user on the machine, and would undo the point of the Linux socket being
//! `0600`. The pipe's security descriptor grants access to ONE account, the one running this
//! (its SID, read from the process token), remote clients are refused by the pipe itself
//! (`PIPE_REJECT_REMOTE_CLIENTS`), and the first instance is created with
//! `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a process that took the name first makes this fail instead
//! of serving clients beside it.
//!
//! EACH CONNECTION IS A BRIDGE OF BYTES to `kern compat docker __stdio` in the distro, which
//! connects to the API socket there (starting the server if none runs). The HTTP, and the streams an
//! attach or exec hands over, are the server's; this side copies bytes both ways.
//!
//! TEST SESSIONS. The server removes a Testcontainers session's containers when the process that
//! made them ends; it cannot watch a Windows process, so this does: the pipe's client process id
//! (`GetNamedPipeClientProcessId`) and creation time are the session's key, passed to the bridge,
//! and when that process ends (`WaitForSingleObject`) the distro is told
//! (`kern compat docker __session-ended <key>`).

#[cfg(windows)]
pub(crate) use imp::run;

#[cfg(not(windows))]
pub(crate) fn run(_wsl_prefix: Vec<String>) -> i32 {
    eprintln!("kern: compat docker pipe is for Windows");
    2
}

/// `<pid>-<creation time>`: a process key that a reused pid cannot match.
#[cfg(windows)]
pub(crate) fn peer_key(pid: u32, created: u64) -> String {
    format!("{pid}-{created}")
}

#[cfg(windows)]
mod imp {
    use std::collections::HashSet;
    use std::ffi::c_void;
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};

    type Handle = *mut c_void;
    type Bool = i32;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit: Bool,
    }

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: Handle,
    }

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_size: u32,
            in_size: u32,
            timeout_ms: u32,
            security: *mut SecurityAttributes,
        ) -> Handle;
        fn ConnectNamedPipe(pipe: Handle, overlapped: *mut Overlapped) -> Bool;
        fn DisconnectNamedPipe(pipe: Handle) -> Bool;
        fn CloseHandle(h: Handle) -> Bool;
        fn GetLastError() -> u32;
        fn CreateEventW(sa: *mut c_void, manual: Bool, initial: Bool, name: *const u16) -> Handle;
        fn ReadFile(
            h: Handle,
            buf: *mut c_void,
            n: u32,
            done: *mut u32,
            ov: *mut Overlapped,
        ) -> Bool;
        fn WriteFile(
            h: Handle,
            buf: *const c_void,
            n: u32,
            done: *mut u32,
            ov: *mut Overlapped,
        ) -> Bool;
        fn GetOverlappedResult(h: Handle, ov: *mut Overlapped, done: *mut u32, wait: Bool) -> Bool;
        fn CancelIoEx(h: Handle, ov: *mut Overlapped) -> Bool;
        fn GetNamedPipeClientProcessId(pipe: Handle, pid: *mut u32) -> Bool;
        fn OpenProcess(access: u32, inherit: Bool, pid: u32) -> Handle;
        fn GetProcessTimes(
            h: Handle,
            created: *mut FileTime,
            exited: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> Bool;
        fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
        fn GetCurrentProcess() -> Handle;
        fn LocalFree(p: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> Bool;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            len: u32,
            returned: *mut u32,
        ) -> Bool;
        fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> Bool;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> Bool;
    }

    const PIPE_NAME: &str = r"\\.\pipe\kern-docker";
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_TYPE_BYTE: u32 = 0;
    const PIPE_READMODE_BYTE: u32 = 0;
    const PIPE_WAIT: u32 = 0;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const ERROR_IO_PENDING: u32 = 997;
    const ERROR_PIPE_CONNECTED: u32 = 535;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const SDDL_REVISION_1: u32 = 1;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const INFINITE: u32 = 0xFFFF_FFFF;
    const BUF: usize = 64 * 1024;

    fn invalid(h: Handle) -> bool {
        h.is_null() || h as isize == -1
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A Win32 handle owned here, closed once. Raw handles may cross threads: the kernel object is
    /// shared, and each thread does its own overlapped I/O with its own event.
    struct Owned(Handle);
    // SAFETY: a HANDLE is an index into the process's handle table, valid from any thread.
    unsafe impl Send for Owned {}
    // SAFETY: as above; concurrent overlapped calls on one handle are what overlapped I/O is for.
    unsafe impl Sync for Owned {}
    impl Drop for Owned {
        fn drop(&mut self) {
            if !invalid(self.0) {
                // SAFETY: the handle is owned by this value and closed only here.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// The account running this, as a string SID (`S-1-5-21-...`), from the process token.
    fn user_sid() -> Option<String> {
        let mut token: Handle = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess is a pseudo-handle; OpenProcessToken writes `token`.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let token = Owned(token);
        let mut need = 0u32;
        // SAFETY: a size query: no buffer, `need` receives the size.
        unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_USER_CLASS,
                std::ptr::null_mut(),
                0,
                &mut need,
            )
        };
        if need == 0 || need > 4096 {
            return None;
        }
        // u64 storage keeps the TOKEN_USER (pointer first) aligned.
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        // SAFETY: `buf` holds `need` bytes, aligned for TOKEN_USER.
        if unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_USER_CLASS,
                buf.as_mut_ptr().cast(),
                need,
                &mut need,
            )
        } == 0
        {
            return None;
        }
        // TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first field is the SID pointer.
        let sid = buf[0] as usize as *mut c_void;
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` points into `buf`, alive here; the call allocates `text` with LocalAlloc.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
            return None;
        }
        let mut len = 0usize;
        // SAFETY: `text` is a NUL-terminated wide string from the call above.
        while unsafe { *text.add(len) } != 0 && len < 256 {
            len += 1;
        }
        // SAFETY: `len` u16s were just read from `text`.
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        // SAFETY: allocated by ConvertSidToStringSidW with LocalAlloc.
        unsafe { LocalFree(text.cast()) };
        s.starts_with("S-1-").then_some(s)
    }

    /// The security descriptor: full access for `sid`, nothing for anyone else, not inherited.
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn descriptor(sid: &str) -> Option<Descriptor> {
        let sddl = wide(&format!("D:P(A;;GA;;;{sid})"));
        let mut sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated; the call allocates `sd`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        (ok != 0 && !sd.is_null()).then_some(Descriptor(sd))
    }

    /// One pipe instance, waiting for a client. The first is created with
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE`: if the name is taken, this fails rather than share it.
    fn instance(sd: &Descriptor, first: bool) -> Result<Owned, u32> {
        let name = wide(PIPE_NAME);
        let mut sa = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: sd.0,
            inherit: 0,
        };
        let mode = PIPE_ACCESS_DUPLEX
            | FILE_FLAG_OVERLAPPED
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: `name` is NUL-terminated and `sa` lives across the call.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUF as u32,
                BUF as u32,
                0,
                &mut sa,
            )
        };
        if invalid(h) {
            // SAFETY: no preconditions.
            Err(unsafe { GetLastError() })
        } else {
            Ok(Owned(h))
        }
    }

    /// Overlapped I/O on `pipe` with this thread's `event`, waited for: bytes moved, `None` at the
    /// end of the connection or on an error (including a cancel from the other direction).
    fn transfer(
        pipe: Handle,
        event: Handle,
        buf: *mut u8,
        len: usize,
        write: bool,
    ) -> Option<usize> {
        let mut ov = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event,
        };
        let mut done = 0u32;
        let n = len.min(BUF) as u32;
        // SAFETY: `buf` holds `len` bytes owned by the caller across the wait below; `ov` too.
        let ok = unsafe {
            if write {
                WriteFile(pipe, buf.cast_const().cast(), n, &mut done, &mut ov)
            } else {
                ReadFile(pipe, buf.cast(), n, &mut done, &mut ov)
            }
        };
        // SAFETY: no preconditions.
        if ok == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return None;
        }
        // SAFETY: waits for the operation started above, which owns `ov` until it completes.
        if unsafe { GetOverlappedResult(pipe, &mut ov, &mut done, 1) } == 0 {
            return None;
        }
        (done > 0).then_some(done as usize)
    }

    fn event() -> Option<Owned> {
        // SAFETY: an unnamed manual-reset event; ReadFile/WriteFile reset it at each start.
        let e = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        (!invalid(e)).then_some(Owned(e))
    }

    /// Wait for a client on `pipe`: true when one is connected.
    fn accept(pipe: &Owned) -> bool {
        let Some(ev) = event() else { return false };
        let mut ov = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: ev.0,
        };
        // SAFETY: `ov` lives until the wait below completes.
        if unsafe { ConnectNamedPipe(pipe.0, &mut ov) } != 0 {
            return true;
        }
        // SAFETY: no preconditions.
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => true,
            ERROR_IO_PENDING => {
                let mut done = 0u32;
                // SAFETY: waits for the connect started above.
                unsafe { GetOverlappedResult(pipe.0, &mut ov, &mut done, 1) != 0 }
            }
            _ => false,
        }
    }

    /// The client process of a connected pipe, as a session key; `None` when it cannot be read.
    fn client_key(pipe: &Owned) -> Option<(String, Owned)> {
        let mut pid = 0u32;
        // SAFETY: writes the client's pid.
        if unsafe { GetNamedPipeClientProcessId(pipe.0, &mut pid) } == 0 || pid == 0 {
            return None;
        }
        // SAFETY: opening a process by id with query + synchronize rights only.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
        if invalid(h) {
            return None;
        }
        let proc_handle = Owned(h);
        let (mut c, mut e, mut k, mut u) = (
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
        );
        // SAFETY: four FILETIME out-parameters.
        if unsafe { GetProcessTimes(proc_handle.0, &mut c, &mut e, &mut k, &mut u) } == 0 {
            return None;
        }
        let created = (u64::from(c.high) << 32) | u64::from(c.low);
        Some((super::peer_key(pid, created), proc_handle))
    }

    /// The sessions already watched, so each Windows process gets one watcher.
    type Watched = Arc<Mutex<HashSet<String>>>;

    /// When the process behind `key` ends, tell the distro, which removes that session's containers.
    fn watch(key: String, proc_handle: Owned, watched: &Watched, wsl_prefix: &[String]) {
        let fresh = watched
            .lock()
            .map(|mut w| w.insert(key.clone()))
            .unwrap_or(false);
        if !fresh {
            return;
        }
        let watched = Arc::clone(watched);
        let mut argv = wsl_prefix.to_vec();
        argv.extend(["compat", "docker", "__session-ended"].map(String::from));
        argv.push(key.clone());
        let _ = std::thread::Builder::new()
            .name("kern-pipe-session".into())
            .spawn(move || {
                // The whole handle moves in (closed when this ends), not its raw field.
                let process = proc_handle;
                // SAFETY: a process handle opened with SYNCHRONIZE.
                unsafe { WaitForSingleObject(process.0, INFINITE) };
                let _ = Command::new("wsl.exe")
                    .args(&argv)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                if let Ok(mut w) = watched.lock() {
                    w.remove(&key);
                }
            });
    }

    /// Carry one connection: the pipe's bytes to the bridge's stdin, the bridge's stdout to the pipe.
    fn bridge(pipe: Owned, key: Option<String>, wsl_prefix: &[String]) {
        let mut argv = wsl_prefix.to_vec();
        argv.extend(["compat", "docker", "__stdio"].map(String::from));
        if let Some(k) = key {
            argv.push("--windows-peer".into());
            argv.push(k);
        }
        let Ok(mut child) = Command::new("wsl.exe")
            .args(&argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            // SAFETY: a connected instance owned here.
            unsafe { DisconnectNamedPipe(pipe.0) };
            return;
        };
        let pipe = Arc::new(pipe);
        let (Some(mut to_linux), Some(mut from_linux)) = (child.stdin.take(), child.stdout.take())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return;
        };
        let up = Arc::clone(&pipe);
        let lift = std::thread::spawn(move || {
            let Some(ev) = event() else { return };
            let mut buf = vec![0u8; BUF];
            while let Some(n) = transfer(up.0, ev.0, buf.as_mut_ptr(), buf.len(), false) {
                if to_linux
                    .write_all(&buf[..n])
                    .and_then(|()| to_linux.flush())
                    .is_err()
                {
                    break;
                }
            }
            // Dropping stdin tells the bridge the client is done sending.
        });
        if let Some(ev) = event() {
            let mut buf = vec![0u8; BUF];
            'copy: loop {
                let n = match from_linux.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut sent = 0;
                while sent < n {
                    // SAFETY: `buf[sent..n]` is initialised and lives across the call.
                    let ptr = unsafe { buf.as_mut_ptr().add(sent) };
                    match transfer(pipe.0, ev.0, ptr, n - sent, true) {
                        Some(m) => sent += m,
                        None => break 'copy,
                    }
                }
            }
        }
        // The answer side ended: stop the read still waiting on the client, then close.
        // SAFETY: cancels this process's I/O on the pipe; the reader's wait then returns.
        unsafe { CancelIoEx(pipe.0, std::ptr::null_mut()) };
        let _ = lift.join();
        let _ = child.kill();
        let _ = child.wait();
        // SAFETY: a connected instance; the Arc's last owner closes it on drop.
        unsafe { DisconnectNamedPipe(pipe.0) };
    }

    /// Serve `\\.\pipe\kern-docker` until stopped. `wsl_prefix` is the `wsl.exe` argv that reaches
    /// this user's kern in the distro (`-d <distro> --exec <kern>`).
    pub(crate) fn run(wsl_prefix: Vec<String>) -> i32 {
        let Some(sid) = user_sid() else {
            eprintln!("kern: compat docker pipe: cannot read this account's SID from its token");
            return 1;
        };
        let Some(sd) = descriptor(&sid) else {
            eprintln!("kern: compat docker pipe: cannot build the pipe's security descriptor");
            return 1;
        };
        let watched: Watched = Arc::new(Mutex::new(HashSet::new()));
        let mut first = true;
        loop {
            let pipe = match instance(&sd, first) {
                Ok(p) => p,
                Err(ERROR_ACCESS_DENIED) if first => {
                    eprintln!(
                        "kern: compat docker pipe: {PIPE_NAME} is held by another process: not shared"
                    );
                    return 1;
                }
                Err(e) => {
                    eprintln!("kern: compat docker pipe: cannot create {PIPE_NAME} (error {e})");
                    return 1;
                }
            };
            if first {
                // Only now: the name is this process's.
                eprintln!(
                    "kern: the Docker API on {PIPE_NAME}, for this account only ({sid})\n  \
                     set DOCKER_HOST=npipe:////./pipe/kern-docker\n  set TESTCONTAINERS_RYUK_DISABLED=true"
                );
            }
            first = false;
            if !accept(&pipe) {
                continue;
            }
            let key = client_key(&pipe).map(|(k, proc_handle)| {
                watch(k.clone(), proc_handle, &watched, &wsl_prefix);
                k
            });
            let prefix = wsl_prefix.clone();
            let _ = std::thread::Builder::new()
                .name("kern-pipe-conn".into())
                .spawn(move || bridge(pipe, key, &prefix));
        }
    }
}
