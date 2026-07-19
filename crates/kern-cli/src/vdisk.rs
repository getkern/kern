//! Host-side ext4-on-loop backend for `vdisk:` profiles (the privileged upgrade over the rootless
//! `tmpfs` fallback). Faithful to the private runtime: a sparse ext4 image on a loop device gives a
//! real **disk-backed** size quota, `persistent` storage, and (best-effort) I/O limits - none of
//! which a RAM-backed tmpfs can do.
//!
//! It needs privilege: `/dev/loop-control` (root or the `disk` group) to grab a loop device, and
//! `CAP_SYS_ADMIN` to `mount` ext4. When any step is unavailable - the common rootless case - the
//! caller falls back to the tmpfs backend, so `vdisk:` always works.
//!
//! **Leak-safety:** the loop device is configured `LO_FLAGS_AUTOCLEAR`, so it detaches itself when
//! its last mount goes away (the box exits and its bind is torn down with the mount namespace) even
//! if kern is killed. On any setup failure we unwind immediately (detach + remove), so a half-built
//! vdisk never leaks a loop device or a stray mount.

use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

// linux/loop.h
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A; // Linux 5.8+ - fd + status in one ioctl
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LO_FLAGS_AUTOCLEAR: u32 = 4;

#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo64,
    reserved: [u64; 8],
}

#[repr(C)]
struct LoopInfo64 {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    sizelimit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}

/// A prepared ext4-on-loop vdisk mounted on the host at `mount`, ready to bind into the box.
pub struct Ext4Vdisk {
    image: PathBuf,
    loop_dev: String,
    /// Host mountpoint that the box binds at `/vdisk/<name>`.
    pub mount: PathBuf,
    persistent: bool,
    /// Holds an exclusive `flock` on a persistent image for the disk's lifetime, so two boxes can't
    /// double-mount the same backing ext4 (→ corruption). `None` for an ephemeral (per-pid) disk.
    _lock: Option<std::fs::File>,
}

impl Ext4Vdisk {
    /// The backing loop device's `major:minor`, for a cgroup `io.max` limit (`--iops`/`--bandwidth`).
    /// `None` if the device node can't be stat'd.
    pub fn loop_dev_num(&self) -> Option<(u32, u32)> {
        let c = cstr(&self.loop_dev)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
            return None;
        }
        let rdev = st.st_rdev;
        // glibc major()/minor() encoding.
        let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfffu64);
        let minor = (rdev & 0xff) | ((rdev >> 12) & !0xffu64);
        Some((major as u32, minor as u32))
    }
}

/// The default home for **persistent** vdisk images when the profile names no `[[disk]]` backend -
/// a stable per-user dir (sibling of the named-volumes dir). This is the for-dummies default: a
/// persistent vdisk survives without the user choosing where it lives (like a Docker volume location).
fn default_vdisk_dir() -> PathBuf {
    crate::volume::volumes_dir()
        .parent()
        .map(|p| p.join("vdisks"))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Try to build an ext4-on-loop vdisk of `size` bytes under `work` (a box-private scratch dir).
/// Returns `None` when privilege/loop devices aren't available (→ tmpfs fallback) or on any failure
/// (already cleaned up). `persistent` keeps the image across boxes; `iops`/`bandwidth` are applied
/// best-effort by the caller against the returned loop device.
pub fn prepare(
    name: &str,
    size: u64,
    persistent: bool,
    backend_dir: Option<&str>,
    work: &Path,
) -> Option<Ext4Vdisk> {
    // Defense-in-depth: the box side already guards the name, but this host-side path interpolates it
    // into the image/mount paths - refuse a name that could climb out (config is operator-owned here,
    // but keep the two layers consistent).
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return None;
    }
    // Fast-fail: need /dev/loop-control writable (root or `disk` group). Saves the mkfs work.
    let ctl = unsafe {
        libc::open(
            c"/dev/loop-control".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    if ctl < 0 {
        return None;
    }

    // Image path: a persistent disk lives under its [[disk]] backend dir (if the profile names one)
    // or a stable per-user default (so `persistent` "just works" without choosing a disk - the
    // for-dummies default); an ephemeral one lives in the box scratch (removed with it).
    let img = match (persistent, backend_dir) {
        (true, Some(d)) => PathBuf::from(d).join(format!("kern-vdisk-{name}.img")),
        (true, None) => default_vdisk_dir().join(format!("kern-vdisk-{name}.img")),
        _ => work.join(format!("vdisk-{name}.img")),
    };
    let mount = work.join(format!("vdisk-mnt-{name}"));

    // Create + size the image (skip mkfs if a persistent image already exists).
    let fresh = !img.exists();
    if fresh {
        if let Some(parent) = img.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::File::create(&img)
            .and_then(|f| f.set_len(size))
            .is_err()
        {
            let _ = std::fs::remove_file(&img); // don't leave a poisoned 0-byte image for reuse
            unsafe { libc::close(ctl) };
            return None;
        }
        // `-F` force, `-q` quiet, no journal = faster mount / less overhead on a loop image.
        let ok = std::process::Command::new("mkfs.ext4")
            .args(["-F", "-q", "-O", "^has_journal"])
            .arg(&img)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_file(&img);
            unsafe { libc::close(ctl) };
            return None;
        }
    }

    // Grab a free loop device.
    let num = unsafe { libc::ioctl(ctl, LOOP_CTL_GET_FREE as _) };
    unsafe { libc::close(ctl) };
    if num < 0 {
        cleanup_image(&img, persistent, fresh);
        return None;
    }
    let loop_dev = format!("/dev/loop{num}");

    // Attach the image to the loop device in one ioctl (autoclear so it self-detaches on last close).
    let backing = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&img)
    {
        Ok(f) => f,
        Err(_) => {
            cleanup_image(&img, persistent, fresh);
            return None;
        }
    };
    // Exclusive lock on a persistent image so two concurrent boxes can't double-mount the same
    // backing ext4 (→ corruption). Held for the disk's lifetime via `_lock` (released on teardown).
    // Ephemeral images live in a per-pid work dir and can't collide, so they don't need it.
    if persistent && unsafe { libc::flock(backing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        eprintln!("kern: vdisk '{name}' is in use by another box - using a tmpfs backend this run");
        cleanup_image(&img, persistent, fresh);
        return None;
    }
    let ldc = cstr(&loop_dev)?;
    let ld = unsafe { libc::open(ldc.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if ld < 0 {
        cleanup_image(&img, persistent, fresh);
        return None;
    }
    let mut cfg: LoopConfig = unsafe { std::mem::zeroed() };
    cfg.fd = backing.as_raw_fd() as u32;
    cfg.info.flags = LO_FLAGS_AUTOCLEAR;
    if unsafe { libc::ioctl(ld, LOOP_CONFIGURE as _, &cfg) } != 0 {
        unsafe { libc::close(ld) };
        cleanup_image(&img, persistent, fresh);
        return None;
    }

    // Mount ext4 while the loop fd is STILL OPEN - with LO_FLAGS_AUTOCLEAR the device self-detaches
    // the moment its open count hits zero, so closing `ld` *before* a mount holds a reference would
    // race the loop away and the mount would fail. Mount first, then close: the mount now holds the
    // reference, and autoclear only fires once it (and the box's bind of it) are gone.
    // Needs CAP_SYS_ADMIN - the step that fails on a non-root host → tmpfs fallback.
    let _ = std::fs::create_dir_all(&mount);
    // `nosuid`+`nodev`: a persistent/writable disk must not honour a device node or setuid binary
    // planted on it (parity with the private runtime). `noatime` for a small perf edge.
    let flags = (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOATIME) as libc::c_ulong;
    let mounted = match (
        cstr(&loop_dev),
        cstr(mount.to_str().unwrap_or("")),
        cstr("ext4"),
    ) {
        (Some(dev_c), Some(mnt_c), Some(ty_c)) => unsafe {
            libc::mount(
                dev_c.as_ptr(),
                mnt_c.as_ptr(),
                ty_c.as_ptr(),
                flags,
                std::ptr::null(),
            ) == 0
        },
        _ => false,
    };
    unsafe { libc::close(ld) };
    if !mounted {
        detach_loop(&loop_dev); // close above may already have autocleared it; idempotent
        cleanup_image(&img, persistent, fresh);
        return None;
    }

    Some(Ext4Vdisk {
        image: img,
        loop_dev,
        mount,
        persistent,
        // Keep the (flock'd, for persistent) backing fd alive for the disk's lifetime; the loop holds
        // its own reference, so this is only about retaining the lock.
        _lock: persistent.then_some(backing),
    })
}

/// Safety net: an error path (a `?` after the vdisk was prepared) that does NOT `exit` runs this and
/// cleans up. The success path calls `teardown()` explicitly before `std::process::exit`, which does
/// not run destructors - so both are needed, and `teardown` is idempotent.
impl Drop for Ext4Vdisk {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl Ext4Vdisk {
    /// Tear the vdisk down: lazy-unmount the host mountpoint (the box's bind, if still up, keeps the
    /// fs alive until it too goes; the loop auto-clears when the last mount drops), then remove an
    /// ephemeral image. Idempotent and best-effort.
    pub fn teardown(&self) {
        if let Some(m) = cstr(self.mount.to_str().unwrap_or("")) {
            unsafe { libc::umount2(m.as_ptr(), libc::MNT_DETACH) };
        }
        // AUTOCLEAR detaches the loop once its last mount is gone; force it too in case we hold the
        // only ref right now.
        detach_loop(&self.loop_dev);
        cleanup_image(&self.image, self.persistent, true);
        let _ = std::fs::remove_dir(&self.mount);
    }
}

fn detach_loop(dev: &str) {
    if let Some(c) = cstr(dev) {
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd >= 0 {
            unsafe {
                libc::ioctl(fd, LOOP_CLR_FD as _);
                libc::close(fd);
            }
        }
    }
}

/// Remove an ephemeral image (persistent ones are kept). `fresh` guards against deleting a
/// pre-existing persistent image we merely reused.
fn cleanup_image(img: &Path, persistent: bool, fresh: bool) {
    if !persistent && fresh {
        let _ = std::fs::remove_file(img);
    }
}

fn cstr(s: &str) -> Option<std::ffi::CString> {
    std::ffi::CString::new(s).ok()
}
