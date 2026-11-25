//! Two TCP rules in the network namespace of a box behind pasta, written as nftables netlink
//! messages by hand (as [`crate::netlink`] writes its RTNETLINK ones), so no `nft` binary is needed.
//!
//! WHAT THEY MEND. pasta stands in for every remote host: a box's SYN is answered by pasta, which
//! `connect()`s on the host and only then answers the box. Two behaviours of the pasta that Ubuntu
//! 24.04 ships (`0.0~git20240220`) cost a box what they cost no Docker container. MEASURED on this
//! desktop against a server of the host, kern and Docker run alternately:
//!
//! - A CLOSED PORT HUNG UNTIL THE CLIENT GAVE UP. pasta answers the box's SYN with a RST that has no
//!   ACK, and a Linux socket in SYN-SENT discards such a RST (RFC 793), so the box sent its SYN again
//!   every second: `wget` of a closed port ran its whole 20 s timeout where Docker said "Connection
//!   refused" in 311 ms. passt fixed it upstream on 2025-01-21 (`db2c91ae`, "Set ACK flag on *all*
//!   RST segments, even for client in SYN-SENT state").
//! - ONE LOST SYN COST TWO SECONDS. When the remote drops the first SYN, the host retries it after a
//!   second, and so does the box; the box's copy reaches pasta first, and that pasta resets the
//!   connection it is still making, so the box starts over a second later: 2029 ms against 1000-1059
//!   for Docker and for the host itself, with a server that drops the first SYN. Edges drop SYNs that
//!   arrive in a burst (curl from the host: 40 of 300 in bursts of 20, 1 of 300 spread over 1.5 s),
//!   and a kern box starts in 30 ms, so its connections burst. Fixed upstream on 2025-02-03
//!   (`722d347c`, "Don't reset outbound connection on SYN retries").
//!
//! THE RULES, on pasta's interface only (a pod's bridge is not touched):
//!
//! 1. A box's SYN for a connection pasta is still making is not sent again: the first goes, and the
//!    retries are the HOST's, as under Docker, where the box's SYN itself crosses the NAT. Kept for
//!    [`PENDING_MS`], under pasta's own SYN timeout, and dropped when the SYN-ACK arrives.
//! 2. A RST without ACK from pasta marks the connection refused, and the box's next SYN for it is
//!    answered by this namespace's own RST|ACK, which the socket takes: `ECONNREFUSED` a second
//!    after the SYN instead of at the client's timeout.
//!
//! Both are inert under a pasta that has the fixes: its RST carries the ACK, so rule 2 never matches,
//! and it ignores a repeated SYN, so rule 1 only spares it a packet. That is why no version is read.
//!
//! WITH THE RULES, same host, same servers: the closed port is refused in 1081-1088 ms (one SYN
//! retry; Docker's 311 ms is a RST the box's socket takes at once, which this namespace cannot
//! forge before that retry), the first-SYN drop costs 1000-1010 ms, and 500 fetches from
//! example.com in bursts of 20 had none over 1.5 s (23 of 300 before). A box's start does not move:
//! 200 paired `kern run --rm alpine true` with `scripts/ab-measure.py`, -108 us, 95% [-383, +218].

use std::io;

const NETLINK_NETFILTER: libc::c_int = 12;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_NEWSET: u16 = 9;

const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;
const NLMSG_ERROR: u16 = 2;
const NLA_F_NESTED: u16 = 0x8000;

const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const NF_INET_LOCAL_IN: u32 = 1;
const NF_INET_LOCAL_OUT: u32 = 3;
const NF_DROP: u32 = 0;

// Attribute numbers, from `linux/netfilter/nf_tables.h`.
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_ID: u16 = 10;
const NFTA_SET_TIMEOUT: u16 = 11;
const NFT_SET_TIMEOUT: u32 = 0x10;
const NFT_SET_EVAL: u32 = 0x20;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_LOOKUP_SET: u16 = 1;
const NFTA_LOOKUP_SREG: u16 = 2;
const NFTA_LOOKUP_SET_ID: u16 = 4;
const NFTA_DYNSET_SET_NAME: u16 = 1;
const NFTA_DYNSET_SET_ID: u16 = 2;
const NFTA_DYNSET_OP: u16 = 3;
const NFTA_DYNSET_SREG_KEY: u16 = 4;
const NFT_DYNSET_OP_ADD: u32 = 0;
const NFT_DYNSET_OP_DELETE: u32 = 2;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_REJECT_TYPE: u16 = 1;
const NFT_REJECT_TCP_RST: u32 = 1;

/// `NFT_REG_VERDICT`, `NFT_REG_1` (16 bytes, the flags) and `NFT_REG32_00` (where a key starts).
const REG_VERDICT: u32 = 0;
const REG_1: u32 = 1;
const REG32_00: u32 = 8;

const TABLE: &str = "kern";
/// How long a box's SYN is held back for a connection pasta is making: under the 10 s after which
/// pasta gives up on one, so a retry still reaches it if pasta lost the first.
pub const PENDING_MS: u64 = 9_000;
/// How long a connection pasta refused stays refused: past the box's next SYN, a second later.
const REFUSED_MS: u64 = 3_000;

const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    out.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align4(out.len()), 0);
}

fn attr_u32(out: &mut Vec<u8>, kind: u16, v: u32) {
    attr(out, kind, &v.to_be_bytes());
}

fn attr_str(out: &mut Vec<u8>, kind: u16, s: &str) {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    attr(out, kind, &v);
}

fn nest(out: &mut Vec<u8>, kind: u16, f: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
    f(out);
    let len = (out.len() - at) as u16;
    out[at..at + 2].copy_from_slice(&len.to_ne_bytes());
}

/// One expression of a rule: `NFTA_LIST_ELEM { NFTA_EXPR_NAME, NFTA_EXPR_DATA { .. } }`.
fn expr(out: &mut Vec<u8>, name: &str, data: impl FnOnce(&mut Vec<u8>)) {
    nest(out, NFTA_LIST_ELEM, |e| {
        attr_str(e, NFTA_EXPR_NAME, name);
        nest(e, NFTA_EXPR_DATA, data);
    });
}

fn meta(out: &mut Vec<u8>, key: u32, dreg: u32) {
    expr(out, "meta", |d| {
        attr_u32(d, NFTA_META_KEY, key);
        attr_u32(d, NFTA_META_DREG, dreg);
    });
}

fn cmp_eq(out: &mut Vec<u8>, sreg: u32, value: &[u8]) {
    expr(out, "cmp", |d| {
        attr_u32(d, NFTA_CMP_SREG, sreg);
        attr_u32(d, NFTA_CMP_OP, NFT_CMP_EQ);
        nest(d, NFTA_CMP_DATA, |v| attr(v, NFTA_DATA_VALUE, value));
    });
}

fn payload(out: &mut Vec<u8>, base: u32, offset: u32, len: u32, dreg: u32) {
    expr(out, "payload", |d| {
        attr_u32(d, NFTA_PAYLOAD_DREG, dreg);
        attr_u32(d, NFTA_PAYLOAD_BASE, base);
        attr_u32(d, NFTA_PAYLOAD_OFFSET, offset);
        attr_u32(d, NFTA_PAYLOAD_LEN, len);
    });
}

/// `tcp flags & mask == want`, through `NFT_REG_1`.
fn tcp_flags(out: &mut Vec<u8>, mask: u8, want: u8) {
    payload(out, NFT_PAYLOAD_TRANSPORT_HEADER, 13, 1, REG_1);
    expr(out, "bitwise", |d| {
        attr_u32(d, NFTA_BITWISE_SREG, REG_1);
        attr_u32(d, NFTA_BITWISE_DREG, REG_1);
        attr_u32(d, NFTA_BITWISE_LEN, 1);
        nest(d, NFTA_BITWISE_MASK, |v| attr(v, NFTA_DATA_VALUE, &[mask]));
        nest(d, NFTA_BITWISE_XOR, |v| attr(v, NFTA_DATA_VALUE, &[0]));
    });
    cmp_eq(out, REG_1, &[want]);
}

/// What every rule starts with, cheapest refusal first: TCP, then the flags (a data segment, almost
/// every packet, has neither SYN nor RST and leaves here), then the interface (`iifname`/`oifname`,
/// padded to `IFNAMSIZ` as the kernel compares it) and the family. MEASURED on 1 GiB through pasta
/// from a server of the host, 4 runs each: 259-271 ms with the rules, 242-261 without.
fn prologue(out: &mut Vec<u8>, ifkey: u32, ifname: &str, family: u8, mask: u8, want: u8) {
    meta(out, NFT_META_L4PROTO, REG_1);
    cmp_eq(out, REG_1, &[libc::IPPROTO_TCP as u8]);
    tcp_flags(out, mask, want);
    let mut name = [0u8; 16];
    let n = ifname.len().min(15);
    name[..n].copy_from_slice(&ifname.as_bytes()[..n]);
    meta(out, ifkey, REG_1);
    cmp_eq(out, REG_1, &name);
    meta(out, NFT_META_NFPROTO, REG_1);
    cmp_eq(out, REG_1, &[family]);
}

/// The key every set holds: the remote address, the remote port, the box's port, loaded from the
/// packet's `remote` side (`src` for one coming in, `dst` for one going out) into consecutive 32-bit
/// registers from `NFT_REG32_00`.
fn key(out: &mut Vec<u8>, family: u8, remote_is_src: bool) {
    let (addr_off, addr_len) = match (family, remote_is_src) {
        (NFPROTO_IPV4, true) => (12, 4),
        (NFPROTO_IPV4, false) => (16, 4),
        (_, true) => (8, 16),
        (_, false) => (24, 16),
    };
    let (rport, lport) = if remote_is_src { (0, 2) } else { (2, 0) };
    payload(
        out,
        NFT_PAYLOAD_NETWORK_HEADER,
        addr_off,
        addr_len,
        REG32_00,
    );
    let next = REG32_00 + addr_len / 4;
    payload(out, NFT_PAYLOAD_TRANSPORT_HEADER, rport, 2, next);
    payload(out, NFT_PAYLOAD_TRANSPORT_HEADER, lport, 2, next + 1);
}

fn dynset(out: &mut Vec<u8>, set: &str, id: u32, op: u32) {
    expr(out, "dynset", |d| {
        attr_str(d, NFTA_DYNSET_SET_NAME, set);
        attr_u32(d, NFTA_DYNSET_SET_ID, id);
        attr_u32(d, NFTA_DYNSET_OP, op);
        attr_u32(d, NFTA_DYNSET_SREG_KEY, REG32_00);
    });
}

fn lookup(out: &mut Vec<u8>, set: &str, id: u32) {
    expr(out, "lookup", |d| {
        attr_str(d, NFTA_LOOKUP_SET, set);
        attr_u32(d, NFTA_LOOKUP_SET_ID, id);
        attr_u32(d, NFTA_LOOKUP_SREG, REG32_00);
    });
}

fn drop_verdict(out: &mut Vec<u8>) {
    expr(out, "immediate", |d| {
        attr_u32(d, NFTA_IMMEDIATE_DREG, REG_VERDICT);
        nest(d, NFTA_IMMEDIATE_DATA, |v| {
            nest(v, NFTA_DATA_VERDICT, |c| {
                attr_u32(c, NFTA_VERDICT_CODE, NF_DROP)
            });
        });
    });
}

fn reject_rst(out: &mut Vec<u8>) {
    expr(out, "reject", |d| {
        attr_u32(d, NFTA_REJECT_TYPE, NFT_REJECT_TCP_RST)
    });
}

/// A batch of nftables messages, framed by `BATCH_BEGIN`/`BATCH_END`, every message but the frame
/// asking for an acknowledgement.
struct Batch {
    buf: Vec<u8>,
    seq: u32,
    acked: u32,
}

impl Batch {
    fn new() -> Batch {
        let mut b = Batch {
            buf: Vec::with_capacity(4096),
            seq: 0,
            acked: 0,
        };
        b.frame(NFNL_MSG_BATCH_BEGIN);
        b
    }

    fn header(&mut self, kind: u16, flags: u16, family: u8, res_id: u16) -> usize {
        self.seq += 1;
        let at = self.buf.len();
        self.buf.extend_from_slice(&0u32.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(&flags.to_ne_bytes());
        self.buf.extend_from_slice(&self.seq.to_ne_bytes());
        self.buf.extend_from_slice(&0u32.to_ne_bytes());
        // `struct nfgenmsg`: family, version, resource id (big-endian).
        self.buf.extend_from_slice(&[family, 0]);
        self.buf.extend_from_slice(&res_id.to_be_bytes());
        at
    }

    fn close(&mut self, at: usize) {
        let len = (self.buf.len() - at) as u32;
        self.buf[at..at + 4].copy_from_slice(&len.to_ne_bytes());
    }

    fn frame(&mut self, kind: u16) {
        let at = self.header(kind, NLM_F_REQUEST, 0, NFNL_SUBSYS_NFTABLES);
        self.close(at);
    }

    fn msg(&mut self, cmd: u16, flags: u16, body: impl FnOnce(&mut Vec<u8>)) {
        let at = self.header(
            (NFNL_SUBSYS_NFTABLES << 8) | cmd,
            NLM_F_REQUEST | NLM_F_ACK | flags,
            NFPROTO_INET,
            0,
        );
        body(&mut self.buf);
        self.close(at);
        self.acked += 1;
    }

    fn rule(&mut self, chain: &str, exprs: impl FnOnce(&mut Vec<u8>)) {
        self.msg(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND, |b| {
            attr_str(b, NFTA_RULE_TABLE, TABLE);
            attr_str(b, NFTA_RULE_CHAIN, chain);
            nest(b, NFTA_RULE_EXPRESSIONS, exprs);
        });
    }

    fn finish(mut self) -> (Vec<u8>, u32) {
        self.frame(NFNL_MSG_BATCH_END);
        (self.buf, self.acked)
    }
}

fn set_name(base: &str, family: u8) -> String {
    format!("{base}{}", if family == NFPROTO_IPV4 { 4 } else { 6 })
}

/// The whole table as one batch. PURE: what goes on the wire, for a test to read. `with_delete`
/// adds the rule that forgets a pending SYN at its SYN-ACK, a `dynset` delete, which kernels before
/// 5.13 refuse: the caller sends the batch without it when they do.
fn table_batch(ifname: &str, with_delete: bool) -> (Vec<u8>, u32) {
    let mut b = Batch::new();
    // EXCLUSIVE: a table already there is an earlier attach's (a pod's pasta comes back on a restart,
    // on the same interface), whose rules stand, and the batch answers EEXIST. Not removed and made
    // again: deleting a table is a grace period of the kernel's, MEASURED at 5-15 ms of a box's
    // start where the whole batch is 0.15 ms.
    b.msg(NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_EXCL, |m| {
        attr_str(m, NFTA_TABLE_NAME, TABLE)
    });
    for (chain, hook) in [("in", NF_INET_LOCAL_IN), ("out", NF_INET_LOCAL_OUT)] {
        b.msg(NFT_MSG_NEWCHAIN, NLM_F_CREATE, |m| {
            attr_str(m, NFTA_CHAIN_TABLE, TABLE);
            attr_str(m, NFTA_CHAIN_NAME, chain);
            nest(m, NFTA_CHAIN_HOOK, |h| {
                attr_u32(h, NFTA_HOOK_HOOKNUM, hook);
                attr_u32(h, NFTA_HOOK_PRIORITY, 0);
            });
            attr_str(m, NFTA_CHAIN_TYPE, "filter");
        });
    }
    let mut id = 0;
    for family in [NFPROTO_IPV4, NFPROTO_IPV6] {
        let key_len = if family == NFPROTO_IPV4 { 12 } else { 24 };
        let (pending, refused) = (set_name("pending", family), set_name("refused", family));
        let (pending_id, refused_id) = (id + 1, id + 2);
        id += 2;
        for (name, sid, ms) in [
            (&pending, pending_id, PENDING_MS),
            (&refused, refused_id, REFUSED_MS),
        ] {
            b.msg(NFT_MSG_NEWSET, NLM_F_CREATE, |m| {
                attr_str(m, NFTA_SET_TABLE, TABLE);
                attr_str(m, NFTA_SET_NAME, name);
                attr_u32(m, NFTA_SET_FLAGS, NFT_SET_TIMEOUT | NFT_SET_EVAL);
                attr_u32(m, NFTA_SET_KEY_LEN, key_len);
                attr_u32(m, NFTA_SET_ID, sid);
                attr(m, NFTA_SET_TIMEOUT, &ms.to_be_bytes());
            });
        }
        // IN: a RST without ACK, which a socket in SYN-SENT discards, marks the connection refused.
        b.rule("in", |e| {
            prologue(
                e,
                NFT_META_IIFNAME,
                ifname,
                family,
                TCP_RST | TCP_ACK,
                TCP_RST,
            );
            key(e, family, true);
            dynset(e, &refused, refused_id, NFT_DYNSET_OP_ADD);
        });
        if with_delete {
            // IN: the SYN-ACK ends the wait, so a new connection on the same ports is not held back.
            b.rule("in", |e| {
                prologue(
                    e,
                    NFT_META_IIFNAME,
                    ifname,
                    family,
                    TCP_SYN | TCP_ACK,
                    TCP_SYN | TCP_ACK,
                );
                key(e, family, true);
                dynset(e, &pending, pending_id, NFT_DYNSET_OP_DELETE);
            });
        }
        // OUT, in this order: a refused connection's SYN gets a RST|ACK from here, a SYN for a
        // connection pasta is still making is held back, and any other SYN starts one.
        b.rule("out", |e| {
            prologue(
                e,
                NFT_META_OIFNAME,
                ifname,
                family,
                TCP_SYN | TCP_ACK,
                TCP_SYN,
            );
            key(e, family, false);
            lookup(e, &refused, refused_id);
            reject_rst(e);
        });
        b.rule("out", |e| {
            prologue(
                e,
                NFT_META_OIFNAME,
                ifname,
                family,
                TCP_SYN | TCP_ACK,
                TCP_SYN,
            );
            key(e, family, false);
            lookup(e, &pending, pending_id);
            drop_verdict(e);
        });
        b.rule("out", |e| {
            prologue(
                e,
                NFT_META_OIFNAME,
                ifname,
                family,
                TCP_SYN | TCP_ACK,
                TCP_SYN,
            );
            key(e, family, false);
            dynset(e, &pending, pending_id, NFT_DYNSET_OP_ADD);
        });
    }
    b.finish()
}

/// Send a batch on a fresh `NETLINK_NETFILTER` socket of THIS network namespace and read its `acks`
/// acknowledgements; the first error is the answer. Bounded by a one-second receive timeout.
fn send_batch(batch: &[u8], acks: u32) -> io::Result<()> {
    // SAFETY: a socket/bind/send/recv sequence on a netlink socket, every buffer sized from the
    // value written into it, the descriptor closed on every path.
    unsafe {
        let sock = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_NETFILTER,
        );
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        let close = |e: io::Error| {
            libc::close(sock);
            Err(e)
        };
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        if libc::bind(
            sock,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) != 0
        {
            return close(io::Error::last_os_error());
        }
        if libc::send(sock, batch.as_ptr().cast(), batch.len(), 0) < 0 {
            return close(io::Error::last_os_error());
        }
        let mut got = 0;
        let mut buf = vec![0u8; 16384];
        while got < acks {
            let n = libc::recv(sock, buf.as_mut_ptr().cast(), buf.len(), 0);
            if n < 0 {
                return close(io::Error::last_os_error());
            }
            let n = n as usize;
            let mut off = 0;
            while off + 20 <= n {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                let kind = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                if len < 16 || off + len > n {
                    break;
                }
                if kind == NLMSG_ERROR {
                    let err = i32::from_ne_bytes([
                        buf[off + 16],
                        buf[off + 17],
                        buf[off + 18],
                        buf[off + 19],
                    ]);
                    if err != 0 {
                        return close(io::Error::from_raw_os_error(-err));
                    }
                    got += 1;
                }
                off += align4(len);
            }
        }
        libc::close(sock);
        Ok(())
    }
}

/// Install the two rules in the network namespace this process is in, for pasta's interface
/// `ifname`. Without the SYN-ACK cleanup on a kernel that refuses a `dynset` delete.
pub fn install_here(ifname: &str) -> io::Result<()> {
    let (full, acks) = table_batch(ifname, true);
    match send_batch(&full, acks) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Err(e)
            if e.raw_os_error() == Some(libc::EOPNOTSUPP)
                || e.raw_os_error() == Some(libc::EINVAL) =>
        {
            let (plain, acks) = table_batch(ifname, false);
            send_batch(&plain, acks)
        }
        Err(e) => Err(e),
    }
}

/// [`install_here`] in the user and network namespaces of `pid1`, from a child forked for it, so
/// the caller's own namespaces are untouched. The child enters them as the port forwarders do
/// ([`crate::ports`]), pinned to one generation of the pid.
///
/// STARTED, NOT WAITED: the caller starts pasta meanwhile and reaps this with [`Install::wait`]. The
/// rules name pasta's interface rather than its index, so they can precede it. MEASURED with
/// `scripts/ab-measure.py` (120 paired `kern run --rm alpine true`): waited for in line, the child
/// cost +567 us of every start (95% [+299, +904]).
pub fn start_install(pid1: i32, ifname: &str) -> io::Result<Install> {
    // SAFETY: fork; the child only enters namespaces, talks netlink and `_exit`s.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        let code = if !crate::ports::enter_box_ns_pinned(pid1, 0) {
            100
        } else {
            match install_here(ifname) {
                Ok(()) => 0,
                Err(e) => e.raw_os_error().unwrap_or(101).clamp(1, 99),
            }
        };
        // SAFETY: `_exit` in the forked child, no destructors of the parent's state run.
        unsafe { libc::_exit(code) };
    }
    Ok(Install { child, pid1 })
}

/// A [`start_install`] under way.
pub struct Install {
    child: libc::pid_t,
    pid1: i32,
}

impl Install {
    /// Reap the child; its exit code is the outcome.
    pub fn wait(mut self) -> io::Result<()> {
        let child = std::mem::replace(&mut self.child, -1);
        let mut st = 0;
        // SAFETY: waiting for the child this value owns, once: `Drop` sees -1 after this.
        while unsafe { libc::waitpid(child, &mut st, 0) } < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
        match (libc::WIFEXITED(st), libc::WEXITSTATUS(st)) {
            (true, 0) => Ok(()),
            (true, 100) => Err(io::Error::other(format!(
                "could not enter the namespaces of {}",
                self.pid1
            ))),
            (true, c) if c < 100 => Err(io::Error::from_raw_os_error(c)),
            _ => Err(io::Error::other("the nftables helper did not finish")),
        }
    }
}

/// A path that returns before [`Install::wait`] (pasta failed) still reaps the child: no zombie is
/// left to the process that started it.
impl Drop for Install {
    fn drop(&mut self) {
        if self.child > 0 {
            let mut st = 0;
            // SAFETY: the child this value owns, not yet reaped.
            unsafe { libc::waitpid(self.child, &mut st, 0) };
        }
    }
}

/// Can this host take the rules? [`install_here`] in a user and network namespace made for the
/// question and gone with it: what `kern info` reports, so a host whose kernel has no nftables says
/// that its boxes keep pasta's behaviour.
pub fn probe() -> io::Result<()> {
    // SAFETY: fork; the child unshares its own namespaces, installs, and `_exit`s.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        // SAFETY: plain syscalls in the forked child.
        let code = unsafe {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                100
            } else {
                match install_here("eth0") {
                    Ok(()) => 0,
                    Err(e) => e.raw_os_error().unwrap_or(101).clamp(1, 99),
                }
            }
        };
        // SAFETY: `_exit` in the forked child.
        unsafe { libc::_exit(code) };
    }
    Install { child, pid1: 0 }
        .wait()
        .map_err(|e| match e.raw_os_error() {
            None => io::Error::other("no user and network namespace could be made to try"),
            Some(_) => e,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The batch is framed (BEGIN first, END last, both of the nftables subsystem), every message's
    /// length adds up to the whole, and one acknowledgement is expected per message but the frame.
    #[test]
    fn the_batch_is_framed_and_its_lengths_add_up() {
        for with_delete in [true, false] {
            let (buf, acks) = table_batch("eth0", with_delete);
            let mut off = 0;
            let mut kinds = Vec::new();
            while off < buf.len() {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                assert!(len >= 20 && off + len <= buf.len(), "message at {off}");
                kinds.push(u16::from_ne_bytes([buf[off + 4], buf[off + 5]]));
                off += align4(len);
            }
            assert_eq!(off, buf.len());
            assert_eq!(kinds.first(), Some(&NFNL_MSG_BATCH_BEGIN));
            assert_eq!(kinds.last(), Some(&NFNL_MSG_BATCH_END));
            assert_eq!(kinds.len() as u32, acks + 2);
            // 1 table, 2 chains, per family 2 sets and 4 rules (5 with the delete).
            let per_family = if with_delete { 7 } else { 6 };
            assert_eq!(acks, 1 + 2 + 2 * per_family);
        }
    }

    /// The batch the kernel is sent is one it takes, in a namespace of this test's own; and a second
    /// install on the same namespace is the EEXIST that means "already there", answered as success.
    #[test]
    fn the_kernel_takes_the_batch_and_a_second_install_is_success() {
        match probe() {
            Ok(()) => {}
            // A host without user namespaces or nftables cannot say anything about the batch.
            Err(e) if e.kind() == io::ErrorKind::Other => {
                eprintln!("skip: {e}");
                return;
            }
            Err(e) => panic!("the kernel refused the batch: {e}"),
        }
        // SAFETY: fork; the child unshares and exits with the second install's outcome.
        let child = unsafe { libc::fork() };
        if child == 0 {
            let code = unsafe {
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                    100
                } else if install_here("eth0").is_ok() && install_here("eth0").is_ok() {
                    0
                } else {
                    1
                }
            };
            unsafe { libc::_exit(code) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(child, &mut st, 0) };
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) != 1,
            "second install failed"
        );
    }
}
