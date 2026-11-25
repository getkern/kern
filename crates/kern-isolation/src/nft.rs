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
//!    [`PENDING_MS`], under pasta's own SYN timeout, keyed by the SYN's sequence number too, so a new
//!    connection on the same ports (another ISN) is not held.
//! 2. A RST without ACK from pasta marks the connection refused, and the box's next SYN for it is
//!    answered by this namespace's own RST|ACK, which the socket takes: `ECONNREFUSED` a second
//!    after the SYN instead of at the client's timeout.
//!
//! 3. A segment from pasta with none of SYN, RST and ACK is dropped before connection tracking, as a
//!    socket's own stack drops it. Only a connection the box forwards ever noticed it (see the rule).
//!
//! Rules 1 and 2 are inert under a pasta that has the fixes: its RST carries the ACK, so rule 2 never
//! matches, and it ignores a repeated SYN, so rule 1 only spares it a packet. Rule 3 drops only what
//! every socket drops, so a connection that ends in the box sees no change under any pasta. That is
//! why no version is read.
//! MEASURED with passt's own build of 2026-10-02 ahead in `PATH`, the rules installed: a closed port
//! refused in 13 ms, a dropped first SYN 1009-1060 ms.
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
const NF_INET_PRE_ROUTING: u32 = 0;
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
///
/// WHAT IT COSTS IF PASTA DID LOSE ONE: the box waits this long. The one way found for a SYN not to
/// reach pasta is the box's interface queue overflowing, and it does not drop: MEASURED, a box
/// sending 3-3.8 GB to the host on 4 connections at full speed while opening 200 more, 0 packets
/// dropped on its interface (`/proc/net/dev`), no connection over 4 ms. A full queue makes the
/// sender wait. Kept rather than shortened: a retry let through while the old pasta is still
/// connecting is reset by it, and that RST would read here as a refusal.
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
/// registers from `NFT_REG32_00`; with `seq`, the segment's sequence number after them, which is
/// what tells a SYN sent again (the same ISN) from a new connection on the same ports.
fn key(out: &mut Vec<u8>, family: u8, remote_is_src: bool, seq: bool) {
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
    if seq {
        payload(out, NFT_PAYLOAD_TRANSPORT_HEADER, 4, 4, next + 2);
    }
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

/// The whole table as one batch. PURE: what goes on the wire, for a test to read.
///
/// A HELD-BACK SYN IS KEYED BY ITS SEQUENCE NUMBER TOO, so nothing has to forget it: a SYN sent
/// again carries the ISN of the first, a new connection on the same ports another. The first form
/// forgot the entry at the SYN-ACK with a `dynset` delete, an operation older kernels do not have,
/// and without it a new connection from the same port waited out the 9 s.
fn table_batch(ifname: &str) -> (Vec<u8>, u32) {
    let mut b = Batch::new();
    // EXCLUSIVE: a table already there is an earlier attach's (a pod's pasta comes back on a restart,
    // on the same interface), whose rules stand, and the batch answers EEXIST. Not removed and made
    // again: deleting a table is a grace period of the kernel's, MEASURED at 5-15 ms of a box's
    // start where the whole batch is 0.15 ms.
    b.msg(NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_EXCL, |m| {
        attr_str(m, NFTA_TABLE_NAME, TABLE)
    });
    // `pre` at -300, ahead of connection tracking (-200): see the rule it holds.
    for (chain, hook, prio) in [
        ("pre", NF_INET_PRE_ROUTING, -300i32),
        ("in", NF_INET_LOCAL_IN, 0),
        ("out", NF_INET_LOCAL_OUT, 0),
    ] {
        b.msg(NFT_MSG_NEWCHAIN, NLM_F_CREATE, |m| {
            attr_str(m, NFTA_CHAIN_TABLE, TABLE);
            attr_str(m, NFTA_CHAIN_NAME, chain);
            nest(m, NFTA_CHAIN_HOOK, |h| {
                attr_u32(h, NFTA_HOOK_HOOKNUM, hook);
                attr_u32(h, NFTA_HOOK_PRIORITY, prio as u32);
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
        for (name, sid, ms, len) in [
            (&pending, pending_id, PENDING_MS, key_len + 4),
            (&refused, refused_id, REFUSED_MS, key_len),
        ] {
            b.msg(NFT_MSG_NEWSET, NLM_F_CREATE, |m| {
                attr_str(m, NFTA_SET_TABLE, TABLE);
                attr_str(m, NFTA_SET_NAME, name);
                attr_u32(m, NFTA_SET_FLAGS, NFT_SET_TIMEOUT | NFT_SET_EVAL);
                attr_u32(m, NFTA_SET_KEY_LEN, len);
                attr_u32(m, NFTA_SET_ID, sid);
                attr(m, NFTA_SET_TIMEOUT, &ms.to_be_bytes());
            });
        }
        // PRE: a segment from pasta with none of SYN, RST and ACK is dropped before connection
        // tracking sees it, as a socket's stack drops it (`!ack && !rst && !syn`: discard). The old
        // pasta sends one (a window update, `Flags [none]`) in the middle of a connection. A local
        // socket never noticed; a connection the box FORWARDS (a runtime's bridge in a
        // `--privileged` box, behind its NAT) did: conntrack calls it invalid, does not translate it
        // back, the box's own stack finds no socket for it and answers RST, and pasta closes the
        // connection. MEASURED with docker:dind: `wget` from a container on dind's bridge timed out,
        // the same from one on dind's host network fetched.
        b.rule("pre", |e| {
            prologue(
                e,
                NFT_META_IIFNAME,
                ifname,
                family,
                TCP_SYN | TCP_RST | TCP_ACK,
                0,
            );
            drop_verdict(e);
        });
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
            key(e, family, true, false);
            dynset(e, &refused, refused_id, NFT_DYNSET_OP_ADD);
        });
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
            key(e, family, false, false);
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
            key(e, family, false, true);
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
            key(e, family, false, true);
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
/// `ifname`. A table already there is an earlier attach's, and success.
pub fn install_here(ifname: &str) -> io::Result<()> {
    let (batch, acks) = table_batch(ifname);
    match send_batch(&batch, acks) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        other => other,
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
        {
            let (buf, acks) = table_batch("eth0");
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
            // 1 table, 3 chains, per family 2 sets and 5 rules.
            assert_eq!(acks, 1 + 3 + 2 * 7);
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

/// The rules against a stand-in for the old pasta, over IPv4 AND IPv6, in namespaces of the test's
/// own: a box namespace (`eth0`, where the rules go) and a peer one on the other end of a veth whose
/// packet socket answers a SYN the way pasta `0.0~git20240220` does. No host network is involved,
/// which is what lets IPv6 be tried on a host with no IPv6 route.
#[cfg(test)]
mod against_a_stand_in {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};

    /// The port the stand-in refuses (a RST without ACK to every SYN), and the one it never answers.
    const REFUSING: u16 = 7001;
    const SILENT: u16 = 7002;
    /// A SYN to this port is answered by a segment with no flags, to [`NO_SOCKET`] of the box: the old
    /// pasta's window update, aimed where the box has no socket, as one a NAT does not translate back
    /// lands. The box's kernel answers it with a RST unless rule 3 dropped it.
    const FLAGLESS: u16 = 7003;
    const NO_SOCKET: u16 = 40999;

    fn ip_bin() -> Option<&'static str> {
        ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
    }

    fn ip(args: &str) -> bool {
        ip_bin().is_some_and(|b| {
            std::process::Command::new(b)
                .args(args.split_whitespace())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
    }

    fn csum(data: &[u8], init: u32) -> u16 {
        let mut sum = init;
        for c in data.chunks(2) {
            let w = if c.len() == 2 {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], 0])
            };
            sum += u32::from(w);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn pseudo_sum(src: &[u8], dst: &[u8], len: usize) -> u32 {
        let mut s = 0u32;
        for c in src.chunks(2).chain(dst.chunks(2)) {
            s += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        s + 6 + len as u32
    }

    /// A RST with no ACK, as that pasta sends it, answering the SYN in `frame`.
    fn rst_for(frame: &[u8], l3: usize, v6: bool, tcp: usize) -> Vec<u8> {
        reply_for(frame, l3, v6, tcp, TCP_RST, None)
    }

    /// A segment back to the sender of `frame` with `flags`, to `to_port` of it when given.
    fn reply_for(
        frame: &[u8],
        l3: usize,
        v6: bool,
        tcp: usize,
        flags: u8,
        to_port: Option<u16>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&frame[6..12]); // to the sender
        out.extend_from_slice(&frame[0..6]);
        out.extend_from_slice(&frame[12..14]);
        let (src, dst) = if v6 {
            (&frame[l3 + 24..l3 + 40], &frame[l3 + 8..l3 + 24])
        } else {
            (&frame[l3 + 16..l3 + 20], &frame[l3 + 12..l3 + 16])
        };
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&frame[tcp + 2..tcp + 4]);
        match to_port {
            Some(p) => t[2..4].copy_from_slice(&p.to_be_bytes()),
            None => t[2..4].copy_from_slice(&frame[tcp..tcp + 2]),
        }
        t[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&255u16.to_be_bytes());
        let c = csum(&t, pseudo_sum(src, dst, 20));
        t[16..18].copy_from_slice(&c.to_be_bytes());
        if v6 {
            let mut h = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
            h.extend_from_slice(src);
            h.extend_from_slice(dst);
            out.extend_from_slice(&h);
        } else {
            let mut h = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
            h.extend_from_slice(src);
            h.extend_from_slice(dst);
            let c = csum(&h, 0);
            h[10..12].copy_from_slice(&c.to_be_bytes());
            out.extend_from_slice(&h);
        }
        out.extend_from_slice(&t);
        out
    }

    /// The stand-in: count every SYN by (v6, destination port, source port), refuse `REFUSING`,
    /// ignore `SILENT`, until `stop` reads end of file. The counts go to `out`, one line each.
    fn stand_in(
        ifname: &str,
        mut ready: std::fs::File,
        up: bool,
        mut stop: std::fs::File,
        mut out: std::fs::File,
    ) {
        // SAFETY: an AF_PACKET socket bound to one interface; buffers sized from what is written.
        let sock = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                i32::from((libc::ETH_P_ALL as u16).to_be()),
            )
        };
        assert!(sock >= 0, "packet socket");
        let idx = crate::netlink::index_of(ifname).unwrap_or(0);
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = idx;
        unsafe {
            libc::bind(
                sock,
                std::ptr::addr_of!(sll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        // READY ONCE BOUND, not before: a SYN that came first would go unanswered, and the rules
        // under test then hold back the retry that would have reached it.
        let _ = ready.write_all(if up { b"r" } else { b"x" });
        let mut counts: HashMap<(bool, u16, u16), u32> = HashMap::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: sock,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stop.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
            if fds[1].revents != 0 {
                let mut b = [0u8; 1];
                if stop.read(&mut b).map_or(true, |n| n == 0) {
                    break;
                }
            }
            if fds[0].revents & libc::POLLIN == 0 {
                continue;
            }
            let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut flen = std::mem::size_of::<libc::sockaddr_ll>() as u32;
            let n = unsafe {
                libc::recvfrom(
                    sock,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    std::ptr::addr_of_mut!(from).cast(),
                    &mut flen,
                )
            };
            if n < 54 || from.sll_pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            let f = &buf[..n as usize];
            let (v6, tcp) = match u16::from_be_bytes([f[12], f[13]]) {
                0x0800 if f[23] == 6 => (false, 14 + usize::from(f[14] & 0x0f) * 4),
                0x86dd if f[20] == 6 => (true, 54),
                _ => continue,
            };
            if f.len() < tcp + 20 {
                continue;
            }
            let sport = u16::from_be_bytes([f[tcp], f[tcp + 1]]);
            let dport = u16::from_be_bytes([f[tcp + 2], f[tcp + 3]]);
            // The box's answer to the flagless segment, counted under destination port 0.
            if sport == NO_SOCKET && f[tcp + 13] & TCP_RST != 0 {
                *counts.entry((v6, 0, NO_SOCKET)).or_default() += 1;
                continue;
            }
            if f[tcp + 13] & (TCP_SYN | TCP_ACK) != TCP_SYN {
                continue;
            }
            *counts.entry((v6, dport, sport)).or_default() += 1;
            if dport == REFUSING {
                let r = rst_for(f, 14, v6, tcp);
                unsafe { libc::send(sock, r.as_ptr().cast(), r.len(), 0) };
            }
            if dport == FLAGLESS {
                let r = reply_for(f, 14, v6, tcp, 0, Some(NO_SOCKET));
                unsafe { libc::send(sock, r.as_ptr().cast(), r.len(), 0) };
            }
        }
        for ((v6, dport, sport), n) in counts {
            let _ = writeln!(out, "{} {dport} {sport} {n}", u8::from(v6));
        }
    }

    /// A non-blocking connect with a deadline: the local port, and the errno it ended with (0 for a
    /// connection, `ETIMEDOUT` for the deadline), and how long it took.
    fn connect(addr: &str, port: u16, limit_ms: i32) -> (u16, i32, u128) {
        connect_from(addr, port, 0, limit_ms)
    }

    /// [`connect`] from the local port `lport` (0: any), bound with `SO_REUSEADDR`.
    fn connect_from(addr: &str, port: u16, lport: u16, limit_ms: i32) -> (u16, i32, u128) {
        let sa: std::net::SocketAddr = format!("{addr}:{port}")
            .parse()
            .or_else(|_| format!("[{addr}]:{port}").parse())
            .expect("address");
        let sock = socket2_like(&sa);
        if lport != 0 {
            let one = 1i32;
            unsafe {
                libc::setsockopt(
                    sock,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    std::ptr::addr_of!(one).cast(),
                    4,
                )
            };
            let any: std::net::SocketAddr = if sa.is_ipv6() {
                format!("[::]:{lport}").parse().expect("any6")
            } else {
                format!("0.0.0.0:{lport}").parse().expect("any4")
            };
            let (raw, len) = sockaddr(&any);
            unsafe { libc::bind(sock, raw.as_ptr().cast(), len) };
        }
        let t = std::time::Instant::now();
        let (raw, len) = sockaddr(&sa);
        unsafe { libc::connect(sock, raw.as_ptr().cast(), len) };
        let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut ll = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        unsafe { libc::getsockname(sock, std::ptr::addr_of_mut!(local).cast(), &mut ll) };
        // `sin_port` and `sin6_port` sit at the same offset, right after the family.
        let lb = unsafe { std::slice::from_raw_parts(std::ptr::addr_of!(local).cast::<u8>(), 4) };
        let lport = u16::from_be_bytes([lb[2], lb[3]]);
        let mut p = libc::pollfd {
            fd: sock,
            events: libc::POLLOUT,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut p, 1, limit_ms) };
        let err = if r == 0 {
            libc::ETIMEDOUT
        } else {
            let mut e = 0i32;
            let mut el = 4u32;
            unsafe {
                libc::getsockopt(
                    sock,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    std::ptr::addr_of_mut!(e).cast(),
                    &mut el,
                )
            };
            e
        };
        unsafe { libc::close(sock) };
        (lport, err, t.elapsed().as_millis())
    }

    fn socket2_like(sa: &std::net::SocketAddr) -> i32 {
        let fam = if sa.is_ipv6() {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        unsafe { libc::socket(fam, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) }
    }

    fn sockaddr(sa: &std::net::SocketAddr) -> (Vec<u8>, u32) {
        match sa {
            std::net::SocketAddr::V4(a) => {
                let mut s: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                s.sin_family = libc::AF_INET as u16;
                s.sin_port = a.port().to_be();
                s.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
                let b = unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::addr_of!(s).cast::<u8>(),
                        std::mem::size_of::<libc::sockaddr_in>(),
                    )
                };
                (b.to_vec(), b.len() as u32)
            }
            std::net::SocketAddr::V6(a) => {
                let mut s: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                s.sin6_family = libc::AF_INET6 as u16;
                s.sin6_port = a.port().to_be();
                s.sin6_addr.s6_addr = a.ip().octets();
                let b = unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::addr_of!(s).cast::<u8>(),
                        std::mem::size_of::<libc::sockaddr_in6>(),
                    )
                };
                (b.to_vec(), b.len() as u32)
            }
        }
    }

    fn pipe() -> (std::fs::File, std::fs::File) {
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        unsafe {
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        }
    }

    /// Per family (IPv4, IPv6): the refused port's errno and milliseconds, how many SYNs to the
    /// silent port the stand-in saw (from a free port, and from a fixed one twice), and how many RSTs
    /// the box sent back for the flagless segment.
    type Seen = Vec<(i32, u128, u32, u32, u32)>;

    fn scenario(with_rules: bool) -> Result<Seen, String> {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
            return Err("skip: no user namespace".into());
        }
        let _ = std::fs::write("/proc/self/setgroups", b"deny");
        if std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_err()
            || std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_err()
        {
            return Err("skip: the namespace's map was refused".into());
        }
        if ip_bin().is_none() || !ip("link add eth0 type veth peer name peer0") {
            return Err("skip: no `ip` or no veth".into());
        }
        let (ready_r, mut ready_w) = pipe();
        let (moved_r, mut moved_w) = pipe();
        let (stop_r, stop_w) = pipe();
        let (res_r, res_w) = pipe();
        let peer = unsafe { libc::fork() };
        if peer == 0 {
            drop((ready_r, moved_w, stop_w, res_r));
            let ok = unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0;
            let _ = ready_w.write_all(if ok { b"n" } else { b"x" });
            let mut b = [0u8; 1];
            let mut moved_r = moved_r;
            let _ = moved_r.read(&mut b);
            let _ = std::fs::write("/proc/sys/net/ipv6/conf/peer0/accept_dad", b"0");
            // SILENT ROUTING for the targets: with forwarding off this kernel answers a packet that
            // is not its own with ICMP unreachable (MEASURED: ENETUNREACH at once), and a forwarded
            // one to a blackhole is dropped with no answer. The packet socket below is the only
            // thing that answers, as pasta is the only thing a box behind it hears from.
            let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1");
            let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", b"1");
            let up = ip("addr add 10.9.0.2/24 dev peer0")
                && ip("addr add fd00:9::2/64 dev peer0 nodad")
                && ip("link set peer0 up")
                && ip("route add blackhole 10.9.1.0/24")
                && ip("-6 route add blackhole fd00:9:1::/64");
            stand_in("peer0", ready_w, up, stop_r, res_w);
            unsafe { libc::_exit(0) };
        }
        drop((moved_r, stop_r, res_w));
        let mut b = [0u8; 1];
        let mut ready_r = ready_r;
        let _ = ready_r.read(&mut b);
        if b[0] != b'n' || !ip(&format!("link set peer0 netns {peer}")) {
            return Err("the peer namespace could not be made".into());
        }
        let _ = moved_w.write_all(b"m");
        let _ = std::fs::write("/proc/sys/net/ipv6/conf/eth0/accept_dad", b"0");
        let up = ip("addr add 10.9.0.1/24 dev eth0")
            && ip("addr add fd00:9::1/64 dev eth0 nodad")
            && ip("link set eth0 up")
            && ip("link set lo up")
            && ip("route add 10.9.1.0/24 via 10.9.0.2")
            && ip("-6 route add fd00:9:1::/64 via fd00:9::2");
        let _ = ready_r.read(&mut b);
        if !up || b[0] != b'r' {
            return Err("the addresses could not be set".into());
        }
        if with_rules {
            install_here("eth0").map_err(|e| format!("install: {e}"))?;
        }
        // Neighbours first, so the first SYN is not held by ARP or neighbour discovery.
        let _ = connect("10.9.0.2", 9, 300);
        let _ = connect("fd00:9::2", 9, 300);
        // Both families at once: they share nothing but the stand-in, which tells them apart.
        let probes: Vec<_> = ["10.9.1.1", "fd00:9:1::1"]
            .into_iter()
            .map(|target| {
                std::thread::spawn(move || {
                    let (_, errno, ms) = connect(target, REFUSING, 2500);
                    let (sport, _, _) = connect(target, SILENT, 2300);
                    // TWO CONNECTIONS FROM ONE PORT, the second as soon as the first is closed: a
                    // new ISN, so the rules must let it through rather than take it for a retry.
                    let fixed = if target.contains(':') { 41002 } else { 41001 };
                    connect_from(target, SILENT, fixed, 300);
                    connect_from(target, SILENT, fixed, 300);
                    connect(target, FLAGLESS, 400);
                    (errno, ms, sport, fixed)
                })
            })
            .collect();
        let mut seen = Vec::new();
        let mut silent_ports = Vec::new();
        for p in probes {
            let (errno, ms, sport, fixed) = p.join().map_err(|_| "a probe thread panicked")?;
            silent_ports.push((sport, fixed));
            seen.push((errno, ms));
        }
        drop(stop_w);
        let mut text = String::new();
        let mut res_r = res_r;
        let _ = res_r.read_to_string(&mut text);
        unsafe { libc::waitpid(peer, std::ptr::null_mut(), 0) };
        let count = |v6: bool, sport: u16| {
            text.lines()
                .filter_map(|l| {
                    let f: Vec<u32> = l.split(' ').filter_map(|x| x.parse().ok()).collect();
                    (f.len() == 4
                        && f[0] == u32::from(v6)
                        && f[1] == u32::from(SILENT)
                        && f[2] == u32::from(sport))
                    .then_some(f[3])
                })
                .sum::<u32>()
        };
        let resets = |v6: bool| {
            text.lines()
                .filter_map(|l| {
                    let f: Vec<u32> = l.split(' ').filter_map(|x| x.parse().ok()).collect();
                    (f.len() == 4
                        && f[0] == u32::from(v6)
                        && f[1] == 0
                        && f[2] == u32::from(NO_SOCKET))
                    .then_some(f[3])
                })
                .sum::<u32>()
        };
        Ok(vec![
            (
                seen[0].0,
                seen[0].1,
                count(false, silent_ports[0].0),
                count(false, silent_ports[0].1),
                resets(false),
            ),
            (
                seen[1].0,
                seen[1].1,
                count(true, silent_ports[1].0),
                count(true, silent_ports[1].1),
                resets(true),
            ),
        ])
    }

    /// Run [`scenario`] in a forked child (a user namespace needs a single-threaded process) and
    /// read its outcome back as text.
    fn in_child(with_rules: bool) -> Result<Seen, String> {
        let (mut r, mut w) = pipe();
        let c = unsafe { libc::fork() };
        if c == 0 {
            drop(r);
            let line = match scenario(with_rules) {
                Ok(s) => s
                    .iter()
                    .map(|(e, ms, n, r, x)| format!("{e} {ms} {n} {r} {x}"))
                    .collect::<Vec<_>>()
                    .join(";"),
                Err(e) => format!("err {e}"),
            };
            let _ = w.write_all(line.as_bytes());
            unsafe { libc::_exit(0) };
        }
        drop(w);
        let mut out = String::new();
        let _ = r.read_to_string(&mut out);
        unsafe { libc::waitpid(c, std::ptr::null_mut(), 0) };
        if let Some(e) = out.strip_prefix("err ") {
            return Err(e.to_string());
        }
        let seen: Seen = out
            .split(';')
            .filter_map(|f| {
                let v: Vec<&str> = f.split(' ').collect();
                Some((
                    v.first()?.parse().ok()?,
                    v.get(1)?.parse().ok()?,
                    v.get(2)?.parse().ok()?,
                    v.get(3)?.parse().ok()?,
                    v.get(4)?.parse().ok()?,
                ))
            })
            .collect();
        if seen.len() == 2 {
            Ok(seen)
        } else {
            Err(format!("the child said {out:?}"))
        }
    }

    /// WITHOUT the rules the stand-in reproduces the three defects, which is what makes the second
    /// half mean anything: the refused port runs to the deadline, the box sends its SYN again (the
    /// retry the old pasta reset on), and a segment with no flags to a port without a socket is
    /// answered with a RST. WITH them, over IPv4 and IPv6 alike: `ECONNREFUSED` within about a
    /// second, one SYN to the silent port in 2.3 s, and no RST.
    #[test]
    fn the_rules_refuse_and_hold_back_over_ipv4_and_ipv6() {
        // The control and the case run at once, each in namespaces of its own.
        let with = std::thread::spawn(|| in_child(true));
        let before = match in_child(false) {
            Ok(s) => s,
            Err(e) if e.starts_with("skip") => {
                eprintln!("{e}");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        let after = with
            .join()
            .map_err(|_| "the thread panicked".to_string())
            .and_then(|r| r)
            .expect("with the rules");
        eprintln!("without: {before:?}\nwith:    {after:?}");
        let (b, a) = (&before, &after);
        for (fam, (wo, w)) in ["ipv4", "ipv6"].iter().zip(b.iter().zip(a.iter())) {
            assert_eq!(
                wo.0,
                libc::ETIMEDOUT,
                "{fam}: the control must hang: {before:?}"
            );
            assert!(
                wo.2 >= 2,
                "{fam}: the control must retry its SYN: {before:?}"
            );
            assert_eq!(w.0, libc::ECONNREFUSED, "{fam}: {after:?}");
            assert!(w.1 < 1600, "{fam}: refused after {} ms", w.1);
            assert_eq!(w.2, 1, "{fam}: the retry must be held back: {after:?}");
            assert_eq!(wo.3, 2, "{fam}: the control sends both SYNs: {before:?}");
            assert_eq!(
                w.3, 2,
                "{fam}: a new connection on the same port is not a retry: {after:?}"
            );
            assert!(
                wo.4 >= 1,
                "{fam}: the control must answer the flagless segment with a RST: {before:?}"
            );
            assert_eq!(
                w.4, 0,
                "{fam}: the flagless segment must be dropped before the stack: {after:?}"
            );
        }
    }
}
