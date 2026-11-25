//! Verbs that read or steer a box that is already running: `ps`, `stats`, `inspect`, `logs`,
//! `attach`, `top`, `diff`, `history`, `wait`, `rename`, `recover`, `stop`, `pause`.
//!
//! None of them start a box; they read the registry, the cgroup and the box's own files, or send it a
//! signal. Split out of `commands/mod.rs`, which keeps the start path (`box_run` and its
//! supervision) and every helper both sides call, reached here through `use super::*`.

use super::*;

/// The `Publishers` array `docker compose ps --format json` emits, built from kern's `ports` string.
///
/// WHY THIS FIELD AND NOT THE OTHER ABSENT ONES. It is how a script discovers where a service is
/// actually reachable, and on a rootless runtime that is the one thing it cannot assume: kern
/// republishes a privileged port above 1024 (`:80` becomes `:8080`), so a script that hardcodes the
/// file's number is wrong and a script that reads this field is right. `Image`, `Mounts` and `Size`
/// stay absent because the registry holds no value for them and an invented one is worse than a
/// missing one; this one kern knows exactly.
///
/// SHAPE MEASURED on Docker 29.6.2, not recalled:
/// `[{"URL":"0.0.0.0","TargetPort":80,"PublishedPort":18080,"Protocol":"tcp"}]`. Docker emits one
/// entry per address family (a second with `"URL":"::"`); kern emits the addresses it actually
/// bound, which is one entry per mapping.
///
/// The input is the registry's own `ports` text, `0.0.0.0:18080->80, 0.0.0.0:18443->443`. A mapping
/// that does not parse is SKIPPED rather than guessed: a `Publishers` entry with an invented port
/// would send a script to the wrong address, which is the failure this field exists to prevent.
fn publishers_json(ports: &str) -> String {
    let mut out = String::from("[");
    let mut first = true;
    for (url, published, target, proto) in parse_port_mappings(ports) {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&format!(
            "{{\"URL\":{},\"TargetPort\":{target},\"PublishedPort\":{published},\"Protocol\":{}}}",
            json_str(url),
            json_str(proto)
        ));
    }
    out.push(']');
    out
}

/// Decode the registry's `ports` text into `(host addr, published, target, proto)` per mapping.
///
/// THE SOLE PARSER of that grammar, so the two documents built from it cannot come to disagree
/// about which port a service is on. The input is kern's own
/// `0.0.0.0:18080->80, 0.0.0.0:18443->443/udp`; a mapping that does not parse is SKIPPED rather
/// than guessed, because an invented port number sends a caller to the wrong address, which is the
/// failure both consumers of this exist to prevent.
pub(crate) fn parse_port_mappings(ports: &str) -> impl Iterator<Item = (&str, u32, u32, &str)> {
    ports.split(',').filter_map(|spec| {
        let (host_side, target) = spec.trim().split_once("->")?;
        // `<addr>:<published>` or a bare `<published>`.
        let (url, published) = match host_side.rsplit_once(':') {
            Some((addr, port)) => (addr, port),
            None => ("0.0.0.0", host_side),
        };
        let (target, proto) = match target.split_once('/') {
            Some((t, p)) => (t, p),
            None => (target, "tcp"),
        };
        Some((url, published.parse().ok()?, target.parse().ok()?, proto))
    })
}

/// Docker's `NetworkSettings.Ports` map, built from the same mappings [`publishers_json`] reads.
///
/// SHAPE MEASURED on Docker 29.1.3 on this machine, not recalled. A container published on
/// `127.0.0.1:18401->80` and additionally EXPOSEing 9999:
///
/// ```text
///   {"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"18401"}],"9999/tcp":null}
///   and once stopped:  {}
/// ```
///
/// FOUR details are load-bearing, and each is the kind a from-memory implementation gets wrong.
/// The KEY is the port INSIDE the container with its protocol suffix, not the published one. The
/// value is an ARRAY, because one container port can be published on several addresses, and a
/// caller doing `.["80/tcp"][0]` breaks on an object. `HostPort` is a STRING, not a number. And the
/// capitalisation is `HostIp`, with a lower-case `p`: `HostIP` would parse as absent in every
/// reader. An earlier version of this comment listed three of the four and named the wrong Docker
/// version, which is the class of error this file exists to avoid.
///
/// ⚠️ ONE KEY KERN NEVER EMITS. Docker maps a port that is EXPOSEd but not published to `null`,
/// which is how a caller tells "the image declares this port" from "nothing declares it". kern's
/// registry records what it actually BOUND and has no notion of a declared-but-unpublished port, so
/// every key here carries an array and none is `null`. A caller iterating the map therefore sees
/// fewer keys here than Docker would show, never a different answer for the same key. A stopped box
/// yields `{}`, which is what Docker yields too.
pub(crate) fn network_ports_json(ports: &str) -> String {
    // Grouped by container port, because two publications of one port share a key and appending
    // them as two keys would produce a document whose second entry silently replaces the first in
    // every JSON parser that reads it.
    let mut keys: Vec<String> = Vec::new();
    let mut binds: Vec<Vec<String>> = Vec::new();
    for (url, published, target, proto) in parse_port_mappings(ports) {
        let key = format!("{target}/{proto}");
        let bind = format!(
            "{{\"HostIp\":{},\"HostPort\":{}}}",
            json_str(url),
            json_str(&published.to_string())
        );
        match keys.iter().position(|k| *k == key) {
            Some(i) => binds[i].push(bind),
            None => {
                keys.push(key);
                binds.push(vec![bind]);
            }
        }
    }
    let body: Vec<String> = keys
        .iter()
        .zip(&binds)
        .map(|(k, v)| format!("{}:[{}]", json_str(k), v.join(",")))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// Split the registry's comma-joined `k=v` label field into pairs.
///
/// THE ONE PLACE THE FIELD BECOMES PAIRS, and every reader of a label goes through it: the renderers
/// (`{{.Labels}}`, `{{.Label "k"}}`, `labels_json`) and `ps_matches`, which answers
/// `--filter label=`. That last one is the reason this matters rather than a tidiness note. It used
/// to compare the raw stored segments, so it shared the decoder but not the bare-key normalisation
/// below, and the two readers disagreed about exactly one input: a box labelled `--label noequals`
/// was found by `--filter label=noequals` and NOT by `--filter label=noequals=`, while its own
/// document said `"noequals":""`. Both now ask this function, and MEASURED against the reference on
/// 2026-09-20, all four spellings (`noequals`, `noequals=`, `empty`, `empty=`) match in kern exactly
/// as they match in docker 29.1.3.
///
/// A segment with no `=` is a label with an EMPTY VALUE, not corruption. Measured on the reference
/// implementation: `--label noequals` renders `{"noequals":""}`.
///
/// ⚠️ THIS COMMENT HAS BEEN WRONG TWICE, both times the same way: it described the state before a
/// change that landed beside it. Once when `--label` began accepting a bare key and the "skipped"
/// sentence was left behind, and once when `ps_matches` started reading through here and the
/// sentence about the two readers differing was left behind. The claim to check first, if it ever
/// reads oddly again, is WHO CALLS THIS, because that is the part that keeps moving.
pub(crate) fn label_pairs(field: &str) -> Vec<(String, String)> {
    label_pairs_of(registry::decode_labels(field))
}

/// The same rule applied to segments that are ALREADY decoded, which is the shape an image's config
/// carries them in (`config.Labels`, a list of `k=v`) as opposed to the registry's encoded field.
///
/// SPLIT OUT RATHER THAN COPIED, and the comment above says why in its own words: the bare-key rule
/// has had two readers disagree about exactly one input before, and `kern image inspect` is now a
/// third reader of it. A second spelling here would be the same defect with a new caller.
pub(crate) fn label_pairs_of(segments: impl IntoIterator<Item = String>) -> Vec<(String, String)> {
    segments
        .into_iter()
        .filter_map(|l| {
            // Docker and podman both accept a BARE KEY (`--label x`) and store an empty value,
            // MEASURED: podman renders `{"noequals":""}`. A segment with no `=` is therefore a
            // real label and not corruption, and dropping it here would lose one the caller set.
            let (k, v) = match l.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (l, String::new()),
            };
            (!k.is_empty()).then_some((k, v))
        })
        .collect()
}

/// The registry's label field as a JSON object, Docker's `Config.Labels` shape.
///
/// `{}` and not `null` for a box with no labels: a consumer that does `.labels.foo` gets "absent"
/// either way, and one that iterates gets an empty loop instead of a type error. Docker emits
/// `null` there, and this is the one place the shape deliberately differs, because the value a
/// script reads is the same and the failure mode is not.
pub(crate) fn labels_json(field: &str) -> String {
    labels_object(registry::decode_labels(field))
}

/// Decoded label segments as Docker's `Config.Labels` object. The rendering half of
/// [`labels_json`], shared with `kern image inspect`, whose labels never passed through the
/// registry's encoding and so have nothing to decode.
pub(crate) fn labels_object(segments: impl IntoIterator<Item = String>) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in label_pairs_of(segments).into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{}:{}", json_str(&k), json_str(&v)));
    }
    out.push('}');
    out
}

/// An image's `HEALTHCHECK` as Docker's `Config.Healthcheck` object, or `null`.
///
/// THE DURATIONS ARE ALREADY NANOSECONDS, which is the unit Docker's document uses, so this is a
/// rename and not a conversion - there is no factor here to get wrong. Each optional field is
/// emitted only when the image set it, because a `"Interval":0` would read as "probe continuously"
/// to a consumer that trusts the number, and this file's rule is that a plausible answer is worse
/// than none.
///
/// `null` for an image with no check, rather than omitting the key, which is what Docker does. The
/// same trade [`labels_json`] documents for `{}`: a consumer reading `.Config.Healthcheck` gets
/// "absent" either way, and kern's own document stays uniform with the other optionals beside it
/// (`WorkingDir`, `User`, `StopSignal` are all spelled `null` here when unset).
pub(crate) fn healthcheck_json(h: Option<&kern_oci::ImageHealthcheck>) -> String {
    let Some(h) = h else {
        return "null".into();
    };
    let test: Vec<String> = h.test.iter().map(|t| json_str(t)).collect();
    let mut out = format!("{{\"Test\":[{}]", test.join(","));
    for (name, v) in [
        ("Interval", h.interval_ns),
        ("Timeout", h.timeout_ns),
        ("StartPeriod", h.start_period_ns),
        ("StartInterval", h.start_interval_ns),
    ] {
        if let Some(ns) = v {
            out.push_str(&format!(",\"{name}\":{ns}"));
        }
    }
    if let Some(r) = h.retries {
        out.push_str(&format!(",\"Retries\":{r}"));
    }
    out.push('}');
    out
}

/// The value of ONE label, or `None` when the box does not carry that key.
///
/// The distinction is the whole point of returning an `Option`: `{{.Label "app"}}` on a box with no
/// `app` label must be able to print an empty string the way Docker does, WITHOUT that being
/// confusable with a label whose value is genuinely empty. Both print nothing; only the caller that
/// asks for the Option can tell them apart.
pub(crate) fn label_value(field: &str, key: &str) -> Option<String> {
    label_pairs(field)
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

/// The two presentation knobs `docker ps` has that are not about WHICH boxes are listed.
///
/// A STRUCT AND NOT TWO BOOLEANS at the call site, because `ps(shape, quiet, all, filters, format,
/// false, None)` says nothing about which `false` is which - the same reason [`JsonShape`] is an
/// enum rather than a second boolean beside `quiet`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PsView<'a> {
    /// `--no-trunc`: print the whole COMMAND even on a terminal, where it is truncated by default so
    /// a long line never wraps.
    pub no_trunc: bool,
    /// `--last N` / `-n N`: keep only the N most recent boxes, newest first, across live and exited.
    /// `Some(0)` lists nothing, which is what `docker ps -n 0` does.
    pub last: Option<usize>,
    /// `compose ps SERVICE...`: only these box names, matched EXACTLY. A `name=` filter is a
    /// substring and would let `web` select `web2`; Docker lists the services named and no other.
    pub only: Option<&'a [String]>,
    /// `compose ps -q`: print each live box's ID, its supervisor pid, instead of its name. It is
    /// the id `kern stop`/`exec`/`logs` resolve and `--filter id=` matches, and it changes when a
    /// service is recreated, which is what a script comparing `ps -q` before and after `up` reads
    /// (as Docker's container ID). The name does not change, so a recreate was invisible.
    pub ids: bool,
    /// `compose ps`: a `--format` listing is sorted by name and a `table` header uses `docker
    /// compose ps`'s words, as Docker Compose prints both.
    pub compose: bool,
    /// `compose ps`: each box's service and image as the file names them, `(box, service, image)`,
    /// for `{{.Service}}`, and for `{{.Image}}` of a row that no longer records one (an exited box).
    pub services: Option<&'a [(String, String, String)]>,
}

/// Docker's `Service` of a box in `ps --format json`: the file's service when the listing knows it
/// (`compose ps`); otherwise the box name without its `<project>-` and, for Docker's
/// `<project>-<service>-<n>`, without its `-<n>`.
fn json_service(view: &PsView<'_>, name: &str, pod: &str) -> String {
    if let Some((_, svc, _)) = view
        .services
        .and_then(|m| m.iter().find(|(b, _, _)| b == name))
    {
        return svc.clone();
    }
    super::service_of_box_name(name, pod)
}

/// How `ps` renders a machine-readable listing.
///
/// AN ENUM AND NOT A SECOND BOOLEAN, because the two shapes are one decision with three outcomes,
/// and `ps(true, true, …)` at a call site says nothing about which of them was meant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JsonShape {
    /// Not JSON: the human table, or a `--format` template.
    No,
    /// ONE ARRAY, which is `kern ps --json`'s documented shape and stays byte-for-byte what it was.
    Array,
    /// ONE OBJECT PER LINE. What `docker compose ps --format json` emits since Compose 2.21 (it was
    /// an array before), so a script that reads it line by line works against kern too. The FIELD
    /// NAMES are still kern's and are not Docker's; that difference is recorded in
    /// docs/RUNTIME-PARITY.md rather than papered over by matching only the framing.
    Lines,
}

pub fn ps(
    shape: JsonShape,
    quiet: bool,
    all: bool,
    filters: &[(String, String)],
    format: Option<&str>,
    view: PsView<'_>,
) -> Result<(), Error> {
    let named = |n: &str| view.only.is_none_or(|only| only.iter().any(|o| o == n));
    // Validate every filter once, fail-fast on an unsupported key or status value.
    for (k, v) in filters {
        match k.as_str() {
            "name" | "id" | "label" | "pod" => {}
            // `health=` IS THE ONE A READINESS LOOP WRITES. `status=` answers whether the box is
            // there; this answers whether it is well, which is the question `depends_on:
            // service_healthy` asks and the question a deploy script asks before it proceeds. The
            // vocabulary is the registry's own, which is Docker's: a box with no healthcheck has an
            // EMPTY verdict and matches no value, rather than being counted as healthy.
            "health" => {
                if !matches!(v.as_str(), "healthy" | "unhealthy" | "starting" | "none") {
                    return Err(Error::Usage(
                        "ps --filter health=: healthy | unhealthy | starting | none (none = the box declares no healthcheck)",
                    ));
                }
            }
            "status" => {
                if !matches!(
                    v.as_str(),
                    "running"
                        | "paused"
                        | "orphaned"
                        | "exited"
                        | "created"
                        | "dead"
                        | "restarting"
                        | "kept"
                ) {
                    return Err(Error::Usage(
                        "ps --filter status=: running | paused | orphaned | exited | kept \
                         (a `kern create` box that never ran is status=kept; \
                         created/dead/restarting match nothing)",
                    ));
                }
            }
            _ => {
                return Err(Error::Usage(
                    "ps --filter: supported keys are name=, status=, id=, label=, pod=, health=",
                ))
            }
        }
    }
    let live = registry::list();
    // THE LIVE NAMES, ONCE. The kept section has to exclude a box that is running (it is a row in
    // the live section instead), and the first version asked `registry::find(name)` per kept box -
    // one `read_dir` of the whole instances directory EACH TIME. MEASURED: 13 syscalls per kept box,
    // and with 200 registry entries and 100 kept boxes, 3.2 ms of reading the same directory 101
    // times, against 0.054 ms for reading it once. From the UNFILTERED list, not from `boxes`
    // below: a running box excluded by a `--filter` would otherwise reappear as a kept row.
    let live_names: std::collections::HashSet<String> =
        live.iter().map(|b| b.name.clone()).collect();
    let boxes: Vec<registry::Instance> = live
        .iter()
        .filter(|b| ps_matches(b, filters) && named(&b.name))
        .cloned()
        .collect();
    // ASK THE KERNEL TOO, because the registry is the one source that can be erased while the boxes it
    // describes keep running. `$XDG_RUNTIME_DIR/kern/instances` is swept by `systemd-tmpfiles`, cleared
    // on logout, and deleted by any operator who reads `/run/user` as scratch. Reproduced here:
    //
    //     box r1 -d -- sleep 120      ps: r1
    //     rm -rf $XDG_RUNTIME_DIR/kern/instances
    //     ps                          r1 GONE
    //     stop r1                     error: no running box named 'r1'
    //     /proc/<pid>                 still there
    //     kern.slice/kern-box-r1-…    still there
    //
    // The box was invisible and unstoppable through kern while every fact needed to find it sat in the
    // cgroup tree, whose directory name carries the tag and the supervisor pid. This does NOT invent a
    // row for it: the two sources disagree, and a table that quietly merged them would be claiming an
    // instance record it does not have (no uptime, no ports, no health). It says the disagreement out
    // loud, with the pid, which is the difference between a leak nobody can see and one an operator can
    // act on with a single `kill`.
    //
    // Silent when the two agree, which is every ordinary run, and silent under `--quiet`/`--format`,
    // whose callers are parsing.
    if !quiet && format.is_none() && filters.is_empty() {
        // A BOX IS KNOWN BY ITS IDENTITY, NOT ITS NAME. The cgroup's directory and a supervisor's
        // command line carry the name the box STARTED with, and `kern rename` changes the record
        // only: MEASURED on 0.56.0, `rename r r2` then `ps` warned that a box `r` ran with no
        // record, about the box listed right under it as `r2`. So a candidate is also known by the
        // cgroup directory a record names, or by the supervisor pid a record has.
        let known: std::collections::HashSet<&str> = live.iter().map(|b| b.name.as_str()).collect();
        let known_cgroups: std::collections::HashSet<&str> = live
            .iter()
            .filter_map(|b| std::path::Path::new(&b.cgroup).file_name()?.to_str())
            .collect();
        let known_pids: std::collections::HashSet<u32> = live
            .iter()
            .filter_map(|b| u32::try_from(b.pid).ok())
            .collect();
        let cg_candidates = kern_isolation::live_box_cgroups();
        let mut lost: Vec<(String, u32)> = cg_candidates
            .iter()
            .filter(|(tag, pid)| {
                !known.contains(tag.as_str())
                    && !known_cgroups.contains(format!("kern-box-{tag}-{pid}").as_str())
            })
            .cloned()
            .collect();
        // FALLBACK, and only when the first channel had nothing to say. A host without cgroup
        // delegation has no `kern-box-*` directory, so the evidence above does not exist there -
        // which is precisely the host where a later pass, as uid 0 with no systemd,
        // measured three live `kern box` processes after a registry wipe: absent from `ps`,
        // unreachable by `stop`, untouched by `gc`, and unreported, because the warning had nothing
        // to read. Asking `/proc` costs about as much as `ps` itself (6.11 ms over 534 pids), so a
        // host that HAS the cheap channel never pays for the expensive one.
        // THE FALLBACK RUNS WHENEVER THE CGROUP CHANNEL PRODUCED NO EVIDENCE, and getting this
        // condition right took two wrong answers, both reported by the same later pass.
        //
        // First I asked "did the cgroup channel find an ORPHAN", which is false on a healthy host
        // with no boxes, so the most ordinary `kern ps` on earth fell through to the scan every time:
        // 3.9 ms against 1.1. So I gated on "does the cheap channel EXIST here", meaning `kern.slice`
        // is a directory. That was worse, and the test's host proved it in one command: there
        // `kern.slice` EXISTS and has no `kern-box-*` children at all, so the gate said yes, the
        // fallback never ran, and three live boxes stayed invisible after a registry wipe - the exact
        // case the fallback was written for. ⛔ A directory existing is not a channel answering.
        //
        // The condition that is actually true is the simplest one: if the cgroup channel produced no
        // CANDIDATES - not "no orphans", no candidates at all - then it has told us nothing, whether
        // because nothing runs or because it cannot see. Ask the other one.
        //
        // The cost that made me reach for a gate is gone: reordering the scan to read the two cheap
        // kernel facts first took it from 3.55 ms to 1.69, and narrowed it from 423 candidates to 2.
        // 1.7 ms on a command a human reads is not worth a gate that can be wrong.
        if cg_candidates.is_empty() {
            lost = kern_isolation::live_box_supervisors_via_proc()
                .into_iter()
                .filter(|(tag, pid)| !known.contains(tag.as_str()) && !known_pids.contains(pid))
                .collect();
        }
        if !lost.is_empty() {
            // TWO CAUSES, AND THE ADVICE USED TO REST ON ONE OF THEM. This said "the runtime dir was
            // cleared under them. Kill by pid, or `kern gc` once they exit", and MEASURED on the
            // getkern.dev VPS the cause was the other one: the box is `getkern-web`, nginx serving the
            // site, started by a systemd unit that sets `XDG_RUNTIME_DIR=/run/kern`, and it has a
            // perfectly good record THERE. From root's default runtime dir it looks orphaned, and a
            // reader who follows the advice kills the box that serves the site.
            //
            // kern's own `compose systemd` writes that variable into the units it generates, so the
            // tool creates this situation itself: naming one cause when the commonest one is the other
            // is the same defect as a diagnosis that says `oom` for every kill. The directory we looked
            // in is now part of the message, because it is what makes the second cause checkable.
            let dir = crate::registry::instances_dir_for_display();
            eprintln!(
                "kern: warning: {} box(es) are RUNNING and have no record in {dir}. EITHER that \
                 runtime dir was cleared under them, OR they were started with a different \
                 XDG_RUNTIME_DIR - a systemd unit written by `kern compose systemd` sets one, and \
                 `systemctl show <unit> -p Environment` says which. Check there before stopping \
                 anything; if the record really is gone, `kern stop <name>` still stops the box:",
                lost.len()
            );
            for (tag, pid) in &lost {
                eprintln!("kern:   {tag} (supervisor pid {pid})");
            }
        }
    }
    // `-a`/`--all` (or an explicit `status=exited`) also surfaces boxes that have exited but whose
    // `waitexit` breadcrumb `gc` has not yet reaped - Docker's `ps -a`. A `status=running` query never
    // wants them, and `exited_matches` (which honours the same status filter) excludes anything the
    // status asked against, so this gate is only "should we even read the exited set at all". `dead`
    // is NOT here: kern has no dead state, so `status=dead` matches nothing (like `created`).
    let want_exited = all || filters.iter().any(|(k, v)| k == "status" && v == "exited");
    // An exited box did not keep its labels (they lived in the pruned instance record; the breadcrumb
    // carries only name/pod/command). Say so rather than let `label=` silently match zero exited rows -
    // the same "no accept-and-ignore on an explicit filter" rule as `status=dead`.
    if want_exited && filters.iter().any(|(k, _)| k == "label") {
        eprintln!(
            "kern: note: --filter label= does not apply to exited boxes (labels are not retained past exit)"
        );
    }
    // KEPT BOXES, the ones `kern start` can run: `-a`, or an explicit `status=kept`, exactly as the
    // exited set above. NOT in a plain `kern ps`, whose contract is the boxes that are UP: a kept box
    // is a layer on disk, and listing one there put a row that is not a process in the view a reader
    // greps for processes (measured, before this gate: `kern ps` on a host with one kept box printed
    // it under a `kept` header).
    // THE SCAN RUNS ONLY WHEN A KEPT ROW COULD SURVIVE, because it is not free (one record read per
    // box) and three callers used to pay for rows that were then discarded: MEASURED at 1000 kept
    // boxes, `ps -a --last 1` paid 5.6 ms to print one row, and `--filter status=running` paid 6.1
    // ms to print none. `--last` clears the kept rows (see the note below it), and a filter on a key
    // no kept row can answer excludes them all in `kept_matches`.
    let kept_possible = view.last.is_none()
        && filters.iter().all(|(k, v)| match k.as_str() {
            "name" => true,
            "status" => matches!(v.as_str(), "kept" | "exited"),
            // `pod`, `id`, `label`, `health`: a kept box has none of them, and `kept_matches`
            // answers false for every one. Asking is the same answer for less work.
            _ => false,
        });
    let want_kept =
        kept_possible && (all || filters.iter().any(|(k, v)| k == "status" && v == "kept"));
    // One that is RUNNING is not a kept ROW: it is in the live set, with its uptime and health, so
    // one box is never two rows of one `ps -a`.
    let mut kept: Vec<crate::keepbox::KeptBox> = if want_kept {
        // `name=` IS ASKED ON THE DIRENT, before the record is opened: it is the one filter key a
        // kept row answers from its name alone.
        let name_want: Option<&str> = filters
            .iter()
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.as_str());
        crate::keepbox::list_matching(|n| name_want.is_none_or(|w| n.contains(w)))
            .into_iter()
            .filter(|k| !live_names.contains(&k.name))
            .filter(|k| kept_matches(k, filters) && named(&k.name))
            .collect()
    } else {
        Vec::new()
    };
    kept.sort_by(|a, b| {
        b.meta
            .created
            .cmp(&a.meta.created)
            .then(a.name.cmp(&b.name))
    });
    let exited: Vec<registry::ExitedBox> = if want_exited {
        // AGAINST THIS `ps`'s OWN SNAPSHOT, UNFILTERED: between a box's `waitexit` write and its
        // unregister both artefacts exist, and a record of a box in `live` is left out by
        // `list_exited_among`, on the full (pid, starttime) identity, so no box appears in BOTH
        // sections of one `ps -a`; a running box a `--filter` hides is still running, not exited.
        registry::list_exited_among(&live)
            .into_iter()
            .filter(|e| exited_matches(e, filters) && named(&e.name))
            // ONE BOX, ONE ROW, for a name that has a kept layer. The exit record is transient (an
            // hour, or `kern gc`) and the kept record is durable and now carries the same code (the
            // supervisor records it), so printing both put one box in two sections of one `ps -a`
            // saying two different things - measured: `exit 137` in one and "never ran" in the
            // other - and made `ps -a -q` print its name twice, which a script acts on.
            .filter(|e| !kept.iter().any(|k| k.name == e.name))
            .collect()
    } else {
        Vec::new()
    };
    // `--last N` / `-n N`: THE N MOST RECENTLY CREATED, ACROSS BOTH LISTS. Docker counts containers,
    // not "running containers and then some exited ones", so a stack where three services are still
    // up and two have finished must answer `-n 2` with the two newest of the five - the cut is made
    // here, on one ordering, and not by trimming each list to N.
    //
    // ORDERED ON THE KERNEL START-TIME, which is the one clock both records hold and the one that
    // means CREATED. The first version of this sorted on "how long ago did it last do something" -
    // `now - started` for a live box and `exited_ago` for a dead one - and those are two different
    // questions wearing one name: a box created an hour ago that finished a second ago came out
    // NEWER than one created a second ago, which is the opposite of what `--last` asks. The ticks
    // are comparable within a boot, which is the only span either record survives (a live box dies
    // with the machine, an exit record is reaped after an hour). `-n 0` lists nothing, as Docker's
    // does.
    // `--last N` SELECTS AMONG THE BOXES THAT RAN, and so it drops the kept section rather than
    // printing it whole beside a capped list. MEASURED with 1000 kept boxes: `ps -a --last 2`
    // answered with 1002 rows, which is not what "the 2 most recent" asks for. The alternative was
    // to order the three kinds together, and they have no comparable clock: live and exited rows are
    // ordered on the KERNEL start-time (ticks, comparable only within a boot, and the one key that
    // means CREATED for both - see the note below), while a kept box outlives the boot and has only
    // a unix `created`. Mixing a tick count with a unix second is how a sort silently lies, so
    // `--last` answers about runs and plain `ps -a` lists the kept layers.
    if view.last.is_some() {
        kept.clear();
    }
    let (boxes, exited) = match view.last {
        None => (boxes, exited),
        Some(n) => {
            // (start-time ticks, is_live, index), newest first; `is_live` breaks a tie toward the
            // running box, which is the one a reader is more likely to have meant.
            let mut order: Vec<(u64, bool, usize)> = boxes
                .iter()
                .enumerate()
                .map(|(i, b)| (b.starttime, true, i))
                .chain(
                    exited
                        .iter()
                        .enumerate()
                        .map(|(i, e)| (e.starttime, false, i)),
                )
                .collect();
            order.sort_by_key(|(ticks, live, _)| (std::cmp::Reverse(*ticks), !*live));
            order.truncate(n);
            let keep_live: std::collections::HashSet<usize> = order
                .iter()
                .filter(|(_, live, _)| *live)
                .map(|(_, _, i)| *i)
                .collect();
            let keep_exited: std::collections::HashSet<usize> = order
                .iter()
                .filter(|(_, live, _)| !*live)
                .map(|(_, _, i)| *i)
                .collect();
            // NEWEST FIRST, AND THE SAME ORDER TWICE FOR THE SAME BOXES. Plain `ps` lists oldest
            // first, which is the registry's order and stays that way; `--last N` asks a question
            // ABOUT RECENCY, and answering it in the opposite order made "the newest" the bottom
            // row. The rows were also not stable: the registry sorts on a start time measured in
            // clock ticks, so boxes created inside the same tick tied and kept whatever order the
            // directory happened to be read in, which is why four boxes started in a loop could
            // come back in any arrangement. NAME BREAKS THE TIE because it is the one key that is
            // unique, present on both records and independent of how the entries were read.
            let mut boxes: Vec<_> = boxes
                .into_iter()
                .enumerate()
                .filter(|(i, _)| keep_live.contains(i))
                .map(|(_, b)| b)
                .collect();
            let mut exited: Vec<_> = exited
                .into_iter()
                .enumerate()
                .filter(|(i, _)| keep_exited.contains(i))
                .map(|(_, e)| e)
                .collect();
            boxes.sort_by(|a, b| b.starttime.cmp(&a.starttime).then(a.name.cmp(&b.name)));
            exited.sort_by(|a, b| b.starttime.cmp(&a.starttime).then(a.name.cmp(&b.name)));
            (boxes, exited)
        }
    };
    // `-q`/`--quiet`: names only, one per line - scriptable, e.g. `kern stop $(kern ps -q)`. An exited
    // box's name is already scrubbed at the source (`list_exited`), so it is safe to print raw here.
    if quiet {
        for b in &boxes {
            if view.ids {
                println!("{}", b.pid);
            } else {
                println!("{}", b.name);
            }
        }
        for e in &exited {
            println!("{}", e.name);
        }
        for k in &kept {
            println!("{}", k.name);
        }
        return Ok(());
    }
    // `--format '{{.Field}}'`: render each box through the bounded template (no Go-template logic).
    // `table ...` IS DOCKER'S DIRECTIVE: a header line, then the rows aligned as its tabwriter
    // aligns them; `table` alone is the default listing. MEASURED on Docker Compose 5.3.1:
    // `--format "table {{.Name}}\t{{.Status}}"` prints `NAME          STATUS` over the rows, and
    // kern printed the word `table` at the start of every row.
    // `compose ps` WITHOUT `--format` IS DOCKER'S TABLE, the columns `docker compose ps` prints
    // (MEASURED on 5.3.1: NAME IMAGE COMMAND SERVICE CREATED STATUS PORTS). kern printed its own
    // pod tree there, which is still `kern ps`'s listing.
    const COMPOSE_DEFAULT: &str = "table {{.Name}}\t{{.Image}}\t{{.Command}}\t{{.Service}}\t\
                                   {{.RunningFor}}\t{{.Status}}\t{{.Ports}}";
    let format =
        format.or((view.compose && !quiet && shape == JsonShape::No).then_some(COMPOSE_DEFAULT));
    let directive = format.map(|f| match f.strip_prefix("table") {
        Some(rest) => (true, rest.trim_start()),
        None => (false, f),
    });
    if let Some((table, tmpl)) = directive.filter(|(table, t)| !(*table && t.is_empty())) {
        let service_of = |n: &str| -> Option<String> {
            view.services
                .and_then(|m| m.iter().find(|(b, _, _)| b == n).map(|(_, s, _)| s.clone()))
        };
        let image_of = |n: &str| -> Option<String> {
            view.services.and_then(|m| {
                m.iter()
                    .find(|(b, _, i)| b == n && !i.is_empty())
                    .map(|(_, _, i)| i.clone())
            })
        };
        let ctx = PsCtx {
            now: registry::now_unix(),
            service: Some(&service_of),
            image: Some(&image_of),
            docker_command: Some(!view.no_trunc),
        };
        let mut rows: Vec<(String, String)> = Vec::new();
        for b in &boxes {
            rows.push((b.name.clone(), render_ps_format_ctx(tmpl, b, &ctx)?));
        }
        for e in &exited {
            rows.push((e.name.clone(), render_ps_format_ctx(tmpl, e, &ctx)?));
        }
        for k in &kept {
            rows.push((k.name.clone(), render_ps_format_ctx(tmpl, k, &ctx)?));
        }
        if view.compose {
            rows.sort_by(|a, b| a.0.cmp(&b.0));
        }
        let mut lines: Vec<String> = Vec::with_capacity(rows.len() + 1);
        if table {
            lines.push(render_ps_header(tmpl, view.compose)?);
        }
        lines.extend(rows.into_iter().map(|(_, r)| r));
        if table {
            print!("{}", tabwrite(&lines));
        } else {
            for l in lines {
                println!("{l}");
            }
        }
        return Ok(());
    }
    if shape != JsonShape::No {
        let mut items: Vec<String> = boxes
            .iter()
            .map(|b| {
                // `status` IS NOT `health`, and leaving it out made `--json` the only blind channel.
                // MEASURED on one paused box: the table said `paused`, `--format '{{.Status}}'` said
                // `paused`, `--filter status=paused` matched it, and `--json` said `"health":""`.
                // Same for an orphaned box, whose supervisor is dead while its workload still holds
                // the port: the table says `orphaned` and the JSON said nothing at all. The channel
                // that loses the fact is the one scripts and agents read.
                //
                // ADDED rather than folded into `health`, because they are two different facts (a box
                // can be orphaned AND unhealthy) and because `--json` is declared additive: consumers
                // ignore unknown fields, and no existing one changes meaning here. The string comes
                // from `box_status`, the same function the table and `--format` use, so the four
                // channels cannot drift again.
                // `labels` is the field a caller could SET and FILTER on but never read back: the
                // box carried it, `--filter label=` matched it, and no output surface printed it.
                // An object rather than the registry's comma-joined text, because a consumer that
                // has to re-split a string is doing the parsing this document exists to avoid.
                format!(
                    "{{\"name\":{},\"pid\":{},\"pod\":{},\"rootfs\":{},\"command\":{},\"started\":{},\"ports\":{},\"url\":{},\"labels\":{},\"health\":{},\"status\":{}}}",
                    json_str(&b.name),
                    b.pid,
                    json_str(&b.pod),
                    json_str(&b.rootfs),
                    json_str(&b.command),
                    b.started,
                    json_str(&b.ports),
                    // The `.localhost` URL its published port answers at, `null` without one.
                    crate::localrouter::url_of(&b.name, &b.pod, &b.ports)
                        .map_or_else(|| "null".to_string(), |u| json_str(&u)),
                    labels_json(&b.labels),
                    json_str(&registry::health_of(&b.name, b.pid)),
                    json_str(&super::box_status(b, "running")),
                )
            })
            .collect();
        // Exited rows carry the fields a dead box still has plus `exit_code`; `ports`/`rootfs` are
        // gone with the box, so they are simply absent rather than emitted as a lie. `started` is
        // there when the exit record's kernel start time converts to a wall clock, the same clock
        // the table's CREATED column reads, and absent when it does not: the Docker API's
        // `StartedAt` of an exited container is built from it.
        for e in &exited {
            let started = super::started_unix(e.starttime)
                .map_or_else(String::new, |s| format!(",\"started\":{s}"));
            items.push(format!(
                // `status` here too, with the same value `health` already carried, so a consumer can
                // read ONE key across live and exited rows instead of knowing that a dead box spells
                // its state in the health field. `health` keeps saying `exited` because something may
                // already read it.
                "{{\"name\":{},\"pid\":{},\"pod\":{},\"command\":{},\"exit_code\":{},\"exited_ago\":{}{started},\"health\":{},\"status\":{}}}",
                json_str(&e.name),
                e.pid,
                json_str(&e.pod),
                json_str(&e.command),
                e.code,
                e.exited_ago,
                json_str("exited"),
                json_str("exited"),
            ));
        }
        for k in &kept {
            // `status` is `kept`, which is the value `--filter status=kept` selects and the word the
            // table's header uses. `image` is the one field a kept box has that a live row spells
            // `rootfs`: it is what the recorded command will run, and it is the only way a consumer
            // can tell two kept boxes apart without replaying their argv. `exit_code` is absent
            // while the box has never finished a run, where `0` would read as a clean one.
            //
            // WHAT A KEPT ROW DOES NOT HAVE, because it is not a process and never was in this
            // boot: `pid`, `pod`, `ports`, `started`, `rootfs`. Absent, not zeroed - the same rule
            // the exited row follows for the fields that died with the box, so a consumer reading
            // `.pid` across `ps -a --json` must handle its absence (it already had to: an exited
            // row has no `started`, `ports` or `rootfs`). `labels` it has: they are in the
            // recorded command the next `kern start` runs, and a client finds a stopped container
            // by them. `exited_ago` once a run has ended, as on an exited row.
            let exit = match (k.meta.last_exit, k.exited_ago) {
                (Some(c), Some(ago)) => format!(",\"exit_code\":{c},\"exited_ago\":{ago}"),
                (Some(c), None) => format!(",\"exit_code\":{c}"),
                (None, _) => String::new(),
            };
            items.push(format!(
                "{{\"name\":{},\"command\":{},\"image\":{},\"created\":{}{exit},\"labels\":{},\"health\":{},\"status\":{}}}",
                json_str(&k.name),
                json_str(&crate::ui::scrub(&k.command)),
                json_str(&crate::ui::scrub(&k.meta.image)),
                k.meta.created,
                labels_object(k.labels.iter().cloned()),
                json_str("kept"),
                json_str("kept"),
            ));
        }
        if shape == JsonShape::Lines {
            // ONE OBJECT PER LINE, and the keys `docker compose ps --format json` uses ALONGSIDE
            // kern's own. Two spellings in one object, not a translation: kern's keys are lowercase
            // (`name`, `command`, `health`) and Docker's are capitalised (`Name`, `Command`,
            // `Health`), so nothing collides and neither consumer has to know about the other.
            //
            // WHY THE NAMES MATTER MORE THAN THE FRAMING. Matching NDJSON and then emitting
            // `{"name": …}` would still break the line every deploy script actually contains,
            // `compose ps --format json | jq -r .Service`. A later pass put this exactly:
            // the field names are the contract a script reads, and this is a NEW surface, so they
            // cost nothing to get right.
            //
            // ONLY WHAT THE REGISTRY CAN ANSWER TRUTHFULLY. `Image`, `Publishers`, `Mounts` and
            // `Size` are Docker keys kern has no value for here, and inventing a shape for them
            // would be worse than their absence: a script reading `.Publishers[0].PublishedPort`
            // must fail loudly, not read a zero.
            //
            // `Service` is derived from the box name by stripping the project prefix, which is how
            // kern built it (`<project>-<service>`). A box renamed by `container_name:` has no
            // prefix to strip and reports its own name, which is the same thing Docker reports for
            // a container named by hand.
            for (i, it) in items.iter().enumerate() {
                let docker = match boxes.get(i) {
                    Some(b) => {
                        let service = &json_service(&view, &b.name, &b.pod);
                        // `State` WAS THE LITERAL "running" FOR EVERY LIVE BOX, which is not a gap
                        // but a wrong answer: a PAUSED box reported itself as running to every
                        // Docker-shaped consumer, and `docker compose ps --format json` does emit
                        // `paused` for a paused container. MEASURED before the fix: the table said
                        // `paused`, `--format '{{.Status}}'` said `paused`, `--filter status=paused`
                        // matched, and this line said `running`.
                        //
                        // DOCKER'S VOCABULARY IN DOCKER'S KEY, kern's in kern's. Docker has no word
                        // for `orphaned` - the container IS running as far as that model goes - so
                        // `State` says `running` there and the kern-native `status` above carries
                        // the distinction. Inventing a state Docker consumers cannot parse would be
                        // the same mistake as inventing a `Publishers` shape.
                        let docker_state = super::docker_state(b);
                        format!(
                            ",\"ID\":{},\"Name\":{},\"Service\":{},\"Project\":{},\"State\":{},\"Health\":{},\"ExitCode\":0,\"Command\":{},\"Publishers\":{}",
                            json_str(&b.pid.to_string()),
                            json_str(&b.name),
                            json_str(service),
                            json_str(&b.pod),
                            json_str(docker_state),
                            json_str(&super::PsRow::ps_health(b)),
                            json_str(&b.command),
                            publishers_json(&b.ports),
                        )
                    }
                    None => match exited.get(i.saturating_sub(boxes.len())) {
                        Some(e) => {
                            let service = &json_service(&view, &e.name, &e.pod);
                            format!(
                                ",\"ID\":{},\"Name\":{},\"Service\":{},\"Project\":{},\"State\":{},\"Health\":{},\"ExitCode\":{},\"Command\":{}",
                                json_str(&e.pid.to_string()),
                                json_str(&e.name),
                                json_str(service),
                                json_str(&e.pod),
                                json_str("exited"),
                                json_str("exited"),
                                e.code,
                                json_str(&e.command),
                            )
                        }
                        None => String::new(),
                    },
                };
                // Splice before the closing brace, so the object stays one object.
                match it.strip_suffix('}') {
                    Some(head) => println!("{head}{docker}}}"),
                    None => println!("{it}"),
                }
            }
        } else {
            // Frame through the shared helper (the sole owner of the `[ , ]` array grammar), so a
            // live-only listing stays byte-for-byte what it was before `-a` existed and this isn't a
            // re-rolled array.
            println!("{}", kern_common::json_array(&items, |s| s.clone()));
        }
    } else {
        // Build rows first so the PORTS column can size to its widest value (a published mapping
        // like `127.0.0.1:8080->80` is wider than the "PORTS" header) - keeps COMMAND aligned.
        let now = registry::now_unix();
        let rows: Vec<(&registry::Instance, u64, String, String)> = boxes
            .iter()
            .map(|b| {
                // Up since the CURRENT run (a `--restart` box is run again in place).
                let (since, restarting) = super::current_run(b);
                let up = now.saturating_sub(since);
                // A frozen box (`kern pause`) is reported as "paused" here - otherwise it looks
                // identical to a running one in `ps`. `-` when no health check is configured. A box
                // between two runs says so, with the code the last one exited with.
                let health = match restarting {
                    Some(code) => format!("restarting ({code})"),
                    None => box_status(b, "-"),
                };
                let ports = if b.ports.is_empty() {
                    "-".to_string()
                } else {
                    b.ports.clone()
                };
                (b, up, health, ports)
            })
            .collect();
        let pw = rows
            .iter()
            .map(|(_, _, _, p)| p.chars().count())
            .chain(std::iter::once(5)) // len("PORTS")
            .max()
            .unwrap_or(5);
        // HEALTH is measured too, with its old 9 as the floor: `restarting (137)` is wider, and a
        // fixed cell pushed PORTS and COMMAND out of line on exactly the row a reader is watching.
        let hw = rows
            .iter()
            .map(|(_, _, h, _)| h.chars().count())
            .chain(std::iter::once(9))
            .max()
            .unwrap_or(9);
        // THE NAME COLUMN IS MEASURED, NOT ASSUMED. It was a fixed 16, and every name longer than
        // that pushed PID, UPTIME, HEALTH and PORTS out of line for the whole table. A compose box is
        // named `<project>-<hash8>-<service>`, which passes 16 for any service name at all, so the
        // stack views - the ones a person looks at while a demo is running - were the ones that
        // broke. MEASURED: `psbug-749cf899-secret` is 21 characters and shifted every column after
        // it. The rule, and the reason for the floor and the ceiling, now lives in one place:
        // `ui::name_col_width`, which four other tables had each got wrong in their own way.
        //
        // The LIVE rows measure their DISPLAYED name (a pod member drops the project prefix) and the
        // exited section its full one, because that is what each prints. THE KEPT SECTION TOO: it
        // was left out, so a kept name longer than every live and exited one overflowed its cell and
        // pushed every column after it out of line - in a pipe, where there is no ceiling and the
        // alignment is supposed to be exact. Measured with a 71-character kept name, which is a
        // length `kern box` accepts. This is the defect `name_col_width` exists to end, and the
        // sixth table was passing five of its six row kinds in.
        let nw = crate::ui::name_col_width(
            rows.iter()
                .map(|(b, _, _, _)| crate::ui::display_box_name(&b.name, &b.pod))
                .chain(exited.iter().map(|e| e.name.as_str()))
                .chain(kept.iter().map(|k| k.name.as_str())),
            16,
            20 + hw + pw,
        );
        // On a TTY, truncate COMMAND to the remaining width so a long command never wraps (like
        // `docker ps`); piped/non-TTY prints it whole so scripts get the full line.
        let tty = std::io::stdout().is_terminal();
        let width = crate::ui::term_width(libc::STDOUT_FILENO);
        let p = crate::ui::Palette::detect();
        // The visible width before COMMAND is fixed (16+1+7+1+7+2+9+1+pw+1 = 45+pw), so the budget
        // is computed arithmetically - colour codes never enter the count.
        let prefix_w = nw + 20 + hw + pw;
        println!(
            "{d}{:<nw$} {:>7} {:>7}  {:<hw$} {:<pw$} COMMAND{z}",
            "NAME",
            "PID",
            "UPTIME",
            "HEALTH",
            "PORTS",
            d = p.d,
            z = p.z
        );
        // The ONE column skeleton every row is emitted through - live OR exited - so a width change
        // can't desync the two paths. Callers pass their own pre-coloured, pre-padded NAME and STATUS
        // cells (they differ: tree connector vs raw name, health string vs `exit <code>`) and the raw
        // COMMAND, which is UNTRUSTED argv: scrubbed of terminal-control sequences (the guard inspect/
        // --format/--json also apply - raw would let `$'\e[2J'` clear the screen on every `kern ps`,
        // and an exited box's stored command would re-fire until `gc`), then TTY-truncated so it never
        // wraps.
        // `pid` is `Option`, because one row has none: a kept box is not a process, and a literal
        // `0` in that column reads as one.
        let emit_row = |name_cell: &str,
                        pid: Option<i32>,
                        time_cell: &str,
                        status_cell: &str,
                        ports: &str,
                        cmd: &str| {
            let safe = crate::ui::scrub(cmd);
            // `--no-trunc` TURNS THE TERMINAL RULE OFF. The default truncates on a TTY so a long
            // command never wraps, which is right for reading and wrong for the moment you need the
            // whole line - and until this flag existed the only way to get it was to pipe the output
            // somewhere, which also turns off every other thing a person is looking at.
            let cmd = if tty && !view.no_trunc {
                truncate(&safe, width.saturating_sub(prefix_w).max(8))
            } else {
                safe
            };
            let pid_cell = pid.map_or_else(|| "-".to_string(), |p| p.to_string());
            println!("{name_cell} {pid_cell:>7} {time_cell:>7}  {status_cell} {ports:<pw$} {cmd}");
        };
        // One LIVE box row. `connector` is a tree glyph ("├─ "/"└─ ") drawn INSIDE the 16-wide NAME cell
        // for a pod member, or "" for a standalone box - so every PID column still lines up.
        let print_row =
            |b: &registry::Instance, up: u64, health: &str, ports: &str, connector: &str| {
                let cw = connector.chars().count();
                // Inside a pod's tree the `<pod>-` prefix is redundant - the pod is the line above -
                // so the member shows the SERVICE name the compose file uses. The registry keeps the
                // full, project-scoped name; this is display only, and a standalone box (no pod) is
                // printed whole.
                let shown = crate::ui::display_box_name(&b.name, &b.pod);
                // dim connector, then reset, then the standard bold-cyan NAME padded to fill the cell.
                let name = format!(
                    "{d}{connector}{z}{b}{c}{:<nw$}{z}",
                    shown,
                    d = p.d,
                    z = p.z,
                    b = p.b,
                    c = p.c,
                    nw = nw.saturating_sub(cw),
                );
                let hc = match health {
                    "healthy" => p.g,
                    "unhealthy" => p.r,
                    _ => p.d,
                };
                let status_cell = format!("{hc}{:<hw$}{}", health, p.z);
                emit_row(
                    &name,
                    Some(b.pid),
                    &format!("{up}s"),
                    &status_cell,
                    ports,
                    &b.command,
                );
            };
        // Standalone boxes (no pod) print flat, exactly like before. Pod members are grouped under a
        // header line - the `kern ps` mirror of Docker Desktop's collapsed compose-project rows.
        for (b, up, health, ports) in rows.iter().filter(|(b, ..)| b.pod.is_empty()) {
            print_row(b, *up, health, ports, "");
        }
        // Group the rest by pod, pods in name order, members in start order (rows already are).
        let mut pods: std::collections::BTreeMap<
            &str,
            Vec<&(&registry::Instance, u64, String, String)>,
        > = std::collections::BTreeMap::new();
        for row in rows.iter().filter(|(b, ..)| !b.pod.is_empty()) {
            pods.entry(row.0.pod.as_str()).or_default().push(row);
        }
        for (pod, members) in &pods {
            // Pod header: bold accent name + a dim "(N boxes)" tag. `kern stop <pod>` acts on the whole
            // group - the header is the "root" the user stops or removes.
            let n = members.len();
            let plural = if n == 1 { "box" } else { "boxes" };
            // A HOLDER THAT IS GONE IS SAID ON THE HEADER: its members still run and their health
            // checks still pass inside them, while nothing reaches them (see `pod::holder_lost`).
            let lost = if crate::pod::holder_lost(pod) {
                " · HOLDER GONE: these services are cut off from each other and their ports; \
                 `kern compose up` recreates them"
            } else {
                ""
            };
            println!(
                "{b}{y}{pod}{z} {d}(pod · {n} {plural}{lost}){z}",
                b = p.b,
                y = p.y,
                d = p.d,
                z = p.z,
            );
            for (i, (b, up, health, ports)) in members.iter().enumerate() {
                let connector = if i + 1 == n { "└─ " } else { "├─ " };
                print_row(b, *up, health, ports, connector);
            }
        }
        // Exited boxes (only when `-a`/`status=exited`): a flat section under a dim header, driven off
        // the SAME `emit_row` as the live rows so they cannot desync. STATUS is `exit <code>` (green at
        // 0, red otherwise); the time cell is how long AGO it exited. The full `<pod>-<service>` name is
        // kept - there is no pod tree here to supply the context.
        if !exited.is_empty() {
            let n = exited.len();
            let plural = if n == 1 { "box" } else { "boxes" };
            println!("{d}exited{z} {d}({n} {plural}){z}", d = p.d, z = p.z);
            for e in &exited {
                let hc = if e.code == 0 { p.g } else { p.r };
                // name is already scrubbed at the source (`list_exited`), so it is safe in the cell.
                let name = format!("{b}{c}{:<nw$}{z}", e.name, b = p.b, c = p.c, z = p.z);
                let status_cell = format!("{hc}{:<hw$}{}", format!("exit {}", e.code), p.z);
                emit_row(
                    &name,
                    Some(e.pid),
                    &fmt_uptime(e.exited_ago),
                    &status_cell,
                    "-",
                    &e.command,
                );
            }
        }
        // KEPT BOXES, which are the ones `kern start` can run. A SEPARATE SECTION, because an exit
        // record and a kept box answer different questions: the exit records are transient (reaped
        // after an hour, gone with the machine) and say "this ran and finished", while a kept box is
        // state on disk that is still there and can be started again. Listed even when its exit
        // record has been reaped, which is the case the operator needs most: a box kept yesterday is
        // invisible in every other view.
        //
        // One that is RUNNING is not listed here - it is in the live section above, where its uptime
        // and health are - so one box is never two rows of one `ps -a`.
        if !kept.is_empty() {
            let n = kept.len();
            let plural = if n == 1 { "box" } else { "boxes" };
            println!(
                "{d}kept{z} {d}({n} {plural}, `kern start <name>` runs one again){z}",
                d = p.d,
                z = p.z
            );
            let now = registry::now_unix();
            for k in &kept {
                let name = format!("{b}{c}{:<nw$}{z}", k.name, b = p.b, c = p.c, z = p.z);
                // No pid: it is not running, and a stale one would read as a process. The time cell
                // is how long ago it was created, which is the only clock a kept box has that does
                // not expire with the machine.
                let status = match k.meta.last_exit {
                    Some(code) => format!("exit {code}"),
                    None => "never ran".to_string(),
                };
                let hc = if k.meta.last_exit == Some(0) {
                    p.g
                } else {
                    p.d
                };
                let status_cell = format!("{hc}{:<hw$}{}", status, p.z);
                let age = now.saturating_sub(k.meta.created);
                emit_row(&name, None, &fmt_uptime(age), &status_cell, "-", &k.command);
            }
        }
    }
    Ok(())
}

/// Does a kept box pass the `--filter`s `ps` was given? Only the keys a kept box can answer: it has
/// no pid, no pod and no health, and a filter on one of those is a question about a running box, so
/// it excludes every kept row rather than matching them all.
fn kept_matches(k: &crate::keepbox::KeptBox, filters: &[(String, String)]) -> bool {
    filters.iter().all(|(key, want)| match key.as_str() {
        "name" => k.name.contains(want),
        // `status=` is the one a script writes. A kept box is `created` when it has never finished a
        // run and `exited` when it has, which is Docker's vocabulary for the same two states.
        "status" => match want.as_str() {
            // `kept` IS THE QUERY THAT MEANS "what can `kern start` run": it selects every kept box
            // whether or not it has ever finished a run, and it selects nothing else (a running or
            // exited registry box has no such status, so `ps_matches` excludes it).
            "kept" => true,
            "exited" => k.meta.last_exit.is_some(),
            // NOT `created`: the usage message for this flag says kern has no created state, and a
            // mapping here would have made that sentence false for one row kind only. A kept box
            // that has never run is `status=kept` with no `exit_code` in `--json`, which answers the
            // same question without a second vocabulary.
            _ => false,
        },
        _ => false,
    })
}

/// `kern stats [--json]` - current memory + cumulative CPU time per running box (from cgroup).
pub fn stats(json: bool, names: &[String]) -> Result<(), Error> {
    let mut boxes = registry::list();
    // `stats <name>...` filters to the named boxes; a requested name that isn't running is reported
    // (not silently dropped - that would look like a box with no stats).
    if !names.is_empty() {
        // name-or-PID (NAME wins globally - an all-digit box name is never shadowed by a coincidental pid).
        let live: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
        let hit = |b: &registry::Instance, n: &str| -> bool {
            n == b.name || (!live.iter().any(|m| m == n) && n.parse::<i32>().ok() == Some(b.pid))
        };
        for want in names {
            if !boxes.iter().any(|b| hit(b, want)) {
                eprintln!("kern: no running box '{want}'");
            }
        }
        boxes.retain(|b| names.iter().any(|n| hit(b, n)));
    }
    if json {
        // `null` (not 0) when the box has no dedicated cgroup to read - "unknown", not "zero".
        let num = json_num;
        let out = kern_common::json_array(&boxes, |b| {
            format!(
                "{{\"name\":{},\"pid\":{},\"mem_bytes\":{},\"cpu_usec\":{}}}",
                json_str(&b.name),
                b.pid,
                num(registry::mem_bytes(b.cgroup_pid())),
                num(registry::cpu_usec(b.cgroup_pid()))
            )
        });
        println!("{out}");
    } else {
        let p = crate::ui::Palette::detect();
        // MEASURED, like `ps` above and for the same reason - this table was simply left out of that
        // fix. The FULL registry name, not the pod-stripped one: `stats` has no pod tree to supply
        // the context a bare service name would be missing.
        let nw = crate::ui::name_col_width(boxes.iter().map(|b| b.name.as_str()), 16, 29);
        println!(
            "{d}{:<nw$} {:>8} {:>9} {:>9}{z}",
            "NAME",
            "PID",
            "MEM",
            "CPU",
            d = p.d,
            z = p.z
        );
        for b in &boxes {
            let mem = registry::mem_bytes(b.cgroup_pid()).map_or("-".into(), human_bytes);
            let cpu = registry::cpu_usec(b.cgroup_pid())
                .map_or("-".into(), |u| format!("{:.1}s", u as f64 / 1e6));
            let name = format!("{}{}{:<nw$}{}", p.b, p.c, b.name, p.z);
            println!("{name} {:>8} {:>9} {:>9}", b.pid, mem, cpu);
        }
    }
    Ok(())
}

/// `kern inspect <name> [--json]` - full detail for one running box: its identity (pid, pid1,
/// rootfs, command, ports, uptime) plus live resource readings (mem/cpu/tasks) and health. A
/// superset of one `ps`+`stats` row for a single box. Untrusted fields (rootfs, command) are
/// scrubbed of terminal-escape sequences before display, exactly like the status panel and tables.
/// Errors with a `kern ps` hint if no live box has that name.
/// The GPU device nodes a running box can see, read through its PID 1.
///
/// `/proc/<pid1>/root` resolves into the box's own mount namespace, so this is the box's `/dev`
/// and not the host's. It is the same node set `--gpus` binds, which makes the row a reading of
/// what the box HAS rather than a replay of what the caller typed: a grant that silently failed,
/// or one a later phase undid, shows here as a dash.
///
/// `None` for a box whose PID 1 is not known or no longer alive, which is also the answer when
/// there is nothing to look inside. Every failure is the same answer, an empty list, because a box
/// whose `/dev` cannot be read has not been shown to hold a card.
/// The driver userspace a RUNNING box is holding, read from its own mount table, and the host's
/// current one beside it when the two have diverged.
///
/// WHY THIS EXISTS. A grant binds the host's driver libraries by path, and a bind pins the INODE.
/// Measured 2026-11-12 with a file this user owns, through the same mechanism: a running box kept
/// `VERSION-1` after the host file was replaced at the same path, and a box started afterwards got
/// `VERSION-2`. So after a driver upgrade a live box keeps the userspace it was granted while a new
/// one gets the new, and two boxes on one host run different driver userspace against one kernel
/// module. NVIDIA requires the two to match, and the error it produces, `Driver/library version
/// mismatch`, names neither the box nor the upgrade.
///
/// NOTHING RECORDED OR COMPARED IT. The grant knows `driver_version` and threw it away: it reached
/// no registry field and no surface, so the skew was invisible from outside the workload's own
/// crash. It is DERIVED here rather than recorded, from the version in the bound library's own
/// NAME, for the reason the node row is read rather than replayed: a recorded version can disagree
/// with what the box actually holds, and a reading cannot.
///
/// Empty when there is nothing to say: no pid, no granted library, or the two versions agree. A row
/// that printed on every box would bury the one case that matters.
pub(crate) fn gpu_driver_skew_of(pid1: Option<i32>) -> String {
    let Some(pid) = pid1 else {
        return String::new();
    };
    let Some(theirs) = box_driver_version(pid) else {
        return String::new();
    };
    // The host's own version line, through the same parser shape the resolver uses: the first
    // `N.N.N` token on it, because the open kernel module and the proprietary one word the rest of
    // the line differently and a reader keyed on position gets the empty string from one of them.
    let Ok(line) = std::fs::read_to_string("/proc/driver/nvidia/version") else {
        return String::new();
    };
    let Some(ours) = first_version_token(&line) else {
        return String::new();
    };
    skew_between(&theirs, ours)
}

/// The first `N.N.N` token on a line, which is how the driver's own version is found.
///
/// KEYED ON THE SHAPE, not on a position. The open kernel module writes `NVIDIA UNIX Open Kernel
/// Module for x86_64  580.173.02  Release Build` and the proprietary one words the prefix
/// differently, so a reader counting words gets the empty string from one of them. The resolver
/// learned this once already; this is the same rule and not a second one.
fn first_version_token(line: &str) -> Option<&str> {
    line.split_whitespace().find(|t| is_three_part_version(t))
}

/// `580.173.02` and not `580.173` or `5.8.0.1` or `x.y.z`.
fn is_three_part_version(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The version a library file name carries, from the `.so.` marker.
///
/// `libcuda.so.580.173.02` answers `580.173.02`. Keyed on the marker AND on the shape of what
/// follows, so `libfoo.so.1` and a name that merely contains digits do not answer.
fn driver_version_in_name(name: &str) -> Option<String> {
    let (_, version) = name.split_once(".so.")?;
    is_three_part_version(version).then(|| version.to_string())
}

/// The sentence, or nothing when the two agree.
///
/// EMPTY IS THE COMMON CASE and it has to stay empty: a row printed on every box would bury the one
/// case that matters, which is a host somebody upgraded under a box that is still running.
fn skew_between(theirs: &str, ours: &str) -> String {
    if theirs == ours {
        return String::new();
    }
    format!("granted under {theirs}, host now has {ours}")
}

/// The driver version a box's bound libraries carry, from the version in their own file names.
///
/// `mountinfo` and not the box's filesystem: the bound path is what the grant chose, and reading it
/// from the mount table cannot be confused by anything the box later created at the same name. The
/// FIRST such mount answers, because a grant binds one version's files and nothing else.
fn box_driver_version(pid: i32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;
    driver_version_in_mountinfo(&text)
}

/// [`box_driver_version`] over a mount table's text.
///
/// ⛔ THE VERSION MOST OF THE DRIVER'S OWN LIBRARIES CARRY, not the first one met. A Jetson's grant
/// binds GStreamer and V4L2 libraries too, and NVIDIA ships some with a version of their own
/// (`libnvidia-egl-gbm.so.1.1.0`, `libnvidia-egl-wayland.so.1.1.11`): MEASURED on a Jetson Orin Nano,
/// the row read "granted under 1.0.0" and then "granted under 1.1.0, host now has 540.4.0" on a box
/// nothing had upgraded, while a dozen `libnvidia-*.so.540.4.0` were bound beside them. A box left
/// running across an upgrade holds the OLD version on all of them, so the majority still names it.
fn driver_version_in_mountinfo(text: &str) -> Option<String> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for line in text.lines() {
        let Some(name) = line
            .split_whitespace()
            .nth(4)
            .and_then(|p| p.rsplit('/').next())
        else {
            continue;
        };
        if !(name.starts_with("libnvidia-") || name.starts_with("libcuda.so.")) {
            continue;
        }
        if let Some(v) = driver_version_in_name(name) {
            match counts.iter_mut().find(|(seen, _)| *seen == v) {
                Some((_, n)) => *n += 1,
                None => counts.push((v, 1)),
            }
        }
    }
    let best = counts.iter().map(|(_, n)| *n).max()?;
    counts.into_iter().find(|(_, n)| *n == best).map(|(v, _)| v)
}

pub(crate) fn gpu_nodes_of(pid1: Option<i32>) -> String {
    let Some(pid) = pid1 else {
        return String::new();
    };
    gpu_nodes_in(
        std::path::Path::new(&format!("/proc/{pid}/root/dev")),
        std::path::Path::new("/dev"),
    )
}

/// The same reading, over a directory a test can build, against the host nodes to agree with.
///
/// Split out because the property worth asserting is the PREDICATE, and the only way to reach it
/// through `gpu_nodes_of` is to have a live box: the forged shapes (a regular file, a directory, a
/// symlink to another character device, a whiteout) need no privilege to create and are exactly
/// what a box does. `host_dev` is `/dev` in production and is the half a box cannot write.
pub(crate) fn gpu_nodes_in(dev: &std::path::Path, host_dev: &std::path::Path) -> String {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = std::fs::read_dir(dev) else {
        return String::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            // THE KIND, NOT ONLY THE NAME, and the row claimed to be a reading of what the box HAS
            // while matching on the name alone. A box's `/dev` is its own writable tmpfs, so
            // `touch /dev/nvidia7; mkdir /dev/nvidia9` in a box with no grant at all made
            // `kern inspect` report `gpu  nvidia7 nvidia9` and lit `kern top`'s `gpu:N` badge, which
            // the TUI legend describes as a box LESS isolated than the default. Measured 2026-11-11.
            //
            // The kind comes from the directory read, so a SYMLINK to the box's own granted node
            // under a second name is a symlink here and not a character device: following it would
            // let one card report as two. That a box cannot manufacture the real thing is measured
            // rather than assumed: `mknod` for majors 195, 226 and 510 answers EPERM on every
            // filesystem a box can write, because `vfs_mknod` resolves CAP_MKNOD against the INITIAL
            // user namespace, and the positive control is a FIFO, which succeeds.
            // `symlink_metadata` AND NOT `file_type()`, which is the first fix this got and it was
            // wrong in the direction that matters least loudly: `readdir` does not cross mount
            // points, so the `d_type` of a granted node is the type of the PLACEHOLDER the bind was
            // mounted over, a regular file. Measured: with `e.file_type()` a box genuinely holding
            // `--gpus device=1` reported `gpu  -`. `lstat` resolves the mount at the final component
            // while still refusing to follow a symlink there, which is exactly the pair of
            // properties this needs: the granted node reads as a character device, and a symlink
            // the box made to one (`/dev/nvidia8 -> /dev/null`) reads as a symlink.
            //
            // THE KIND IS NOT ENOUGH EITHER, and the reason is that the measurement above enumerated
            // the majors a GPU uses instead of the exemption the kernel writes: `vfs_mknod` tests
            // CAP_MKNOD only `if (S_ISCHR(mode) || S_ISBLK(mode)) && !is_whiteout`, and a whiteout is
            // exactly `c 0 0`. So an unprivileged process CAN make a character device, measured on
            // ext4 and on a box's own tmpfs, and `python3 -c 'os.mknod("/dev/nvidia9", S_IFCHR, 0)'`
            // in a box holding `--gpus device=0` made this row read `nvidia0 nvidia9`, while a box
            // holding nothing read `nvidia7 nvidia8`. Measured 2026-11-11, after the kind check.
            //
            // So the device NUMBER has to agree with the host node of that name, which is the half
            // of the pair the box cannot write: the whiteout is 0:0 and the real card is 195:N, and
            // the two ways to carry a real number across are both refused. `mknod` of major 195, 226
            // or 510 is EPERM, and a hardlink from a granted node to a second name is EXDEV, because
            // the grant arrives as a bind mount and `link(2)` does not cross one (measured: `ln
            // /dev/nvidia0 /dev/nvidia7` in a box that holds nvidia0). Agreement also makes the row
            // fail closed on a host whose node is gone, which is the honest answer: a card kern can
            // no longer name is not a card it can report.
            let kind = std::fs::symlink_metadata(e.path()).ok()?;
            if !kind.file_type().is_char_device() {
                return None;
            }
            let n = e.file_name().to_string_lossy().into_owned();
            let host = std::fs::symlink_metadata(host_dev.join(&n)).ok()?;
            if !host.file_type().is_char_device() || host.rdev() != kind.rdev() {
                return None;
            }
            // The per-card nodes only. `nvidiactl`, `nvidia-uvm` and `nvidia-modeset` go with any
            // card, so listing them would make one card look like four.
            let rest = n.strip_prefix("nvidia")?;
            (!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())).then_some(n)
        })
        .collect();
    names.sort();
    names.join(" ")
}

/// The human `mem-cap` row: what was ASKED FOR, and whether that is what the kernel holds.
///
/// A free function rather than a `match` inside `inspect` because its most important branch is the
/// one this developer's host cannot produce. `enforced == None` needs a box whose PID 1 is outside
/// every kern leaf, which happens on a host with no usable cgroup delegation and not here; buried in
/// a 245-line I/O function that branch was unreachable by any test, and it is precisely the branch a
/// later pass had to discover by hand. Pure, total over the four `(asked, enforced)` shapes,
/// and pinned by `mem_cap_row_*` below.
///
/// The wording is deliberate in each arm:
/// - no cap asked: `-`, the same dash the rest of this block uses for "nothing to report".
/// - asked and held, equal: the number alone. The common case must stay quiet.
/// - asked and held, DIFFERENT: both, because an outer limit (a fleet cap on `kern.slice`, or a
///   `kern update` that has not been recorded) can bind tighter than the request, and reporting only
///   the request would name a ceiling the box does not actually have.
/// - asked and NOT held: say so in the row. Silence here is what let a box report `mem-cap 64M`
///   on a host holding no such limit, which is the defect this whole field exists to close.
///
/// AND A `memory.high` ABOVE THE BOX, appended whatever the arm, because it is the one limit the
/// arms above cannot express: the cap can be asked, held and equal, and the box still stalls before
/// reaching it. MEASURED on a Jetson Orin, 2026-10-03: `mem-cap 512M` over a box that `kern.slice`'s
/// `MemoryHigh=80M` held in state D at ~90 MiB. The row names the limit and the cgroup carrying it.
fn mem_cap_row(
    asked: Option<u64>,
    enforced: Option<u64>,
    throttle: Option<&kern_isolation::OuterMemoryHigh>,
) -> String {
    let base = match (asked, enforced) {
        (None, _) => "-".into(),
        (Some(asked), Some(live)) if live == asked => human_bytes(asked),
        (Some(asked), Some(live)) => {
            format!("{} (in force: {})", human_bytes(asked), human_bytes(live))
        }
        (Some(asked), None) => format!("{} (requested, NOT enforced here)", human_bytes(asked)),
    };
    match throttle {
        Some(t) => format!(
            "{base}; throttled above {} by {} (memory.high)",
            t.high_human(),
            t.cgroup_path()
        ),
        None => base,
    }
}

/// Report a cached IMAGE, for the case where `name` is not a running box.
///
/// WHY `inspect` ANSWERS BOTH. Docker's `inspect` takes a container OR an image, and kern's took only
/// a box: `docker inspect alpine` through the drop-in answered `no running box named 'alpine'` for a
/// reference the machine had on disk. Reported by a later pass as a declared gap on that
/// surface; the fix belongs in kern's own verb rather than in the translation layer, because the
/// question ("what is this thing kern knows about") is the same one either spelling is asking.
///
/// A BOX FIRST, ALWAYS. The box registry is consulted before the image cache, so a box named after an
/// image still reports the box - the live thing is what a reader inspecting a name is asking about,
/// and this path is only reached when there is no such box.
///
/// THE JSON IS DOCKER'S SHAPE, not kern's flat one. There was no prior kern shape for an image to
/// break (`--json` is additive by contract, and this subject is new), and a consumer of
/// `inspect <image>` reads `.Config.Env` / `.Config.Cmd`. Fields kern does not know are OMITTED
/// rather than filled: there is no image digest in the cache entry, so no `Id` is printed, and a
/// reader templating `.Id` gets nothing instead of a fabricated value.
fn inspect_image(name: &str, json: bool) -> Result<(), Error> {
    let cache = crate::commands::imagecache::cache_dir();
    let safe = crate::commands::imagecache::sanitize_ref(name);
    // A BUILT IMAGE HAS NO `<ref>/` DIRECTORY. `cache_entry_complete` describes a PULLED image, whose
    // rootfs is that directory; a layered build is a `.layers` manifest over `L/` (and a legacy one a
    // `.diff`), so it always read as absent. MEASURED with kern 0.30.0: `kern inspect` of a built
    // image answered "nothing named ... `kern pull` fetches one" while `kern images` listed it on the
    // line above. Present here means what `kern images` already means: the sentinel and the config
    // sidecar exist and no layer it references is missing.
    let built = cache.join(format!("{safe}.layers")).exists()
        || cache.join(format!("{safe}.diff")).is_dir();
    let present = if built {
        cache.join(format!("{safe}.ok")).exists()
            && cache.join(format!("{safe}.image")).exists()
            && !crate::commands::imagecache::image_stat(&cache, &safe).1
    } else {
        crate::commands::imagecache::cache_entry_complete(&cache, &safe)
    };
    if !present {
        // THREE SUBJECTS, NOT TWO. A reader who reaches here has usually just watched a box run,
        // and the third case is the one they are in: the box EXITED. `kern ps -a` lists it with its
        // code and `kern ps -a --json` carries the same as a field, so answering "nothing named
        // that, try `kern pull`" sent them to fetch an image named after their own box. Same
        // reasoning `wait` already applies a few hundred lines up: `ps -a` lists the box with its
        // code, so no other surface here may deny that it existed.
        if let Some(exited) = crate::registry::list_exited()
            .into_iter()
            .find(|e| e.name == *name)
        {
            return Err(Error::NotRunning(format!(
                "no running box named '{name}': it exited with {}. `kern ps -a` lists recently-exited boxes and `kern ps -a --json` carries the code as a field; `kern inspect` reports a box while it runs",
                exited.code
            )));
        }
        // A KEPT BOX IS A THIRD SUBJECT WITH THAT NAME, and saying "nothing named 'x'" about a
        // layer sitting in the store is the same defect as the one the note above records for
        // images: `kern ps -a` listed it while `kern inspect` denied it existed.
        if let Some(dir) = crate::keepbox::dir_of(name) {
            if crate::keepbox::read(&dir).is_some() {
                return Err(Error::NotRunning(format!(
                    "'{name}' is a kept box that is not running: its layer and its command line are \
                     in {}, and `kern start {name}` runs it. `kern inspect` reports a box while it \
                     runs, so start it first, and `kern ps -a` shows what the last run exited with",
                    dir.display()
                )));
            }
        }
        // NEITHER EXISTS, so name both subjects: a reader told only about boxes goes looking for
        // the wrong thing.
        return Err(Error::NotRunning(format!(
            "nothing named '{name}': no running box, no exit record for one, no kept box and no image in the local cache. `kern ps -a` lists recently-exited and kept boxes, `kern images` lists images and `kern pull {name}` fetches one"
        )));
    }
    let cfg = crate::commands::imagecache::read_image_config(&cache.join(format!("{safe}.image")));
    let (size, _dangling) = crate::commands::imagecache::image_stat(&cache, &safe);
    if json {
        let arr = |v: &[String]| -> String {
            let items: Vec<String> = v.iter().map(|x| json_str(x)).collect();
            format!("[{}]", items.join(","))
        };
        // `ExposedPorts` is Docker's OBJECT keyed by `<port>/<proto>`, not a list: a consumer walks
        // its keys.
        let ports: Vec<String> = cfg
            .exposed_ports
            .iter()
            .map(|(p, udp)| {
                format!(
                    "{}:{{}}",
                    json_str(&format!("{p}/{}", if *udp { "udp" } else { "tcp" }))
                )
            })
            .collect();
        let opt = |o: &Option<String>| o.as_deref().map(json_str).unwrap_or_else(|| "null".into());
        println!(
            // `Labels` AND `Healthcheck` WERE PARSED AND THEN NOT EMITTED. Both are read out of the
            // `.image` sidecar into `cfg` a few lines up and both were dropped on the floor here:
            // the human output below prints the healthcheck, so the two renderings of one image
            // disagreed about what kern knows, and `Labels` appeared in neither. An image's labels
            // are where `org.opencontainers.image.*` lives - source commit, version, licence - so a
            // consumer asking kern for them was told the image has none.
            "[{{\"RepoTags\":[{}],\"RepoDigests\":[{}],\"Os\":\"linux\",\"Architecture\":{},\"Size\":{},\"Config\":{{\"Entrypoint\":{},\"Cmd\":{},\"Env\":{},\"WorkingDir\":{},\"User\":{},\"ExposedPorts\":{{{}}},\"StopSignal\":{},\"Labels\":{},\"Healthcheck\":{}}}}}]",
            json_str(name),
            // The repository digest the pull recorded, as Docker lists it (`repo@sha256:...`);
            // empty for a build, a commit, a load, or an image pulled before it was recorded.
            cfg.repo_digest.as_deref().map_or_else(String::new, |d| {
                json_str(&kern_common::repo_digest_ref(name, d))
            }),
            // DOCKER'S SPELLING FOR THIS FIELD, which is the Go one: `docker image inspect` says
            // `amd64` where `docker info` says `x86_64`, and a consumer compares against a fixed
            // string. Same table as the shim's `--format` renderer, for the same reason.
            json_str(match std::env::consts::ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                other => other,
            }),
            size,
            arr(&cfg.entrypoint),
            arr(&cfg.cmd),
            arr(&cfg.env),
            opt(&cfg.workdir),
            opt(&cfg.user),
            ports.join(","),
            opt(&cfg.stop_signal),
            labels_object(cfg.labels.iter().cloned()),
            healthcheck_json(cfg.healthcheck.as_ref()),
        );
        return Ok(());
    }
    let p = crate::ui::Palette::detect();
    println!("{}{name}{} (image)", p.b, p.z);
    let row = |k: &str, v: &str| {
        if !v.is_empty() {
            println!("  {k:<14} {v}");
        }
    };
    row("size", &human_bytes(size));
    row("digest", cfg.repo_digest.as_deref().unwrap_or_default());
    row("entrypoint", &cfg.entrypoint.join(" "));
    row("command", &cfg.cmd.join(" "));
    row("workdir", cfg.workdir.as_deref().unwrap_or(""));
    row("user", cfg.user.as_deref().unwrap_or(""));
    row("stop signal", cfg.stop_signal.as_deref().unwrap_or(""));
    let ports: Vec<String> = cfg
        .exposed_ports
        .iter()
        .map(|(port, udp)| format!("{port}/{}", if *udp { "udp" } else { "tcp" }))
        .collect();
    row("exposes", &ports.join(", "));
    // The ENV is a list and can be long; it is printed one per line so a reader can grep it, and
    // counted first so the reader knows what they are looking at.
    if !cfg.env.is_empty() {
        println!("  {:<14} {} variable(s)", "env", cfg.env.len());
        for e in &cfg.env {
            println!("    {e}");
        }
    }
    if let Some(h) = &cfg.healthcheck {
        row("healthcheck", &h.test.join(" "));
    }
    // THE LABELS, which this rendering did not have either. One per line and counted first, the same
    // shape `env` above uses and for the same reason: an image can carry a dozen
    // `org.opencontainers.image.*` entries, and a reader greps them.
    let labels = label_pairs_of(cfg.labels.iter().cloned());
    if !labels.is_empty() {
        println!("  {:<14} {} label(s)", "labels", labels.len());
        for (k, v) in &labels {
            println!("    {k}={v}");
        }
    }
    Ok(())
}

/// `inspect` with Docker's `--format`, for the field set kern can answer TRUTHFULLY.
///
/// WHY THE FIELDS ARE ENUMERATED AND NOT MAPPED FROM A STRUCT. Docker's inspect document has
/// hundreds of fields describing a daemon kern does not have; answering one of them with a plausible
/// value is worse than refusing it, because a script that reads `.HostConfig.NetworkMode` and gets a
/// guess makes a decision on it. The table below is what kern KNOWS, and anything else is refused by
/// name - the same rule `docker version --format` follows after it failed open once.
///
/// MEASURED: Sentry's `install.sh` polls `docker inspect --format '{{.State.Running}}' <name>` in a
/// 60-iteration wait loop; kern answered `unknown flag "--format"`, the loop broke on the first
/// iteration and the step reported the container never became ready.
pub fn inspect_formatted(name: &str, json: bool, format: Option<&str>) -> Result<(), Error> {
    let Some(tmpl) = format else {
        return inspect(name, json);
    };
    let b = registry::find_ref(name);
    let running = b.is_some();
    let health = b
        .as_ref()
        .map(|i| registry::health_of(&i.name, i.pid))
        .unwrap_or_default();
    // A BOX THAT NEVER EXISTED IS NOT AN EXITED BOX, and this used to answer `exited` for both.
    //
    // The lookup was "is it running?", so every name that was not running - a typo, a service from
    // another stack, a box `down` removed an hour ago - rendered `.State.Status` as `exited` and
    // `.State.Running` as `false`, with exit status 0. That is the answer a wait loop is looking
    // for: `until [ "$(kern inspect -f '{{.State.Status}}' setup)" = exited ]` ENDS IMMEDIATELY on a
    // misspelled service and the script proceeds as if the step had completed. Docker answers `No
    // such object` and exits non-zero, and so does this now.
    //
    // The exited record is the `waitexit` breadcrumb `kern ps -a` reads, which is transient by
    // design (an hour), so a box that exited long ago is genuinely unknown to kern rather than
    // reported as anything. The refusal says so instead of leaving the reader to guess.
    let exited = if running {
        None
    } else {
        registry::list_exited().into_iter().find(|e| e.name == name)
    };
    if !running && exited.is_none() {
        return Err(Error::NotRunning(format!(
            "no box '{name}': it is not running, and kern holds no recent exit record for it \
             (`kern ps -a` lists what exited within the last hour). Refusing rather than reporting \
             it as exited, which a wait loop would read as done"
        )));
    }
    // Docker's `.State.Status` vocabulary, from the ONE function that reads the freezer and the
    // orphan flag. It used to be decided here by `health == "paused"`, a word `health_of` never
    // returns, so a frozen box reported `running` while `kern ps` reported `paused`.
    let status = match &b {
        None => "exited",
        Some(i) => box_lifecycle_status(i),
    };
    let field = |f: &str| -> Option<String> {
        match f {
            "State.Running" => Some(running.to_string()),
            "State.Status" => Some(status.to_string()),
            "State.Paused" => Some((status == "paused").to_string()),
            // Docker prints `healthy`/`unhealthy`/`starting`, and an empty string for a container
            // with no healthcheck. kern's registry uses the same words.
            "State.Health.Status" => Some(health.clone()),
            "State.Pid" => Some(b.as_ref().map_or(0, |i| i.pid1_recorded).to_string()),
            // Docker reports 0 while a container runs and the real status once it has exited, which
            // is exactly what the two sources here hold. It is the other half of the wait loop:
            // having learnt that a one-shot service is `exited`, the next question is whether it
            // exited WELL, and `kern ps -a` is a table rather than a value a script can test.
            "State.ExitCode" => Some(exited.as_ref().map_or(0, |e| e.code).to_string()),
            "Name" => Some(format!("/{name}")),
            "Config.Image" | "Image" => b.as_ref().map(|i| i.rootfs.clone()),
            // Every label as a JSON object, which is the shape `{{json .Config.Labels}}` asks for
            // and the only shape a caller can feed to a parser. A box past its exit has none: the
            // instance record that held them is pruned, so `{}` here is the honest empty and not a
            // lost value.
            "Config.Labels" => Some(labels_json(b.as_ref().map_or("", |i| i.labels.as_str()))),
            // Docker's published-port map. THE FIELD A HARNESS READS to learn where a service it
            // just started is actually reachable, and on a rootless runtime it is the one thing it
            // cannot assume: kern republishes a privileged port above 1024, so a caller that trusts
            // the number it asked for is wrong and one that reads this is right.
            "NetworkSettings.Ports" => Some(network_ports_json(
                b.as_ref().map_or("", |i| i.ports.as_str()),
            )),
            _ => None,
        }
    };
    // `{{.Label "key"}}`: ONE label, the only key here that takes an argument, so it is resolved
    // before the table lookup rather than inside it. Absent prints empty (Docker's behaviour, and
    // the token exists to be paired with `--filter label=`, which has already proven the key is
    // there); a missing quote is still an error, because that is a typo and not an absent label.
    let labelled = |key: &str| -> Option<Result<String, Error>> {
        let arg = key.strip_prefix("Label ")?.trim();
        Some(
            match arg
                .strip_prefix('"')
                .and_then(|k| k.strip_suffix('"'))
                .filter(|k| !k.is_empty())
            {
                // SCRUBBED, as `ps --format` scrubs the same value. It was not, and the two
                // renderers therefore disagreed about whether a label reaches the terminal raw:
                // MEASURED with a label carrying ESC, `ps --format` printed `[31mred` and
                // `inspect --format` printed the escape intact. A label is caller-supplied text
                // and one of the two paths was a terminal-injection surface.
                Some(k) => Ok(crate::ui::scrub(
                    &label_value(b.as_ref().map_or("", |i| i.labels.as_str()), k)
                        .unwrap_or_default(),
                )),
                None => Err(Error::Usage(
                    "inspect --format: {{.Label \"key\"}} needs a quoted key",
                )),
            },
        )
    };
    let mut out = String::with_capacity(tmpl.len());
    let mut rest = tmpl;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            return Err(Error::Usage(
                "inspect --format: an unterminated `{{` is not a template",
            ));
        };
        // `{{json .X}}`: Go's template pipeline as Docker exposes it, and the form every generated
        // command line uses for a field that is not a scalar. It is accepted and IGNORED as a
        // wrapper, because the two keys it is ever applied to (`.Config.Labels`,
        // `.NetworkSettings.Ports`) already render as JSON documents here and quoting them again
        // would hand the caller a string where it asked for an object. A scalar under `json` is the
        // one case that would differ from Docker, and it is not a shape any caller asks for.
        let raw = after[..close].trim();
        let jsonified = raw.starts_with("json ");
        let key = raw
            .strip_prefix("json ")
            .unwrap_or(raw)
            .trim()
            .trim_start_matches('.');
        // WHICH KEYS ARE ALREADY DOCUMENTS. Everything else under `json` is a SCALAR and Docker
        // quotes it: `docker inspect --format '{{json .Name}}'` prints `"/web"`, and kern printed
        // `/web`. An earlier comment here dismissed that as a shape nobody asks for, which is
        // wrong twice: `{{json .State.Status}}` is a common one, and a value that should be JSON
        // and is not breaks the parser on the other end of the pipe rather than the eye.
        let already_json = matches!(key, "Config.Labels" | "NetworkSettings.Ports");
        let quoted = |v: String| {
            if jsonified && !already_json {
                json_str(&v)
            } else {
                v
            }
        };
        if let Some(v) = labelled(key) {
            out.push_str(&quoted(v?));
            rest = &after[close + 2..];
            continue;
        }
        match field(key) {
            Some(v) => out.push_str(&quoted(v)),
            None => {
                return Err(Error::NotRunning(format!(
                    "inspect --format names '{{{{.{key}}}}}', which kern cannot answer - refusing rather than printing something a script would read as the answer. `kern inspect {name} --json` prints what kern knows"
                )))
            }
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    println!("{out}");
    Ok(())
}

pub fn inspect(name: &str, json: bool) -> Result<(), Error> {
    let Some(b) = registry::find_ref(name) else {
        // A RUNNING BOX, then an IMAGE. `inspect` reports a box WHILE IT RUNS, and an exited one is
        // refused by `inspect_image` with its code and a pointer to `kern ps -a`, which is the
        // surface that carries the answer. The value a script wants from an exited box is served by
        // `inspect -f '{{.State.ExitCode}}'`, which reads the same exit record.
        return inspect_image(name, json);
    };
    let health = registry::health_of(&b.name, b.pid);
    let mem = registry::mem_bytes(b.cgroup_pid());
    let cpu = registry::cpu_usec(b.cgroup_pid());
    let tasks = registry::tasks(b.cgroup_pid());
    let up = registry::now_unix().saturating_sub(b.started);
    // WHAT IS ACTUALLY IN FORCE, read from the box's own cgroup, next to what was ASKED FOR.
    //
    // `memory_max` is the value the box was STARTED with: kern writes it into the registry entry and
    // this echoes it. It is not a read-back, and on a host that cannot delegate a cgroup there is
    // nothing behind it. A later pass measured exactly that: `--memory 64m` reported
    // `"memory_max": 67108864` while the box's PID 1 sat in `0::/`, the cgroup-v2 ROOT, which has no
    // `memory.max` file at all. A cap reported as a fact where the kernel holds none.
    //
    // The number is NOT changed, because a consumer may legitimately read it as "what was asked" and
    // `--json` is additive by contract. A second field answers the other question, and the two
    // together are the honest report: `memory_max` what you asked for, `memory_max_enforced` what the
    // kernel will hold you to. `null` there means nothing is enforcing it.
    //
    // Resolved from `/proc/<pid1>/cgroup` rather than from a recorded path: the registry's `cgroup`
    // field is empty for a box with no dedicated cgroup, which is precisely the case being reported on.
    //
    // THE BOX'S CGROUP WHOEVER NAMED IT, AND THE WHOLE CHAIN ABOVE IT. This used to read `memory.max`
    // at a single level reached through `box_cgroup_dir`, which refuses any leaf kern did not name,
    // and both halves cost a true answer. An independent host measured the first (2026-10-08): a
    // detached `--memory 64m` box that kern could not place in a cgroup of its own left its PID 1 in
    // the launcher's scope, so this answered `"memory_max_enforced": null` beside
    // `"memory_max": 67108864` - and `null` is what `kern doctor` tells a reader means "nothing in
    // force", on a reading that could not have told the two apart. The second is the mirror: an
    // ANCESTOR's ceiling is the one the kernel enforces on a box whose own level says `max`, and it
    // was invisible here. `memory_max_in_force` walks the chain the kernel walks.
    //
    // PINNED TO THE LIVE PID 1 (`live_pid1`, start-time checked) rather than the recorded number,
    // because this now reads a cgroup kern does not own: a recycled pid would otherwise have this
    // report a stranger's ceiling as the box's. `None` there answers exactly as a missing cgroup does.
    let box_dir = b.live_pid1().and_then(kern_isolation::effective_cgroup_dir);
    let enforced_mem = box_dir
        .as_deref()
        .and_then(kern_isolation::memory_max_in_force);
    // The limit the two numbers above cannot show: a `memory.high` on or above the box's cgroup that
    // the kernel applies before the cap. Same directory, so the three readings are about one box.
    let outer_mem_high = box_dir
        .as_deref()
        .and_then(kern_isolation::outer_memory_high);
    if json {
        // ⚠️ ONE OBJECT, WHERE `docker inspect` EMITS AN ARRAY of one. Measured: Docker's document
        // opens with `[`. kern's opens with `{`, deliberately and from before this, because
        // `kern inspect` names exactly one box; but the habit a caller brings is `jq '.[0].x'`,
        // and that reads `null` here rather than failing. Said out loud at the point the shape is
        // produced, because a reader of this function is the one who would otherwise assume.
        // `null` (not 0) for a resource the box has no dedicated cgroup to read - "unknown".
        let num = json_num;
        // THE ONE FIELD A SCRIPT ASKS FOR FIRST WAS NOT THERE. The document carried `health`, which
        // is empty for the majority of boxes (no healthcheck), and nothing that answered "is it
        // running?" - so `kern inspect x --json | jq -r .status` read `null` and every caller had to
        // infer liveness from the presence of a `pid`. The vocabulary is the one `-f
        // '{{.State.Status}}'` and `ps --format '{{.Status}}'` already print, so the three surfaces
        // agree word for word: `running`, `paused`, `exited`.
        let status = box_lifecycle_status(&b);
        // THE HARDWARE ROW WAS HUMAN-ONLY, against this file's own contract. `--json` is additive by
        // contract, and a consumer asking "which of my boxes hold a card" had to parse the human
        // output or go to `kern top`'s badge. It is the one row whose answer a script most plausibly
        // acts on, since it decides scheduling.
        //
        // The SAME call the human row uses, so the two cannot disagree: a string of card names, and
        // `null` rather than `""` for a box holding none, because an empty string reads as "a card
        // with no name" to a consumer that only checks presence.
        let gpu = gpu_nodes_of(b.live_pid1());
        let gpu_json = if gpu.is_empty() {
            "null".to_string()
        } else {
            json_str(&gpu)
        };
        println!(
            "{{\"name\":{},\"status\":{},\"pid\":{},\"pid1\":{},\"rootfs\":{},\"image\":{},\"command\":{},\"created\":{},\"started\":{},\"uptime\":{},\"ports\":{},\"url\":{},\"labels\":{},\"health\":{},\"mem_bytes\":{},\"cpu_usec\":{},\"tasks\":{},\"pod\":{},\"egress\":{},\"landlock_rw\":{},\"gpu\":{},\"memory_max\":{},\"memory_max_enforced\":{},\"memory_high_outer\":{},\"memory_high_outer_cgroup\":{},\"pids_max\":{},\"ends_at\":{}}}",
            json_str(&b.name),
            json_str(status),
            b.pid,
            b.pid1_recorded,
            json_str(&b.rootfs),
            // The `--image` the box was started from, as the registry recorded it; `null` for a
            // `--rootfs` box, which has none. The Docker API's `Image` and `Config.Image` are
            // this, and Testcontainers for Java inspects that image right after the start.
            if b.image.is_empty() {
                "null".to_string()
            } else {
                json_str(&b.image)
            },
            json_str(&b.command),
            // When the box was MADE: a kept box's record says, across its restarts (`started` is
            // this run's); any other box was made when it started. The Docker API's `Created` is
            // this, and Dev Containers keys `postCreateCommand` on it: from `started`, it ran the
            // command again at every reopen.
            crate::keepbox::dir_of(&b.name)
                .and_then(|d| crate::keepbox::read(&d))
                .map_or(b.started, |(_, m)| m.created),
            b.started,
            up,
            json_str(&b.ports),
            crate::localrouter::url_of(&b.name, &b.pod, &b.ports)
                .map_or_else(|| "null".to_string(), |u| json_str(&u)),
            labels_json(&b.labels),
            json_str(&health),
            num(mem),
            num(cpu),
            num(tasks),
            json_str(&b.pod),
            json_str(&b.egress),
            json_str(&b.landlock_rw),
            gpu_json,
            num(b.memory_max),
            num(enforced_mem),
            num(outer_mem_high.as_ref().map(|o| o.high)),
            outer_mem_high
                .as_ref()
                .map_or_else(|| "null".to_string(), |o| json_str(&o.cgroup_path())),
            num(b.pids_max),
            // When the box's deadline stops it (Unix seconds), `null` for none: `--timeout`, moved
            // by `kern update --timeout`. A foreground box's own timer is not recorded here.
            num(registry::box_deadline(&b.name, b.pid)
                .filter(|d| d.at_unix_ms > 0)
                .map(|d| d.at_unix_ms / 1000)),
        );
    } else {
        let p = crate::ui::Palette::detect();
        let row = |k: &str, v: &str| println!("{d}{k:<8}{z} {v}", d = p.d, z = p.z);
        // Bold-cyan name header, matching the panel/tables. The name is charset-validated by
        // `BoxName`; rootfs/command are untrusted, so they go through `scrub`.
        println!("{}{}{}{}", p.b, p.c, b.name, p.z);
        // The same word the JSON and the template print, so the three surfaces cannot be read as
        // saying different things about one box. `paused` is the case worth a row of its own: a
        // frozen box still has a pid, an uptime and a cgroup, and every other row here looks exactly
        // as it does for a running one.
        row("status", box_lifecycle_status(&b));
        row("pid", &b.pid.to_string());
        if b.pid1_recorded != 0 {
            // MARKED WHEN THE GATE REFUSES IT. The recorded number is what this row is for, and
            // printing it bare made a pid the runtime will NOT use indistinguishable from one it
            // will: a reader comparing `inspect` against `ps` or `/proc` would be reasoning about a
            // number that no consumer trusts. `stale` here means the process at that pid is not the
            // one we registered, so every consumer falls back to the supervisor's child instead.
            let pid1 = match b.live_pid1() {
                Some(_) => b.pid1_recorded.to_string(),
                None => format!("{} (stale: not the process recorded)", b.pid1_recorded),
            };
            row("pid1", &pid1);
        }
        row("uptime", &fmt_uptime(up));
        row("rootfs", &crate::ui::scrub(&b.rootfs));
        row("command", &crate::ui::scrub(&b.command));
        row("ports", if b.ports.is_empty() { "-" } else { &b.ports });
        row("health", if health.is_empty() { "-" } else { &health });
        row("mem", &mem.map_or("-".into(), human_bytes));
        row(
            "cpu",
            &cpu.map_or("-".into(), |u| format!("{:.1}s", u as f64 / 1e6)),
        );
        row("tasks", &tasks.map_or("-".into(), |t| t.to_string()));
        // THE CARD THE BOX ACTUALLY HOLDS, read from the box's own `/dev` and not from what was
        // asked for. The registry records no device, and persisting one would create a second
        // answer that a later edit could let drift; this row is the box's reality, in the same
        // register as `mem` and `tasks` above, which read live cgroup files rather than the flags.
        let gpu = gpu_nodes_of(b.live_pid1());
        row("gpu", if gpu.is_empty() { "-" } else { &gpu });
        // ONLY WHEN THE TWO HAVE DIVERGED. A row on every box would bury the one case that matters,
        // and on a host nobody has upgraded this is silent.
        let skew = gpu_driver_skew_of(b.live_pid1());
        if !skew.is_empty() {
            row("driver", &skew);
        }
        // Configured caps (the REQUESTED limits, distinct from the live usage above, which reads `-`
        // when the box has no dedicated cgroup) and the 0.6.7 isolation policies, shown when set.
        row(
            "mem-cap",
            &mem_cap_row(b.memory_max, enforced_mem, outer_mem_high.as_ref()),
        );
        row(
            "pids-cap",
            &b.pids_max.map_or("-".into(), |v| v.to_string()),
        );
        if !b.pod.is_empty() {
            row("pod", &b.pod);
        }
        if !b.egress.is_empty() {
            row("egress", &crate::ui::scrub(&b.egress));
        }
        if !b.landlock_rw.is_empty() {
            row("landlock", &crate::ui::scrub(&b.landlock_rw));
        }
    }
    Ok(())
}

/// `kern recover` - reconcile the runtime state: drop registry entries for boxes whose process is
/// gone (a crash/kill that skipped the supervisor's cleanup) and remove the orphaned overlay scratch
/// they left behind. Never touches a live box.
pub fn recover() -> Result<(), Error> {
    let (recovered, freed) = sweep_orphan_scratch();
    let p = crate::ui::Palette::detect();
    if recovered == 0 {
        println!(
            "{}nothing to recover - runtime state is consistent{}",
            p.d, p.z
        );
    } else {
        println!(
            "{g}recovered{z} {recovered} orphaned box scratch dir(s), freed {}",
            human_bytes(freed),
            g = p.g,
            z = p.z
        );
    }
    Ok(())
}

/// `kern rename <old> <new>` - give a running box a new name (Docker parity). The box keeps running
/// under the new name; its pid is unchanged. Refuses an invalid name or one already held by a live
/// box. Foreground/detached boxes only (an interactive `-it` box is not registered).
pub fn rename(old: &str, new: &str) -> Result<(), Error> {
    let parsed = BoxName::parse(new).map_err(Error::InvalidBox)?;
    let new = parsed.as_str();
    let p = crate::ui::Palette::detect();
    if registry::find_ref(new).is_some() {
        return Err(Error::AlreadyRunning(format!(
            "a box named '{new}' is already running"
        )));
    }
    let Some(inst) = registry::find_ref(old) else {
        // A KEPT BOX THAT IS NOT RUNNING is renamed too, as Docker renames a stopped or created
        // container: only its layer and its record carry the name.
        if crate::keepbox::rename(old, new)? {
            println!("{}renamed{} {old} → {new}", p.g, p.z);
            return Ok(());
        }
        return Err(Error::NotRunning(format!(
            "no running box named '{old}' and no kept box by that name"
        )));
    };
    if inst.name == new {
        return Ok(()); // already named that - a no-op, not an error
    }
    // The layer first: a name already kept elsewhere refuses before the registry moves.
    let kept = crate::keepbox::rename(&inst.name, new)?;
    if let Err(e) = registry::rename(&inst.name, new, inst.pid) {
        // Put the layer back, so the box and its layer keep answering to one name.
        if kept {
            let _ = crate::keepbox::rename(new, &inst.name);
        }
        return Err(Error::Sandbox(format!(
            "rename '{}' to '{new}': {e}",
            inst.name
        )));
    }
    println!("{}renamed{} {} → {new}", p.g, p.z, inst.name);
    Ok(())
}

/// The longest `kern wait` sleeps with nothing to wake it: the poll it had.
const WAIT_FLOOR_MS: i32 = 100;

/// `kern wait <box>...` - block until each box exits, then print its exit code, one per line, in
/// argument order (Docker `wait`). A box that has ALREADY exited answers at once from its exit
/// record, for as long as `kern ps -a` still lists it; past that window, and for an interactive
/// `-it` box (never registered, no supervisor to record a code), there is nothing to answer with.
/// The command itself returns 0 unless a name doesn't resolve. Woken when the box leaves the
/// registry (inotify), with a 100 ms poll as the floor - no daemon, no busy-spin.
pub fn wait(names: &[String]) -> Result<(), Error> {
    for name in names {
        let Some(inst) = registry::find_ref(name) else {
            // Not running: answer from the exit record if the box left one, which is Docker's
            // behaviour (`docker wait` on a stopped container returns its code at once) and the one
            // `kern ps -a` already implies - it lists that box WITH its code, so refusing to say the
            // same number here was an inconsistency in our own surface, not ephemerality. Newest
            // first, so a recycled name answers about the run that just ended. Outside the `ps -a`
            // window there is nothing left to read and the error below is the honest answer.
            if let Some(exited) = registry::list_exited()
                .into_iter()
                .find(|e| e.name == *name)
            {
                println!("{}", exited.code);
                continue;
            }
            return Err(Error::NotRunning(format!(
                "no running box named '{name}' and no exit record for one (kern keeps no stopped boxes; the record is dropped by `prune`/`gc`, and an hour after the box exited)"
            )));
        };
        // Block on the EXACT (name,pid) pair leaving the registry, so a reused pid or name can't make
        // a still-live box read as gone. The supervisor (self-exit) and `stop`/`kill` both write the
        // `(pid,starttime)`-keyed exit sidecar before the box leaves `list()`, so once the pair is gone
        // the code is already recorded. The read is NON-consuming, so parallel/repeat waiters all see it.
        //
        // WOKEN AT THE REMOVAL, by inotify on the registry (`BoxWaiter`), with the old 100 ms poll
        // as the floor: an attached `docker run` paid that poll on every command that ends at once.
        let waiter = crate::commands::boxlog::BoxWaiter::new(None);
        while registry::pair_alive(&inst.name, inst.pid) {
            waiter.wait(WAIT_FLOOR_MS);
        }
        match registry::box_exit(inst.pid, inst.starttime) {
            Some(code) => println!("{code}"),
            None => {
                // Gone but no recorded code. THREE causes, and this cannot tell them apart: a
                // foreground/-it box (no supervisor to capture one), a box started with `--rm`
                // (whose whole purpose is to leave no record), or a crash that killed the
                // supervisor before it could write. The record that would say which is the record
                // that is missing, and the instance entry went with the box.
                //
                // SO IT NAMES ALL THREE rather than asserting one. It used to assert the first,
                // and `--rm` made that assertion wrong: a caller reading the line was told its
                // box ran in the foreground when it had explicitly asked for no record. A
                // diagnosis with more than one cause does not get to declare one.
                eprintln!(
                    "kern: box '{}' exited without a recorded exit code. One of: it ran in the \
                     foreground or under -it (no supervisor to capture one), it was started with \
                     `--rm` (which leaves no record by design), or its supervisor died before it \
                     could write one",
                    inst.name
                );
            }
        }
    }
    Ok(())
}

/// `kern diff <box>` - list filesystem changes vs the box's image (Docker `diff`). Walks the box's
/// overlay UPPER (writable) layer: `C <path>` = a path created or modified, `D <path>` = a deletion
/// (an overlayfs whiteout). Deletions (`D`) are exact; kern does not distinguish brand-new (`A`) from
/// modified (`C`) without diffing against the base image, so both surface as `C`. Likewise a directory
/// wholly replaced in the box (`rm -rf d && mkdir d`, an overlayfs *opaque* dir) shows as `C d` without
/// a per-file `D` for the wiped lower contents. Only overlay boxes have an upper: a `--bind-rootfs` box
/// writes through to its source (nothing to diff) and a `--read-only` box has an empty upper (no changes).
pub fn diff(name: &str, json: bool) -> Result<(), Error> {
    // A KEPT BOX'S LAYER IS ITS OWN, running or stopped, and that is where its changes are: `--keep`
    // mounts `keepbox::dir_of(<name>)/upper` as the upper, not the scratch sibling of `merged`.
    // MEASURED: `kern diff` on a running `--keep` box answered "has no overlay to diff - it uses
    // --bind-rootfs", which it did not, and Docker's `diff` also answers for a stopped container.
    let inst = registry::find_ref(name);
    let box_name: String = inst
        .as_ref()
        .map_or_else(|| name.to_string(), |i| i.name.clone());
    let kept_upper = crate::keepbox::dir_of(&box_name)
        .map(|d| d.join("upper"))
        .filter(|u| u.is_dir());
    // `rootfs` is `<scratch>/<name>-<pid>/merged`; the writable upper is its sibling `upper`.
    let scratch_upper = inst.as_ref().and_then(|i| {
        let merged = std::path::Path::new(&i.rootfs);
        let is_overlay = merged.file_name().and_then(|s| s.to_str()) == Some("merged");
        merged
            .parent()
            .map(|s| s.join("upper"))
            .filter(|u| is_overlay && u.is_dir())
    });
    if inst.is_none() && kept_upper.is_none() {
        return Err(Error::NotRunning(format!(
            "no running box named '{name}' and no kept box by that name"
        )));
    }
    match kept_upper.or(scratch_upper) {
        Some(u) => {
            let mut out: Vec<(char, String)> = Vec::new();
            walk_diff(&u, &u, 0, &mut out);
            // kern's own setup writes into the same upper the box does; those lines are not the box's
            // changes and drowned the ones that were.
            out = strip_scaffolding(out);
            out.sort_by(|a, b| a.1.cmp(&b.1));
            if out.len() >= DIFF_MAX_ENTRIES {
                eprintln!("kern: diff truncated at {DIFF_MAX_ENTRIES} entries (upper too large)");
            }
            if json {
                // `json_str` and NOT `ui::scrub` here. The two do different jobs and the JSON path
                // needs the first: scrub DELETES control bytes, which silently changes a filename,
                // and a consumer that then tries to `rm` what it was told exists would miss. Escaping
                // preserves the byte and still cannot forge a line or reach a terminal, because the
                // whole value stays inside one JSON string.
                let buf = kern_common::json_array(&out, |(kind, path)| {
                    format!(
                        "{{\"change\":{},\"path\":{}}}",
                        json_str(&kind.to_string()),
                        json_str(path),
                    )
                });
                println!("{buf}");
                return Ok(());
            }
            for (kind, path) in &out {
                // The path comes from an UNTRUSTED box-controlled filename: scrub control bytes so a
                // name like `a\nD /etc/shadow` or an ANSI-escape filename can't forge a diff line or
                // inject into the operator's terminal (same guard `ps --format` applies).
                println!("{kind} {}", crate::ui::scrub(path));
            }
            Ok(())
        }
        None => Err(Error::Sandbox(format!(
            "box '{box_name}' has no overlay to diff - it uses --bind-rootfs, which writes \
             straight through to the source directory (nothing is layered to compare)"
        ))),
    }
}

/// `kern history [-n N]` - the most recent boxes, reconstructed from their captured log files
/// (`<name>-<pid>.log`): name, pid, when it last ran, and whether it's still running. A lightweight
/// audit trail without a separate history store (prune/gc remove these, so it's "recent", not "all").
pub fn history(count: usize) -> Result<(), Error> {
    let dir = registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let mut rows: Vec<(String, i32, u64, bool)> = Vec::new(); // name, pid, mtime, alive
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            let Some(stem) = fname.strip_suffix(".log") else {
                continue;
            };
            // `<name>-<pid>` - split on the LAST '-' (a name may contain '-').
            let Some((name, pid_s)) = stem.rsplit_once('-') else {
                continue;
            };
            let Ok(pid) = pid_s.parse::<i32>() else {
                continue;
            };
            let mtime = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            rows.push((name.to_string(), pid, mtime, alive));
        }
    }
    rows.sort_by_key(|b| std::cmp::Reverse(b.2)); // newest first
    rows.truncate(count);
    let p = crate::ui::Palette::detect();
    if rows.is_empty() {
        println!("{}no box history yet{}", p.d, p.z);
        return Ok(());
    }
    let now = registry::now_unix();
    // MEASURED, and here the fixed 20 failed the other way: this cell TRUNCATES, so it printed two
    // different boxes as one string. A compose stack with services `worker` and `workqueue` gave two
    // rows both reading `sdktest-cd95af93-wo…`, different pids, no way to tell which log is which.
    // The column is measured now and truncates only past the shared ceiling.
    let nw = crate::ui::name_col_width(rows.iter().map(|(n, _, _, _)| n.as_str()), 20, 30);
    println!(
        "{d}{:<nw$} {:>8} {:>12}  STATUS{z}",
        "NAME",
        "PID",
        "WHEN",
        d = p.d,
        z = p.z
    );
    for (name, pid, mtime, alive) in &rows {
        let status = if *alive {
            format!("{}running{}", p.g, p.z)
        } else {
            format!("{}exited{}", p.d, p.z)
        };
        println!(
            "{b}{c}{:<nw$}{z} {:>8} {:>12}  {status}",
            truncate(name, nw),
            pid,
            fmt_age(now.saturating_sub(*mtime)),
            b = p.b,
            c = p.c,
            z = p.z
        );
    }
    Ok(())
}

/// Resolve a box's newest log AND open it, retrying while a rotation is in flight.
///
/// ONE OPERATION, NOT TWO, because a rotation invalidates both halves and doing them separately just
/// moves the window. `rotate` renames `<key>.log` to `<key>.log.1` and opens a fresh one: a reader
/// that looks between those calls finds no name, and a reader that resolved the name a moment earlier
/// opens a descriptor to a file that has just been renamed out from under it. Both were measured, one
/// after the other: fixing the first alone turned "box writes no log" into "opening log: No such
/// file", which is the same defect one step further along.
///
/// MEASURED by the concurrency battery from an audit pass, at roughly 1 read in 6000 against a box
/// rotating every few KB - rare enough never to appear by hand, common enough to be someone's first
/// impression of `kern logs` on a busy box. Three tries 20 ms apart cover a window that is two
/// syscalls wide; a box that genuinely has no log finds nothing on every try, so the wait is spent
/// only on a path that is already an error.
fn open_newest_log(name: &str) -> Result<Option<(std::path::PathBuf, std::fs::File)>, Error> {
    for attempt in 0..3 {
        if let Some(p) = newest_log(name)? {
            match std::fs::File::open(&p) {
                Ok(f) => return Ok(Some((p, f))),
                // Renamed between the resolve and the open: look again rather than report it missing.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempt < 2 => {}
                Err(e) => return Err(Error::Sandbox(format!("opening log: {e}"))),
            }
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    Ok(None)
}

/// `kern logs <name>` - print the captured stdout/stderr of the most recent box named `name`.
/// What [`log_head`] leaves for a follow: the open log, its path, the box's name, the stamper.
struct LogHead {
    f: std::fs::File,
    path: std::path::PathBuf,
    name: String,
    stamper: Option<crate::commands::boxlog::Stamper>,
}

/// Write what a box's newest log holds now to `w`, as `kern logs` shows it (`--tail`, timestamps,
/// a time window), and hand back what a follow continues from.
/// A box started with `--log-driver none` keeps no output, and saying so is Docker's answer for that
/// driver ("configured logging driver does not support reading"): an empty screen would read as a
/// box that printed nothing.
fn refuse_unlogged(name: &str) -> Result<(), Error> {
    match registry::find_ref(name) {
        Some(b) if b.log_driver == "none" => Err(Error::Sandbox(format!(
            "box '{}' was started with --log-driver none: its output is not kept, so there is \
             nothing to read",
            b.name
        ))),
        _ => Ok(()),
    }
}

fn log_head<W: std::io::Write>(
    name: &str,
    tail: Option<usize>,
    follow: bool,
    timestamps: bool,
    window: (Option<u64>, Option<u64>),
    frames: bool,
    w: &mut W,
) -> Result<LogHead, Error> {
    use std::io::{Read, Seek, SeekFrom};
    refuse_unlogged(name)?;
    // Accept a `kern ps` PID too: a live box's pid resolves to its name; a name (incl. a stopped box,
    // whose log file persists) is used as-is.
    let by_pid = registry::find_ref(name).map(|i| i.name);
    let name = by_pid.as_deref().unwrap_or(name);
    let Some((path, mut f)) = open_newest_log(name)? else {
        // 🔴 A LIVE BOX WITH NO LOG IS NOT A MISSING BOX, and the two used to share one sentence whose
        // hint sent the reader in a circle: `no logs for box 'x'` plus "run `kern ps` to see running
        // boxes", for a box that `kern ps` was ALREADY showing. MEASURED through the SDK, which is
        // where this is normal rather than exotic: every `run_code` box is a FOREGROUND box, its
        // output belongs to the caller that is reading it, and no log file is written at all. Only
        // `-d` detaches the output into a file, which is why the same command works there.
        let live = registry::find_ref(name).is_some();
        return Err(Error::NotRunning(if live {
            format!(
                "box '{name}' is running and writes no log: its output goes to whoever started it \
                 (a foreground box, which is what an SDK call and a plain `kern box` both are). Only \
                 `kern box -d` detaches the output into a log this verb can read"
            )
        } else {
            format!("no logs for box '{name}'")
        }));
    };
    // `--tail N` seeks a bounded window near EOF (cost O(bytes shown), not O(file size)); a plain
    // `logs` reads the whole file. Either way `f` ends positioned at EOF so `--follow` streams NEW
    // appends without re-printing. (Narrow race on `--tail N -f` of an actively-appending box: a line
    // written between the tail read and the re-seek to EOF can be skipped - acceptable for a log tail.)
    let shown: Vec<u8> = match tail {
        Some(n) => {
            let t = tail_file(&mut f, n)?;
            if follow {
                f.seek(SeekFrom::End(0))
                    .map_err(|e| Error::Sandbox(format!("seeking log: {e}")))?;
            }
            t
        }
        None => {
            let mut content = Vec::new();
            f.read_to_end(&mut content)
                .map_err(|e| Error::Sandbox(format!("reading log: {e}")))?;
            content
        }
    };
    // WHERE `shown` STARTS IN THE FILE, which is what turns a byte into a time. `--tail` hands back a
    // window near the end, a plain `logs` the whole file, and both are the file's LAST `shown.len()`
    // bytes at this instant - so one subtraction covers both and neither needs `tail_file` to grow a
    // second return value.
    let file_len = f.metadata().map(|m| m.len()).unwrap_or(shown.len() as u64);
    // A WINDOW NEEDS THE SAME MACHINERY AS THE COLUMN and not the column itself: `--since` is a
    // filter on the recorded time, `-t` prints it, and Docker's `--since` does not imply
    // `--timestamps`. One Stamper serves both, told which of the two jobs it has.
    let windowed = window.0.is_some() || window.1.is_some();
    let mut stamper = (timestamps || windowed || frames).then(|| {
        crate::commands::boxlog::Stamper::new(&path, file_len.saturating_sub(shown.len() as u64))
            .with_window(window.0, window.1, timestamps)
            .with_frames(frames)
    });
    {
        // BUFFERED BY [`logs`], BECAUSE `stdout()` IS A LineWriter. It flushes on every newline, and the stamped
        // path writes two pieces per line (the time column, then the line), so a large log paid two
        // syscalls per line instead of one per 8 KiB. MEASURED on a 48 MB log: 63.8 ms stamped
        // against 31.6 ms plain, the whole difference. A write larger than the buffer still goes
        // straight through, so the unstamped path is untouched.
        let map = |e| Error::Sandbox(format!("writing log: {e}"));
        match stamper.as_mut() {
            Some(s) => {
                s.push(w, &shown).map_err(map)?;
                // Not following: whatever is held back is a last line with no newline, and that is
                // all it will ever be. Under `--follow` it stays held, because its newline may yet
                // arrive in the next chunk.
                if !follow {
                    s.flush(w).map_err(map)?;
                }
            }
            None => w.write_all(&shown).map_err(map)?,
        }
        w.flush().map_err(map)?;
    }
    Ok(LogHead {
        f,
        path,
        name: name.to_string(),
        stamper,
    })
}

/// A box's log as it is now, written to `w`: `kern logs` without `-f`, for a caller that prefixes
/// the lines (`compose logs`).
pub(crate) fn logs_to<W: std::io::Write>(
    name: &str,
    tail: Option<usize>,
    timestamps: bool,
    window: (Option<u64>, Option<u64>),
    w: &mut W,
) -> Result<(), Error> {
    log_head(name, tail, false, timestamps, window, false, w).map(|_| ())
}

/// `frames` (`logs --frames`, internal): Docker's multiplexed frames, stdout and stderr apart where
/// the box was started with `--log-streams`. The Docker API server's reader; see `boxlog::Stamper`.
pub fn logs(
    name: &str,
    tail: Option<usize>,
    follow: bool,
    timestamps: bool,
    window: (Option<u64>, Option<u64>),
    frames: bool,
) -> Result<(), Error> {
    use std::io::Write;
    let LogHead {
        f,
        path,
        name,
        mut stamper,
    } = {
        let out = std::io::stdout();
        let mut w = std::io::BufWriter::new(out.lock());
        let head = log_head(name, tail, follow, timestamps, window, frames, &mut w)?;
        w.flush()
            .map_err(|e| Error::Sandbox(format!("writing log: {e}")))?;
        head
    };
    let name = name.as_str();
    if follow {
        // Only a live box appends more output; a stopped box's log is already complete.
        if let Some(bx) = registry::find_ref(name) {
            return follow_log(f, &path, name, bx.pid, stamper);
        }
        // A stopped box under `-f`: nothing more is coming, so release the held fragment now.
        if let Some(s) = stamper.as_mut() {
            let out = std::io::stdout();
            let mut lock = out.lock();
            s.flush(&mut lock)
                .map_err(|e| Error::Sandbox(format!("writing log: {e}")))?;
            let _ = lock.flush();
        }
    }
    Ok(())
}

/// `kern attach <name>` - stream a running (detached) box's output live until it exits or you press
/// Ctrl-C (which **detaches** without stopping the box; a detached box has no stdin, so this is
/// output-only). Prints the log so far, then follows appends by polling the file, and stops when the
/// box leaves the registry.
pub fn attach(name: &str) -> Result<(), Error> {
    refuse_unlogged(name)?;
    let bx = registry::find_ref(name);
    let Some(bx) = bx else {
        return Err(Error::NotRunning(format!("no running box named '{name}'")));
    };
    let Some(path) = newest_log(name)? else {
        return Err(Error::NotRunning(format!(
            "box '{name}' has no log to attach to (only detached boxes log to a file)"
        )));
    };
    eprintln!(
        "kern: attached to '{name}' (pid {}) - Ctrl-C detaches (box keeps running)",
        bx.pid
    );
    let f = std::fs::File::open(&path).map_err(|e| Error::Sandbox(format!("opening log: {e}")))?;
    // Print the log so far (from offset 0), then poll appends until the box exits (shared with `logs -f`).
    follow_log(f, &path, name, bx.pid, None)?;
    eprintln!("kern: box '{name}' exited");
    Ok(())
}

/// `kern top` - live, auto-refreshing view of running boxes (name, pid, uptime, mem, cpu%).
/// Reads the registry + each box's cgroup every second; exit with Ctrl-C.
/// `kern top` - an interactive task-manager TUI (tabs, live refresh, keyboard nav) when stdout is
/// a terminal; a one-shot table when piped. The implementation lives in [`crate::tui`].
pub fn top() -> Result<(), Error> {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        crate::tui::run()
    } else {
        crate::tui::snapshot()
    }
}

/// Set while a verb whose stdout belongs to a different answer stops a box: `restart`, whose stdout is
/// the restarted names only, as Docker's. The narration then goes to stderr. One process, one verb at
/// a time, so `Relaxed` is all the ordering the flag needs.
static STOP_NARRATES_TO_STDERR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The "stopped" line, on stdout unless [`STOP_NARRATES_TO_STDERR`] says otherwise.
fn narrate_stop(line: &str) {
    if STOP_NARRATES_TO_STDERR.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("{line}");
    } else {
        println!("{line}");
    }
}

pub fn stop(names: &[String], all: bool) -> Result<(), Error> {
    stop_with_grace(names, all, None, crate::commands::DeafInit::Kill)
}

/// [`stop`], with the per-invocation grace `docker compose down -t <secs>` sets.
///
/// `None` keeps each box's OWN recorded grace, which is what every other caller wants: the value was
/// chosen when the box was started (`--stop-timeout`, default 10 s, Docker's default) and a service
/// that asked for 60 s to flush should get 60 s. `Some(n)` REPLACES it for this teardown, which is
/// what the flag means - Sentry's `install.sh` runs `docker compose down -t 30 --remove-orphans`, and
/// a flag accepted and not honoured is the defect this codebase refuses to ship.
///
/// `Some(0)` IS A REAL VALUE, not "unset": Docker reads `-t 0` as "do not wait, kill now", and the
/// `> 0` tests below are what implement that, unchanged.
pub fn stop_with_grace(
    names: &[String],
    all: bool,
    grace: Option<u64>,
    deaf: crate::commands::DeafInit,
) -> Result<(), Error> {
    let dir = registry::dir().map_err(|e| Error::Sandbox(format!("registry: {e}")))?;
    let running = registry::list();
    let mut targets: Vec<_> = if all {
        running.clone()
    } else {
        boxes_matching_refs(running.clone(), names)
    };
    // A persistent (`--restart always`) box is supervised by systemd and may be momentarily down
    // between restarts - not in the registry, but its unit still exists and would resurrect it at
    // reboot. Collect those so stop reliably removes them too: for explicit names, the requested
    // ones; for `--all`, every `kern-*.service` in the user unit dir not already a live target.
    let managed_only: Vec<String> = if all {
        user_systemd_dir()
            .ok()
            .and_then(|d| std::fs::read_dir(d).ok())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter_map(|f| {
                Some(
                    f.strip_prefix("kern-")?
                        .strip_suffix(".service")?
                        .to_string(),
                )
            })
            // The name only makes a file a CANDIDATE. Ownership is read from the file itself, or
            // `stop --all` removes units it never wrote - see `is_kern_managed_unit`.
            .filter(|n| managed_unit_path(n).is_some_and(|p| is_kern_managed_unit(&p)))
            .filter(|n| !targets.iter().any(|b| &b.name == n))
            .collect()
    } else {
        names
            .iter()
            .filter(|n| !targets.iter().any(|b| &b.name == *n))
            .filter(|n| managed_unit_path(n).is_some_and(|p| is_kern_managed_unit(&p)))
            .cloned()
            .collect()
    };
    // A NAME WITH NO RECORD HERE CAN STILL BE A RUNNING BOX: `kern ps` names such boxes from their
    // cgroups and processes, and they used to stay unstoppable through kern. MEASURED in an external
    // test: after the registry was wiped, `ps` named the box and its supervisor pid while
    // `kern stop <name>` answered "no running box named". Only for a name that matches nothing
    // recorded, so a recorded box is never stopped this way.
    let mut stopped_unrecorded: Vec<String> = Vec::new();
    if !all {
        let live_names = live_name_set(&running);
        for n in names {
            let recorded = targets.iter().any(|b| ref_matches(b, n, &live_names));
            if recorded || managed_only.contains(n) {
                continue;
            }
            if let Some(msg) = stop_unrecorded(n, grace.unwrap_or(DEFAULT_UNRECORDED_GRACE_S))? {
                println!("{msg}");
                stopped_unrecorded.push(n.clone());
            }
        }
    }
    if targets.is_empty() && managed_only.is_empty() && !stopped_unrecorded.is_empty() {
        let rest: Vec<&String> = names
            .iter()
            .filter(|n| !stopped_unrecorded.contains(n))
            .collect();
        if rest.is_empty() {
            return Ok(());
        }
        return Err(Error::NotRunning(format!(
            "no running box named {}",
            rest.iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    if targets.is_empty() && managed_only.is_empty() {
        return Err(Error::NotRunning(if all {
            "no running boxes to stop".to_string()
        } else {
            let listed = names
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("no running box named {listed}")
        }));
    }
    // A target that could not actually be stopped (orphan cgroup not reaped, a SIGKILL that did not
    // land in time) or a named ref that matched nothing is a real failure, not a note on stderr:
    // collect the reasons and return them as ONE `Err` at the end so the command exits NON-ZERO and
    // `kern top` (which reuses this fn with stderr muted) can show the reason. Same rule and shape as
    // `pause`, kept identical so the partial-failure convention is not re-derived per command.
    let mut failures: Vec<String> = Vec::new();
    // Wait on the SHORTEST grace first. Phase 1 signals every box at once, so this reorders no
    // shutdown - what it reorders is which confirmation kern waits for first, and that is what
    // decides when each box is SIGKILLed. The loop is sequential, so a member whose turn comes after
    // a longer-lived one has already spent its own grace and is killed at once: MEASURED on a
    // four-service stack asking 1, 2, 4 and 6 s, all hanging in their handler, the 1 s service was
    // killed at 6201 ms and the 4 s one at 6201. Ascending, each waits only the difference from the
    // one before it, so every member is killed on its own grace and the stack still finishes in
    // max(grace). `sort_by_key` is stable, so boxes asking the same grace keep the caller's order.
    targets.sort_by_key(|b| grace.unwrap_or(b.stop_grace));
    // PHASE 1: send every box its stop signal BEFORE waiting on any of them, and share ONE deadline.
    // Stopping serially made each box burn its own full grace in turn, so an N-service stack of
    // workloads that ignore SIGTERM took N x grace (measured: 20 s for two `sh -c sleep` services).
    // Docker stops a project in parallel; so do we. The per-box wait below then sees processes that
    // have already been signalled and, for the ones that exit, returns at once.
    // When the signal went out. Each box's own grace is measured from here, so a member that asked
    // for less is not held to the longest grace in the stack - see `remaining_grace_ms`.
    // THE STOP MARKER GOES DOWN BEFORE THE FIRST SIGNAL, so an owner that sees its box die already
    // knows a stop ended it and writes ONE history line saying so. See `registry::mark_stopping`.
    // A COMPOSE STOP WAITS FOR A BOX STILL BEING SET UP TO RUN ITS WORKLOAD, before any signal and
    // before the reapers are held, so everything below sees its real init. See `wait_for_workload`.
    if deaf == crate::commands::DeafInit::WaitGrace {
        for b in targets.iter_mut() {
            let budget = std::time::Duration::from_secs(grace.unwrap_or(b.stop_grace));
            if let Some(fresh) = crate::commands::wait_for_workload(&b.name, b.pid, budget) {
                *b = fresh;
            }
        }
    }
    for b in &targets {
        registry::mark_stopping(&b.name, b.pid);
    }
    let signalled_at = std::time::Instant::now();
    // Hold every target's reaper BEFORE a single signal goes out, so each box's exit status is still
    // readable when its wait returns. Kept alive to the end of the teardown loop and released by
    // the `drop` after it; a box with no grace has nothing to observe and holds nothing. See
    // `ReaperHold`.
    let holds: Vec<ReaperHold> = targets
        .iter()
        .map(|b| {
            // Only where an interrupted `stop` is RECOVERABLE. A held reaper is resumed by `Drop`,
            // which a SIGKILL of this process skips, and a box with a dedicated cgroup survives that:
            // its supervisor is gone, so `kern ps` shows it ORPHANED and the next `kern stop` reaps
            // the whole cgroup (verified: `stopped 'victim2' (was orphaned; reaped via cgroup.kill)`,
            // no stopped process and no stray left). A box with NO dedicated cgroup - `cgroup` is
            // empty exactly there - has no such handle: it would vanish from `ps` with its runner
            // stopped for good, where before this hold existed the runner simply died and the init
            // reparented and reaped itself. An exit code is not worth turning a self-healing case
            // into a leak, so those boxes keep the unguarded read.
            if grace.unwrap_or(b.stop_grace) > 0 && !b.orphaned && !b.cgroup.is_empty() {
                ReaperHold::new(b.pid, b.pid1_recorded)
            } else {
                ReaperHold(None)
            }
        })
        .collect();
    // The supervisors whose workload this stop saw exit: waited for once their reapers are released.
    let mut finished: Vec<(i32, u64)> = Vec::new();
    for b in &targets {
        if grace.unwrap_or(b.stop_grace) > 0 {
            let sig = if b.stop_signal > 0 {
                b.stop_signal
            } else {
                libc::SIGTERM
            };
            // Through `live_pid1`: the recorded number is only a victim we can name while it is still
            // the init we registered. Between an init exiting and its supervisor unregistering, that
            // pid can already belong to someone else, and `stop` would send them SIGTERM.
            if let Some(pid1) = b.live_pid1() {
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
                unsafe { signal_box(fd, pid1, sig) };
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                }
            }
            // The group carries the signal to the box's OTHER processes, not just its init: they
            // inherit the supervisor's process group, so a shell blocked in `sleep` wakes now
            // instead of when its child happens to finish. MEASURED: dropping this turned a 3 ms
            // stop into 65 ms for exactly that shape of workload. The box's own runner is in that
            // group too and would die here - which is why `stop` holds it first, see `ReaperHold`.
            //
            // ⛔ NOT FOR A COMPOSE TEARDOWN, which signals the init alone as Docker does: neither
            // the group nor the supervisor hears it. MEASURED against Docker on
            // `sh -c 'sleep 3; date > /out/done'` stopped at 1 s: Docker's `down` took 2.2 s and the
            // file was written 1.95 s in, when the `sleep` finished, because the shell (PID 1, deaf)
            // never heard the signal and its child never received one; kern's group signal killed
            // the `sleep` at once and the script ran its next command at stop time.
            //
            // ⛔ A COMPOSE STOP DOES NOT SIGNAL THE SUPERVISOR EITHER. MEASURED on the desktop, a GPU
            // service stopped by `--abort-on-container-exit` while it started exited 143 in 4 runs
            // of 60 with the supervisor signalled, and 0 of 120 with only the init signalled. The
            // supervisor is ended once the workload has (below), so a restart policy cannot bring
            // the service back.
            if b.pid > 1 && deaf == crate::commands::DeafInit::Kill {
                unsafe { libc::kill(-b.pid, sig) };
            }
        }
    }

    for b in &targets {
        // ORPHANED box: its supervisor is already dead (that is what makes it orphaned), so the
        // pid-based kill below has nothing to signal - the box's PID 1 and its `-p` forwarder are
        // reachable ONLY through the recorded cgroup. `reap_orphan` SIGKILLs that whole cgroup at once
        // (`cgroup.kill`), which frees the host port the forwarder was holding, and drops the record.
        // Without this branch `kern stop <name>` answered "no running box" while the port stayed bound.
        if b.orphaned {
            let reaped = registry::reap_orphan(b);
            registry::set_box_exit(b.pid, b.starttime, 137, &b.name, &b.pod, &b.command);
            crate::history::record_stopped(b, 137);
            registry::clear_health(&b.name, b.pid);
            // The environment sidecar has the same lifetime as the health one: cleared together so a
            // runtime dir cannot accumulate one and not the other.
            registry::clear_box_env(&b.name, b.pid);
            registry::clear_box_shm(&b.name);
            cleanup_box_scratch(&b.rootfs);
            if reaped {
                println!(
                    "stopped '{}' (was orphaned; reaped via cgroup.kill)",
                    b.name
                );
            } else {
                failures.push(format!(
                    "'{}' was orphaned but its cgroup could not be reaped (already gone?)",
                    b.name
                ));
            }
            continue;
        }
        // A persistent box: tell systemd to stop AND disable the unit (so it neither restarts now
        // nor comes back at reboot), then remove it. Killing the process instead would just trip
        // systemd's `Restart=always`. Otherwise kill the box's PID-namespace init directly - see
        // `kill_box`; a bare `kill(-pid)` reaches only a detached, `setsid`-ed supervisor's group,
        // never a foreground box whose init isn't in that group.
        // Capture the box's exact direct-path cgroup dir NOW, while pid1 is still alive and a member of
        // it (`/proc/<pid1>/cgroup`). After the SIGKILL below the pid1 lingers as a zombie, so the general
        // orphan-sweep would skip the dir until it's reaped; we `rmdir` the (now-empty) dir ourselves right
        // after. No-op for a systemd-scope box (not a `kern-box-*` leaf → `None`). See `box_cgroup_dir`.
        // Also `live_pid1`: this dir is read from `/proc/<pid1>/cgroup` and then `rmdir`ed, so a
        // recycled pid would have us resolve, and delete, a cgroup that is not the box's.
        let box_cgroup = b.live_pid1().and_then(kern_isolation::box_cgroup_dir);
        // Recovery path for a box left FROZEN by a `commit` that died past its signal trap (SIGKILL / OOM
        // / panic=abort): thaw it before killing. SIGKILL is honoured on a frozen cgroup-v2 task anyway,
        // but thawing first guarantees prompt delivery and means a stuck-frozen box is never unrecoverable
        // without the user knowing about `cgroup.freeze`. Best-effort; a non-frozen box is unaffected.
        if let Some(cg) = &box_cgroup {
            let _ = std::fs::write(cg.join("cgroup.freeze"), "0");
        }
        let outcome = if stop_managed_unit(&b.name) {
            // systemd owns the lifecycle and has torn the unit down: gone, but its exit code went to
            // the journal, not to us, so it records like any teardown we did not observe.
            Teardown::Gone(None)
        } else if b.pid1_recorded > 0 && b.live_pid1().is_none() {
            // ⛔ THE WORKLOAD IS ALREADY GONE: phase 1's signal ended it before this loop reached
            // the box. With no reaper hold (a box without a dedicated cgroup has none) the
            // supervisor reaps its init at once, so there is no init left to poll, and the graceful
            // call below, handed pid1 = 0, slept the whole remaining grace on a box that had exited.
            // MEASURED on WSL2 as an unprivileged user without delegation: `down` of a stack whose
            // service traps SIGTERM beside a `sleep` took 10.3-11.5 s in 5 runs of 12 and 0.3 s in the
            // others, depending on whether the trap had fired before the loop got there. The
            // supervisor is let finish (its record carries the real code), then its group is swept
            // with no grace, and the code it recorded is the one reported.
            // A RUN THAT ALREADY RECORDED ITS CODE is not waited on: a supervisor in its restart
            // backoff does not finish, it restarts (MEASURED: an `on-failure:3` service stopped in
            // its one-second backoff ran a second time while this waited two seconds for it).
            let recorded = registry::box_exit(b.pid, b.starttime);
            if recorded.is_none() {
                crate::commands::wait_supervisor_done(b.pid, b.starttime);
            }
            match kill_box_graceful(
                b.pid,
                0,
                libc::SIGKILL,
                0,
                crate::commands::GraceSignal::AlreadySent,
                deaf,
            ) {
                Teardown::Gone(None) => {
                    Teardown::Gone(recorded.or_else(|| registry::box_exit(b.pid, b.starttime)))
                }
                other => other,
            }
        } else {
            // Honour the shutdown contract the box was STARTED with: the registry carries it, so a
            // later `kern stop` (a different process) sends the same signal and waits the same grace.
            // An older entry (0/0) keeps the historical immediate SIGKILL.
            kill_box_graceful(
                b.pid,
                // The gate, not the raw number: this signals the pid. `None` (never recorded, or no
                // longer the init we registered) passes 0, which the callee already reads as "no init
                // to signal" and answers by tearing down through the supervisor instead.
                b.live_pid1().unwrap_or(0),
                if b.stop_signal > 0 {
                    b.stop_signal
                } else {
                    libc::SIGTERM
                },
                // What is LEFT of this box's own grace, counted from the phase-1 signal.
                remaining_grace_ms(grace.unwrap_or(b.stop_grace), signalled_at.elapsed()),
                // PHASE 1 ALREADY SENT IT. Sending it again re-enters the workload's shutdown
                // handler: measured at 4006 ms for a 2 s handler against 2006 ms without the second
                // send, with the box's own log showing the trap entered twice. Phase 1 signals
                // exactly the boxes with `stop_grace > 0`, and for the rest `remaining_grace_ms` is
                // 0 and the graceful phase is skipped, so this is true in both arms.
                crate::commands::GraceSignal::AlreadySent,
                deaf,
            )
        };
        if outcome.confirmed() {
            match deaf {
                crate::commands::DeafInit::Kill => finished.push((b.pid, b.starttime)),
                // The workload is gone and the supervisor was never signalled: end it now, before
                // its restart policy (whose first backoff is a second) can start the next run. The
                // teardown below is the one a SIGKILLed supervisor already gets.
                crate::commands::DeafInit::WaitGrace => {
                    if b.pid > 1 && registry::is_alive(b.pid, b.starttime) {
                        unsafe { libc::kill(-b.pid, libc::SIGKILL) };
                    }
                }
            }
        }
        // A `stop` signals the supervisor's group, so the supervisor never records its own exit code.
        // We record it here - BEFORE removing the instance file - so `kern wait` on a stopped box
        // answers like Docker instead of "no exit code recorded". The code is the box's REAL one when
        // it shut itself down inside the grace: a workload that traps the signal and exits 0 has to
        // read as `exited (0)`, not as the SIGKILL we never sent it. See `Teardown`.
        registry::set_box_exit(
            b.pid,
            b.starttime,
            outcome.exit_code(),
            &b.name,
            &b.pod,
            &b.command,
        );
        crate::history::record_stopped(b, outcome.exit_code());
        // AND THE KEPT RECORD, FOR THE SAME REASON, in the same place: the sentence above says the
        // supervisor never records its own code under a `stop`, and the kept record is the one that
        // OUTLIVES this runtime dir. The supervisor's own call covers a box that ended by itself;
        // this covers the one `stop` ended, which otherwise said "never ran" for ever while the
        // transient record said `exit 137` (measured, both rows in one `ps -a`).
        if let Some(kd) = crate::keepbox::dir_of(&b.name) {
            if kd.is_dir() {
                crate::keepbox::set_exit(&kd, outcome.exit_code());
            }
        }
        let _ = std::fs::remove_file(dir.join(format!("{}-{}", b.name, b.pid)));
        registry::clear_health(&b.name, b.pid);
        // The environment sidecar has the same lifetime as the health one: cleared together so a
        // runtime dir cannot accumulate one and not the other.
        registry::clear_box_env(&b.name, b.pid); // a SIGKILL skips the supervisor's own cleanup
        registry::clear_box_shm(&b.name);
        cleanup_box_scratch(&b.rootfs);
        if outcome.confirmed() {
            // Eagerly rmdir the box's now-empty cgroup dir (captured above) - the SIGKILL skipped the
            // supervisor's RAII guard, so it would otherwise linger until `gc`/the next box start. rmdir is
            // empty-only, so a (vanishingly unlikely) reused-pid live box is safe. Covers `compose down`
            // too - it tears the stack down via this same `stop`.
            //
            // EXCEPT a `.scope`: on the systemd-scope path the box's cgroup IS a transient unit, and
            // that dir belongs to systemd's bookkeeping, not to ours. `--collect` removes the unit
            // (and its cgroup) when its last process exits, so racing it here would win nothing and
            // could leave the manager tearing down a cgroup that is already gone.
            if let Some(cg) = &box_cgroup {
                let is_unit = cg
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".scope"));
                if !is_unit {
                    let _ = std::fs::remove_dir(cg);
                }
            }
            narrate_stop(&format!("stopped '{}' (pid {})", b.name, b.pid));
        } else {
            // Don't report success while alive: the SIGKILL went out but the box wasn't confirmed
            // gone within the grace window. Surface it honestly instead of printing `stopped`.
            failures.push(format!(
                "sent SIGKILL to '{}' (pid {}) but it did not exit in time",
                b.name, b.pid
            ));
        }
    }
    // The supervisor of a workload that exited on its signal is still tearing down, and writes the
    // box's exit record as its last act: wait for it, so nothing the caller does next races that
    // write. AFTER the reapers are released, because a held supervisor cannot finish (MEASURED: the
    // wait placed inside the loop always ran to its 2 s bound).
    drop(holds);
    for (pid, starttime) in finished {
        crate::commands::wait_supervisor_done(pid, starttime);
    }
    for n in &managed_only {
        stop_managed_unit(n);
        narrate_stop(&format!("stopped '{n}' (systemd-managed)"));
    }
    // Stopping a pod means removing its "root" too (like Docker Desktop's stop-the-project): once every
    // member of a pod is stopped, tear the pod down - its holder process, network namespace and shared
    // hosts/resolv files. This fires whether the pod was named directly (`kern stop <pod>`), swept by
    // `--all`, or emptied by stopping its last member - matching `compose down`'s cleanup.
    let stopped_pods: std::collections::BTreeSet<&str> = targets
        .iter()
        .map(|b| b.pod.as_str())
        .filter(|p| !p.is_empty())
        .collect();
    // A pod survives iff some running member's pid ISN'T among the stopped targets. Compute the set of
    // surviving pods in ONE pass with a pid HashSet - the naive `for pod { running.any(!targets.any) }`
    // is O(pods·running·targets) (≈O(N³) on `stop --all` with many boxes); this is O(N).
    let target_pids: std::collections::HashSet<i32> = targets.iter().map(|b| b.pid).collect();
    let survivors: std::collections::HashSet<&str> = running
        .iter()
        .filter(|b| !b.pod.is_empty() && !target_pids.contains(&b.pid))
        .map(|b| b.pod.as_str())
        .collect();
    // A pod the operator CREATED BY NAME is not torn down merely because its last member stopped.
    // Before this, the same end state had two outcomes depending on how it was reached: a pod whose
    // last member exited on its own survived, and the same pod whose last member was STOPPED did
    // not. `kern pod create` is a verb that makes a thing, and `kern pod rm` is the verb that
    // removes it; a `stop` that also removed it made the second verb optional by accident.
    //
    // THREE WAYS STILL TEAR ONE DOWN, and they are the three where removal is what was asked for:
    // `--all` sweeps everything by definition; naming the pod itself (`kern stop <pod>`) is a
    // request about the pod and not about a box inside it; and a pod DERIVED from a stack has no
    // explicit marker, so `compose down` and a stack emptied by `stop` clean up exactly as before.
    for pod in stopped_pods {
        if survivors.contains(pod) {
            continue;
        }
        let named_directly = names.iter().any(|n| n == pod);
        if !all && !named_directly && crate::pod::is_explicit(pod) {
            continue;
        }
        let (existed, _) = crate::pod::teardown(pod);
        if existed {
            println!("removed pod '{pod}'");
        }
    }
    // Don't silently ignore refs that matched no running box (and no managed unit). A ref matched a
    // target by NAME, by its PID, or by its POD name (same rule as the selection above), so check all
    // three - else `kern stop <pid|pod>` acts AND then wrongly warns the ref "isn't a box".
    if !all {
        let live_names = live_name_set(&running);
        for n in names {
            let matched = targets.iter().any(|b| ref_matches(b, n, &live_names));
            if !matched && !managed_only.contains(n) && !stopped_unrecorded.contains(n) {
                failures.push(format!("no running box '{n}'"));
            }
        }
    }
    if !failures.is_empty() {
        return Err(Error::Sandbox(format!(
            "could not stop: {}",
            failures.join("; ")
        )));
    }
    Ok(())
}

/// The grace an unrecorded box gets: its own `--stop-timeout` was in the record that is gone, so
/// Docker's default, 10 s.
const DEFAULT_UNRECORDED_GRACE_S: u64 = 10;

/// Stop the running box called `name` that has NO record here, found the way `kern ps` finds it
/// (its `kern-box-<name>-<pid>` cgroup, else its `kern box <name>` supervisor in `/proc`).
///
/// `Ok(None)` when there is none, an error when two live boxes carry the name (which one is meant
/// cannot be told), and the line to print when one was stopped. Docker's stop: `SIGTERM` to the
/// box's init, `grace_s` to exit, then `SIGKILL`, which takes its whole pid namespace; then the
/// supervisor, if it is still there. Every signal goes to a pid whose start time is the one read
/// when it was found, so a recycled pid is never signalled.
fn stop_unrecorded(name: &str, grace_s: u64) -> Result<Option<String>, Error> {
    let recorded: std::collections::HashSet<String> =
        registry::list().into_iter().map(|i| i.name).collect();
    let pick = |found: Vec<(String, u32)>| -> Vec<u32> {
        found
            .into_iter()
            .filter(|(tag, _)| tag == name && !recorded.contains(tag))
            .map(|(_, pid)| pid)
            .collect()
    };
    let mut sups = pick(kern_isolation::live_box_cgroups());
    if sups.is_empty() {
        sups = pick(kern_isolation::live_box_supervisors_via_proc());
    }
    sups.sort_unstable();
    sups.dedup();
    // ONLY A BOX OF THIS RUNTIME DIRECTORY. The cgroups and processes above are every box of this
    // user, and a box with this name may belong to another directory's world (a systemd unit, a
    // test, a script with its own XDG_RUNTIME_DIR); stopping it from here ended a box this directory
    // never started. Such a box is named, not stopped: it is stopped from its own directory.
    let (mine, elsewhere): (Vec<u32>, Vec<u32>) = sups
        .into_iter()
        .partition(|s| registry::same_runtime_dir_as(*s));
    if mine.is_empty() && !elsewhere.is_empty() {
        return Err(Error::Sandbox(format!(
            "no box named '{name}' runs from {dir}; one does from another runtime directory \
             (supervisor pid {}), and is left alone: stop it with the XDG_RUNTIME_DIR it was \
             started with",
            elsewhere
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            dir = crate::registry::instances_dir_for_display()
        )));
    }
    let sups = mine;
    let sup = match sups.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        many => {
            return Err(Error::Sandbox(format!(
                "two or more running boxes are called '{name}' and none has a record here \
                 (supervisor pids {}); stop one by pid with `kill`",
                many.iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    };
    let Ok(sup) = i32::try_from(sup) else {
        return Ok(None);
    };
    let sup_start = registry::proc_starttime(sup);
    if sup_start == 0 {
        return Ok(None); // gone between the scan and now
    }
    let init = registry::box_init_under(sup);
    let target = init.unwrap_or(sup);
    let target_start = registry::proc_starttime(target);
    let alive = |pid: i32, start: u64| start != 0 && registry::proc_starttime(pid) == start;
    let signal = |pid: i32, start: u64, sig: libc::c_int| {
        if alive(pid, start) {
            // SAFETY: a positive pid whose start time was just re-read, never 0 or -1.
            unsafe { libc::kill(pid, sig) };
        }
    };
    signal(target, target_start, libc::SIGTERM);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(grace_s);
    while alive(target, target_start) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    signal(target, target_start, libc::SIGKILL);
    let sup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while alive(sup, sup_start) && std::time::Instant::now() < sup_deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    signal(sup, sup_start, libc::SIGKILL);
    let dir = crate::registry::instances_dir_for_display();
    Ok(Some(format!(
        "stopped '{name}' (supervisor pid {sup}): it had no record in {dir}, and was found by its \
         cgroup and processes"
    )))
}

/// `kern pause <name>...` / `kern unpause <name>...` - freeze / thaw a running box via the cgroup v2
/// **freezer** (`cgroup.freeze`), which suspends every process in the box's cgroup atomically (no
/// signal races, and a paused box can't be woken by `SIGCONT` from inside). Needs the box to have a
/// dedicated cgroup (a `systemd --user` scope, the default when present); without one there's nothing
/// to freeze and we say so rather than pretend. `freeze=true` pauses, `false` resumes.
pub fn pause(names: &[String], all: bool, freeze: bool) -> Result<(), Error> {
    let verb = if freeze { "pause" } else { "unpause" };
    let running = registry::list();
    // Captured before `running` is consumed - the unmatched-ref report below needs the full live-name
    // set to apply the same NAME-wins rule as selection (a pod/pid ref must not be called "not a box").
    let live_names = live_name_set(&running);
    let targets: Vec<_> = if all {
        running
    } else {
        boxes_matching_refs(running, names)
    };
    if targets.is_empty() {
        return Err(Error::NotRunning(format!("no running box to {verb}")));
    }
    // A box that MATCHED but could not actually be (un)frozen - it has no dedicated cgroup (freeze is
    // a cgroup-v2 operation that needs a delegated scope), or the `cgroup.freeze` write errored - is a
    // real failure, not a success with a note on stderr. Collect the reasons (plus any named ref that
    // matched no live box) into ONE returned error so the command exits NON-ZERO (a scripted
    // `kern pause X && next` must not run `next` when the freeze never happened) AND the message is
    // self-contained: the `kern top` TUI reuses this fn with stdout/stderr muted, so a "see above"
    // pointer would dangle - the reason must travel IN the error, which the TUI shows in its overlay.
    // Successes still stream to stdout so an `--all` reports each box as it goes.
    let mut failures: Vec<String> = Vec::new();
    for b in &targets {
        match registry::box_cgroup(b.cgroup_pid()) {
            Some(cg) => {
                let path = cg.join("cgroup.freeze");
                match std::fs::write(&path, if freeze { "1" } else { "0" }) {
                    Ok(()) => println!("{}d '{}' (pid {})", verb, b.name, b.pid),
                    Err(e) => failures.push(format!("'{}': {e}", b.name)),
                }
            }
            None => failures.push(format!(
                "'{}' has no dedicated cgroup (freeze needs a systemd --user scope)",
                b.name
            )),
        }
    }
    if !all {
        for n in names {
            // Same NAME-or-PID-or-POD rule as `stop`: a `kern pause <pod>` froze every member, so the
            // pod ref matched - don't then wrongly report it as "no running box".
            if !targets.iter().any(|b| ref_matches(b, n, &live_names)) {
                failures.push(format!("no running box named '{n}'"));
            }
        }
    }
    if !failures.is_empty() {
        return Err(Error::Sandbox(format!(
            "could not {verb}: {}",
            failures.join("; ")
        )));
    }
    Ok(())
}

/// `kern start <name>...` - run a box created with `box --keep` again, on the writable layer it left
/// behind.
///
/// IT RE-RUNS THE RECORDED COMMAND, which is the whole design (see [`crate::keepbox`]): the box comes
/// back with the mounts, caps, filter, profile, ports and workload the operator gave it, because what
/// is replayed is their own command line rather than a field-by-field reconstruction that could
/// disagree with it. The kern that runs is THIS one, by path: a `kern start` must not be answered by
/// a different binary that happens to come first on `PATH`.
///
/// A box of that name that is ALREADY RUNNING is refused, not restarted. Two boxes cannot hold one
/// name, and the operator who typed `start` on a live box meant something kern cannot guess between
/// (`stop` then `start`, or nothing at all).
///
/// IN THE DIRECTORY THE BOX WAS CREATED IN, because a relative `-v ./data:/data` means nothing
/// anywhere else. A directory that is gone is a refusal that names it, rather than a box whose mounts
/// quietly resolve against wherever the operator happens to stand.
pub fn start_kept(names: &[String], attach_after: bool) -> Result<(), Error> {
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    let many = names.len() > 1;
    let mut first: Option<Error> = None;
    let mut failed = 0usize;
    for name in names {
        let r = start_one_kept(&self_exe, name);
        // `start -a`: Docker's start-and-attach. A box recorded detached (`create` records it so)
        // returns at once from its start; its output is then followed until it exits, and its exit
        // code becomes this command's, as `docker start -a` does. A box recorded in the foreground
        // already streamed and ended inside the start.
        //
        // THE CODE IS READ AS `kern wait` READS IT, from the exact run. The output ends when the box
        // exits, and its supervisor writes the code a moment LATER, after it reaps the box; this read
        // the exited list at once and answered 0 when the record was not there yet. MEASURED under a
        // full test suite in a Debian 13 VM: `start -a` of `echo only-this; exit 3` returned 0,
        // once, with the right output. The supervisor writes the code before its box leaves the
        // registry, so waiting for the `(name, pid)` pair to leave it, then reading the record of
        // that run by `(pid, starttime)`, cannot race. Bounded, so a supervisor that died cannot
        // hold this forever; then the newest record of the name, as before.
        let r = match r {
            Ok(0) if attach_after => match registry::find_ref(name) {
                Some(inst) => {
                    let (who, pid, starttime) = (inst.name.clone(), inst.pid, inst.starttime);
                    attach(name).map(|()| {
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(30);
                        while registry::pair_alive(&who, pid)
                            && std::time::Instant::now() < deadline
                        {
                            std::thread::sleep(std::time::Duration::from_millis(20));
                        }
                        registry::box_exit(pid, starttime).unwrap_or_else(|| {
                            registry::list_exited()
                                .into_iter()
                                .find(|e| e.name == *name)
                                .map_or(0, |e| e.code)
                        })
                    })
                }
                // ALREADY OVER before the attach could begin: a box that prints and exits at once
                // (`echo only-this; exit 3`) can finish inside its own start. Its output is in its
                // log and its code in its record; both are what `start -a` owes, where this
                // answered nothing and 0.
                None => {
                    let stdout = std::io::stdout();
                    let mut out = stdout.lock();
                    logs_to(name, None, false, (None, None), &mut out).map(|()| {
                        registry::list_exited()
                            .into_iter()
                            .find(|e| e.name == *name)
                            .map_or(0, |e| e.code)
                    })
                }
            },
            other => other,
        };
        match r {
            Ok(code) => {
                // THE WORKLOAD'S OWN EXIT CODE IS THE CALLER'S, like `kern box`, but only when one
                // box was named: with several, the codes cannot all be the status of this process, so
                // a non-zero one is reported as a failure of that box and the summary is the status.
                if !many {
                    std::process::exit(code);
                }
                if code != 0 {
                    failed += 1;
                    eprintln!("kern: '{name}' exited {code}");
                }
            }
            Err(e) => {
                failed += 1;
                if many {
                    eprintln!("kern: '{name}': {e}");
                } else if first.is_none() {
                    first = Some(e);
                }
            }
        }
    }
    if let Some(e) = first {
        return Err(e);
    }
    if failed > 0 {
        return Err(Error::Sandbox(format!(
            "{failed} of {} box(es) did not start or exited non-zero",
            names.len()
        )));
    }
    Ok(())
}

/// `kern restart <box>...` - stop a kept box and start it again from its record, or start it if it
/// is not running (Docker's `restart` on a stopped container starts it). A running box that is not
/// kept is refused by name: stopped, it would leave nothing to start again, which is kern's default
/// for a box. `grace` is `-t/--time`, the seconds before the kill, as `docker restart -t`.
pub fn restart(names: &[String], grace: Option<u64>) -> Result<(), Error> {
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    let mut failures: Vec<String> = Vec::new();
    for name in names {
        let kept = crate::keepbox::dir_of(name)
            .and_then(|d| crate::keepbox::read(&d))
            .is_some();
        if let Some(inst) = registry::find_ref(name) {
            if crate::keepbox::dir_of(&inst.name)
                .and_then(|d| crate::keepbox::read(&d))
                .is_none()
            {
                failures.push(format!(
                    "'{}' is not a kept box: stopped, it would leave nothing to start again. \
                     `kern box {} --keep ...` keeps one, and `kern create` makes one",
                    inst.name, inst.name
                ));
                continue;
            }
            STOP_NARRATES_TO_STDERR.store(true, std::sync::atomic::Ordering::Relaxed);
            let stopped = stop_with_grace(
                std::slice::from_ref(&inst.name),
                false,
                grace,
                crate::commands::DeafInit::Kill,
            );
            STOP_NARRATES_TO_STDERR.store(false, std::sync::atomic::Ordering::Relaxed);
            if let Err(e) = stopped {
                failures.push(format!("'{}': could not be stopped: {e}", inst.name));
                continue;
            }
        } else if !kept {
            failures.push(format!("no running box and no kept box named '{name}'"));
            continue;
        }
        match start_one_kept(&self_exe, name) {
            Ok(0) => println!("{name}"),
            Ok(code) => failures.push(format!("'{name}' exited {code}")),
            Err(e) => failures.push(format!("'{name}': {e}")),
        }
    }
    match failures.as_slice() {
        [] => Ok(()),
        [one] => Err(Error::Sandbox(one.clone())),
        many => {
            for f in many {
                eprintln!("kern: {f}");
            }
            Err(Error::Sandbox(format!(
                "{} of {} box(es) were not restarted",
                many.len(),
                names.len()
            )))
        }
    }
}

/// `kern create [OPTIONS] IMAGE [COMMAND] [ARG...]` - a kept box recorded and NOT started, which
/// `kern start` runs: Docker's `create`, on kern's kept boxes (see `keepbox`). `argv` is the `kern
/// box` command line it records (`box <name> ... --keep -- ...`), already built by the parser;
/// it is read by the same parser here, so a flag `kern box` refuses is refused now and not at
/// `start`. The image is resolved (pulled when it is missing), as Docker's `create` pulls. Prints
/// the box's name, which is what kern's other verbs take, where Docker prints an id.
pub fn create(name: &str, image: &str, argv: &[String]) -> Result<(), Error> {
    crate::cli::parse(argv)?;
    if registry::find_ref(name).is_some()
        || crate::keepbox::dir_of(name).is_some_and(|d| std::fs::symlink_metadata(d).is_ok())
    {
        return Err(Error::AlreadyRunning(format!(
            "the name '{name}' is already in use by a box: `kern rm {name}` removes it, or choose \
             another with --name"
        )));
    }
    crate::commands::resolve_image(image)?;
    let Some(dir) = crate::keepbox::dir_of(name) else {
        return Err(Error::Sandbox(format!("'{name}' is not a box name")));
    };
    let meta = crate::keepbox::Meta {
        created: registry::now_unix(),
        last_exit: None,
        image: String::new(),
        cwd: std::env::current_dir()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default(),
    };
    let os: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    crate::keepbox::write(&dir, &os, &meta)
        .map_err(|e| Error::Sandbox(format!("create {name}: cannot record the box: {e}")))?;
    println!("{name}");
    Ok(())
}

/// `kern export <box> [-o file]` - the box's filesystem as a tar, as Docker's `export` writes it:
/// relative member names (`usr/...`, no `./`), owners as the box sees them, and neither the mounts
/// the box was given (`/proc`, `/sys`, `/dev`, volumes, secrets) nor their contents. To stdout
/// without `-o`, refusing a terminal as Docker does.
///
/// THE HOST'S `tar`, RUN IN THE BOX'S USER NAMESPACE against `/proc/<pid1>/root`. From the host
/// side a file the box's root owns reads as the invoking user's and one a `--uid-range` uid owns is
/// unreadable; inside that user namespace the owners are the box's and every file is readable. The
/// mount namespace is NOT entered, so the `tar` that runs is the host's, never one the image ships.
pub fn export(name: &str, out: Option<&str>) -> Result<(), Error> {
    use std::io::IsTerminal;
    use std::os::unix::process::CommandExt;
    let Some(inst) = registry::find_ref(name) else {
        return Err(Error::NotRunning(format!(
            "no running box named '{name}': `kern export` reads a running box's filesystem (`kern \
             start {name}` runs a kept one again)"
        )));
    };
    let Some(pid1) = inst
        .live_pid1()
        .or_else(|| registry::box_init_under(inst.pid))
    else {
        return Err(Error::NotRunning(format!(
            "box '{}' has no running init to read the filesystem of",
            inst.name
        )));
    };
    if out.is_none() && std::io::stdout().is_terminal() {
        return Err(Error::Usage(
            "export <box> -o <file> (or redirect stdout): a tar is not written to a terminal",
        ));
    }
    let root = format!("/proc/{pid1}/root");
    // WHAT IS NOT THE BOX'S FILESYSTEM is what is mounted over it: `/proc`, `/sys`, `/dev`, the
    // volumes, the secrets. Read from the box's own mount table, because the device of a path is not
    // the answer: MEASURED on an `alpine` box, `/` was the overlay and `/usr` reported another
    // `st_dev` (overlayfs gives a lower directory its own), so `--one-file-system` exported 19 empty
    // directories. A mount point stays, as its directory or file; what it holds does not.
    let mountinfo = std::fs::read_to_string(format!("/proc/{pid1}/mountinfo"))
        .map_err(|e| Error::Sandbox(format!("export {}: its mount table: {e}", inst.name)))?;
    let mut excluded: Vec<String> = mountinfo
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(unescape_mountinfo)
        .filter(|m| m != "/")
        .map(|m| m.trim_start_matches('/').to_string())
        .collect();
    excluded.sort();
    excluded.dedup();
    let mut entries: Vec<String> = std::fs::read_dir(&root)
        .map_err(|e| Error::Sandbox(format!("export {}: listing its root: {e}", inst.name)))?
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    entries.sort();
    let userns = std::fs::File::open(format!("/proc/{pid1}/ns/user"))
        .map_err(|e| Error::Sandbox(format!("export {}: its user namespace: {e}", inst.name)))?;
    let userns_fd = std::os::fd::AsRawFd::as_raw_fd(&userns);
    // EVERY OPTION BEFORE THE FIRST NAME: GNU tar's selection options are positional and it refuses
    // one that follows a name (measured: `--no-recursion` after the names ended the export).
    let mut cmd = std::process::Command::new("tar");
    cmd.arg("--numeric-owner").arg("--anchored");
    for m in &excluded {
        cmd.arg(format!("--exclude={m}/*"));
    }
    cmd.arg("-C")
        .arg(&root)
        .arg("-cf")
        .arg(out.unwrap_or("-"))
        .args(&entries);
    // SAFETY: `setns` is async-signal-safe and touches no memory of this process; it runs in the
    // forked child before `exec`, where the child is single-threaded as `setns(CLONE_NEWUSER)`
    // requires.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(userns_fd, libc::CLONE_NEWUSER) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = cmd
        .status()
        .map_err(|e| Error::Sandbox(format!("export {}: running tar: {e}", inst.name)))?;
    drop(userns);
    if !status.success() {
        return Err(Error::Sandbox(format!(
            "export {}: tar exited {}",
            inst.name,
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// A mount point as `/proc/<pid>/mountinfo` writes it: space, tab, newline and backslash are octal
/// escapes (`\040`).
fn unescape_mountinfo(field: &str) -> String {
    let b = field.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = b.get(i + 1..i + 4).and_then(|d| {
            std::str::from_utf8(d)
                .ok()
                .and_then(|t| u8::from_str_radix(t, 8).ok())
        });
        match (b.get(i), octal) {
            (Some(b'\\'), Some(v)) => {
                out.push(v);
                i += 4;
            }
            (Some(c), _) => {
                out.push(*c);
                i += 1;
            }
            (None, _) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a recorded `kern box` argv runs detached: `-d`/`--detach` before the workload's `--`.
fn recorded_detached(argv: &[std::ffi::OsString]) -> bool {
    argv.iter()
        .take_while(|a| a.as_os_str() != "--")
        .any(|a| a == "-d" || a == "--detach")
}

/// One box of [`start_kept`]: the recorded command, run until it has started. Returns its exit code.
///
/// ALWAYS DETACHED, a box recorded in the foreground too, as `docker start` and `docker restart`
/// start a container whatever `docker run` attached it to; `start -a` then follows it from its
/// log. MEASURED before this: the kept box of an attached `docker run` (Dev Containers makes its
/// container that way) ran again in the foreground, and the `docker start` that reopens it never
/// answered; and `start -a` of such a box printed its output, then failed with "no logs", because a
/// foreground box writes none to follow.
fn start_one_kept(self_exe: &std::path::Path, name: &str) -> Result<i32, Error> {
    let Some(dir) = crate::keepbox::dir_of(name) else {
        return Err(Error::Sandbox(format!(
            "'{name}' is not a box name kern would have made"
        )));
    };
    // ALREADY RUNNING: refused before the record is even read, because the answer does not depend on
    // what the record says. `find_ref` resolves a name or an id prefix, the same way `stop` does.
    if let Some(inst) = registry::find_ref(name) {
        return Err(Error::AlreadyRunning(format!(
            "box '{}' is already running (pid {}) - `kern stop {}` first, or `kern exec {} <cmd>` to \
             run something in the box that is up",
            inst.name, inst.pid, inst.name, inst.name
        )));
    }
    let Some((argv, meta)) = crate::keepbox::read(&dir) else {
        // TWO DIFFERENT FACTS, TWO SENTENCES. "No kept box" sends the reader to look for a box that
        // is not there; a box whose DIRECTORY is there and whose record kern cannot read is there,
        // takes disk, and is invisible in `kern ps -a` (the listing skips what it cannot read, which
        // is right: it would have nothing true to print). Measured with a record one byte over the
        // size bound, which is the shape an editor or a truncated write leaves: the old message said
        // the box did not exist while its layer sat in the store.
        if dir.is_dir() {
            return Err(Error::Sandbox(format!(
                "kept box '{name}': its layer is in {} but kern cannot read the record beside it, \
                 so it does not know what to run. `kern rm {name}` removes both and `kern box \
                 {name} --image <ref> --keep -- <cmd>` makes it again",
                dir.display()
            )));
        }
        return Err(Error::NotRunning(format!(
            "no kept box '{name}': `kern box {name} --image <ref> --keep -- <cmd>` creates one, and \
             `kern ps -a` lists the ones there are. A box started without `--keep` leaves nothing to \
             start again, which is kern's default"
        )));
    };
    // THE RECORD MUST BE A `kern box` COMMAND LINE, which is the only thing `--keep` ever writes.
    // `kern start` runs THIS binary with the recorded argv, so the record decides which verb runs;
    // checking it keeps that decision inside what `--keep` can produce instead of inheriting
    // whatever is on disk. The store is the user's own (`$XDG_DATA_HOME/kern/boxes`, 0700), so this
    // is not a trust boundary - it is the same reason `read` bounds the record's size and rejects an
    // empty argv: a record kern did not write is reported, not replayed.
    // `box <name>` AS THE FIRST TWO ELEMENTS, not "box somewhere and the name somewhere". MEASURED
    // on the first version, which asked for `argv[0] == "box"` and the name ANYWHERE in the line: a
    // record of `box other-name --keep --image … -- /bin/true <name>` passed, and `kern start
    // <name>` started a box called `other-name` with an image the `ps -a` row did not show. A
    // replay can now only ever be this box.
    let looks_like_box = argv.first().is_some_and(|a| a == "box")
        && argv.get(1).is_some_and(|a| a == std::ffi::OsStr::new(name));
    if !looks_like_box {
        return Err(Error::Sandbox(format!(
            "kept box '{name}': its record does not begin `box {name}`, so it is not a command \
             line this box can be started from. `kern rm {name}` removes it, and `kern box {name} \
             --image <ref> --keep -- <cmd>` makes it again"
        )));
    }
    let cwd = std::path::PathBuf::from(&meta.cwd);
    if !meta.cwd.is_empty() && !cwd.is_dir() {
        return Err(Error::Sandbox(format!(
            "kept box '{name}' was created in {} and that directory is gone, so a relative path in \
             its command line (a `-v ./dir:/dir`, a `--env-file`) would resolve somewhere else. \
             Re-create it with `kern box {name} ... --keep` from where you want it to run",
            meta.cwd
        )));
    }
    let mut argv = argv;
    if !recorded_detached(&argv) {
        // Right after `box <name>`, where every `kern box` flag may stand.
        argv.insert(2, std::ffi::OsString::from("-d"));
    }
    let mut cmd = std::process::Command::new(self_exe);
    cmd.args(&argv);
    if !meta.cwd.is_empty() {
        cmd.current_dir(&cwd);
    }
    let status = cmd
        .status()
        .map_err(|e| Error::Sandbox(format!("kept box '{name}': cannot run kern again: {e}")))?;
    // 128 + signal, the shell's convention and the one `kern wait` uses, for a kern killed by a
    // signal while the box ran. `code()` is None exactly then.
    Ok(status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(0)
    }))
}

/// `kern rm <name>...` - remove a stopped `--keep` box: its writable layer and its record, in one
/// removal (they live in one directory, see [`crate::keepbox`]).
///
/// A RUNNING BOX IS REFUSED AND NOT KILLED. Docker's `rm` behaves this way, and the reason is the
/// same: `rm` on a box that is up is as likely to be a typo as an intention, and the data it would
/// take with it is the data the operator asked to keep. The message names `stop`.
/// `force` is `docker rm -f`, MEASURED with docker 29: a running container is stopped and removed
/// (its name printed, exit 0), and a name that does not exist is said and still exits 0. kern had no
/// `-f` and answered "unknown flag", so the line a docker user types first to clean up failed.
pub fn remove_kept(names: &[String], force: bool) -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let mut failures: Vec<String> = Vec::new();
    for name in names {
        if let Some(inst) = registry::find_ref(name) {
            if !force {
                failures.push(format!(
                    "'{}' is running (pid {}) - `kern stop {}` first, or `kern rm -f`",
                    inst.name, inst.pid, inst.name
                ));
                continue;
            }
            if let Err(e) = stop(std::slice::from_ref(&inst.name), false) {
                failures.push(format!("'{name}': could not be stopped: {e}"));
                continue;
            }
        }
        // AN EXITED BOX'S RECORD GOES TOO, as `docker rm` takes a container out of `docker ps -a`;
        // and a box with no `--keep` layer is then removed by exactly that, stopped or exited.
        let kept =
            crate::keepbox::dir_of(name).is_some_and(|d| std::fs::symlink_metadata(d).is_ok());
        // ITS LOGS GO WITH IT, as `docker rm` removes a container's log: they stayed in the
        // runtime dir until the hour-long expiry, and kern's Docker API removes a `docker run --rm`
        // box this way once it has read the box's output.
        let records = registry::clear_exited_named(name);
        for pid in &records {
            crate::commands::boxlog::remove_run_logs(&format!("{name}-{pid}"));
        }
        if !kept && !records.is_empty() {
            println!("{name}");
            continue;
        }
        match crate::keepbox::remove(name) {
            Ok(()) => {
                // Every run of a kept box left a log: none of them outlives the box.
                crate::commands::boxlog::remove_logs_of(name);
                println!("removed kept box '{}{name}{}'", p.c, p.z)
            }
            // `-f` on a name that is not there: said, and not a failure, as docker answers it.
            Err(e) if force => eprintln!("kern: '{name}': {e}"),
            Err(e) => failures.push(format!("'{name}': {e}")),
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    // One sentence per name that could not go, and a non-zero status: `kern rm a b` where `b` is
    // running has not done what was asked, and a script reading the status must not be told it has.
    for f in &failures {
        eprintln!("kern: {f}");
    }
    Err(Error::Sandbox(format!(
        "{} of {} kept box(es) could not be removed",
        failures.len(),
        names.len()
    )))
}

#[cfg(test)]
mod tests {

    /// THE CARD NODES AND ONLY THOSE, for the row `kern inspect` prints and the badge `kern top`
    /// shows. The two read this one function so they cannot disagree about one box.
    ///
    /// `nvidiactl`, `nvidia-uvm`, `nvidia-uvm-tools` and `nvidia-modeset` go with ANY card, so
    /// listing them would make a box holding one card look like it holds four. `/proc/self/root`
    /// is this process's own root and has no card nodes under `/dev`, which is the honest empty
    /// case; a pid that is gone, and `None`, are the same answer for the same reason.
    #[test]
    fn the_gpu_row_names_cards_and_not_the_shared_nodes() {
        // This process: a real, readable `/proc/<pid>/root/dev` with no `/dev/nvidiaN` in it.
        let mine = super::gpu_nodes_of(Some(std::process::id() as i32));
        for shared in [
            "nvidiactl",
            "nvidia-uvm",
            "nvidia-uvm-tools",
            "nvidia-modeset",
        ] {
            assert!(
                !mine.contains(shared),
                "a shared node leaked into the card list: {mine}"
            );
        }
        for name in mine.split_whitespace() {
            let rest = name
                .strip_prefix("nvidia")
                .unwrap_or_else(|| panic!("not a card node: {name}"));
            assert!(
                !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
                "not a card node: {name}"
            );
        }
        // NO PID AND A DEAD PID ARE THE SAME ANSWER, and it is empty rather than an error: a box
        // whose `/dev` cannot be read has not been shown to hold a card, and saying so with a
        // dash is what both callers render.
        assert_eq!(super::gpu_nodes_of(None), "");
        assert_eq!(super::gpu_nodes_of(Some(-1)), "");
        assert_eq!(super::gpu_nodes_of(Some(0)), "");
    }

    /// A DRIVER UPGRADE UNDER A RUNNING BOX IS INVISIBLE, AND NOW IT IS NOT.
    ///
    /// A grant binds the host's driver libraries by path, and a bind pins the INODE. Measured
    /// 2026-11-12 through the same mechanism, on a file this user owns so no driver was touched: a
    /// running box kept `VERSION-1` after the host file was REPLACED at the same path (a new inode,
    /// which is what a package upgrade does), and a box started afterwards got `VERSION-2`.
    ///
    /// So after an upgrade a live box keeps the driver userspace it was granted while a new one
    /// gets the new, and two boxes on one host run different userspace against one kernel module.
    /// NVIDIA requires the two to match and the error it produces, `Driver/library version
    /// mismatch`, names neither the box nor the upgrade. The grant knew `driver_version` and threw
    /// it away: it reached no registry field and no surface.
    ///
    /// DERIVED, NOT RECORDED, for the reason the node row is read rather than replayed: a recorded
    /// version can disagree with what the box actually holds and a reading cannot. It also needs no
    /// new persisted state, so an older kern's records stay readable.
    #[test]
    fn a_driver_upgrade_under_a_running_box_is_named() {
        // THE VERSION IN A LIBRARY NAME.
        assert_eq!(
            super::driver_version_in_name("libcuda.so.580.173.02").as_deref(),
            Some("580.173.02")
        );
        assert_eq!(
            super::driver_version_in_name("libnvidia-ml.so.585.1.2").as_deref(),
            Some("585.1.2")
        );
        // NOT every name with digits: a SONAME link and an ordinary library must not answer, or the
        // row would report a version from a file that carries none.
        for name in [
            "libcuda.so.1",
            "libcuda.so",
            "libc.so.6",
            "libfoo.so.1.2",
            "libfoo.so.1.2.3.4",
            "libfoo.so.a.b.c",
            "libfoo.so..",
            "nvidia0",
        ] {
            assert_eq!(
                super::driver_version_in_name(name),
                None,
                "{name} must not read as a driver version"
            );
        }

        // THE VERSION LINE, in BOTH wordings. The open kernel module and the proprietary one differ in
        // the prefix, so a reader keyed on a position gets the empty string from one of them; the
        // resolver learned this once already and this is the same rule.
        let open =
            "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  580.173.02  Release Build\n";
        let proprietary =
            "NVRM version: NVIDIA UNIX x86_64 Kernel Module  535.183.01  Fri May 10\n";
        assert_eq!(super::first_version_token(open), Some("580.173.02"));
        assert_eq!(super::first_version_token(proprietary), Some("535.183.01"));
        assert_eq!(
            super::first_version_token("NVRM version: no numbers here"),
            None
        );

        // THE SENTENCE, and the empty case is the one that must stay empty: a row on every box
        // would bury the one case that matters.
        assert_eq!(super::skew_between("580.173.02", "580.173.02"), "");
        let said = super::skew_between("580.173.02", "585.1.2");
        assert!(said.contains("granted under 580.173.02"), "{said}");
        assert!(said.contains("host now has 585.1.2"), "{said}");

        // AND THE LIVE HALF: this process holds no granted library, so it reports nothing. A box
        // that does is covered by the pentest, which can start one.
        assert_eq!(
            super::gpu_driver_skew_of(Some(std::process::id() as i32)),
            "",
            "a process with no granted library must say nothing"
        );
        assert_eq!(super::gpu_driver_skew_of(None), "");
    }

    /// A BOX CANNOT TALK ITS WAY INTO THE ROW, which is what "a reading of what the box HAS rather
    /// than a replay of what the caller typed" has to mean to be worth printing.
    ///
    /// The row matched on the NAME alone, and a box's `/dev` is its own writable tmpfs: measured on
    /// 2026-11-11, `touch /dev/nvidia7; mkdir /dev/nvidia9` in a box with NO grant made
    /// `kern inspect` print `gpu  nvidia7 nvidia9` and lit `kern top`'s `gpu:N` badge, which that
    /// legend describes as a box less isolated than the default. An operator asking which boxes hold
    /// hardware was answered by the boxes.
    ///
    /// All four forged shapes need no privilege, which is the point, and the fourth is the one that
    /// defeated the first fix. The symlink case is what a careless `metadata` reintroduces: it would
    /// follow the link to a real character device and report a card. The WHITEOUT is sharper, and it
    /// says the earlier measurement asked the wrong question: `mknod` of majors 195, 226 and 510 is
    /// EPERM because `vfs_mknod` resolves CAP_MKNOD against the initial user namespace, but that test
    /// reads `if ((S_ISCHR(mode) || S_ISBLK(mode)) && !is_whiteout && !capable(CAP_MKNOD))`, and a
    /// whiteout is `c 0 0`. Measured 2026-11-11: an unprivileged `mknod("nvidia9", S_IFCHR, 0)`
    /// SUCCEEDS on ext4 and on a box's own `/dev` tmpfs, and with the kind check alone a box holding
    /// `--gpus device=0` printed `gpu  nvidia0 nvidia9`.
    ///
    /// Hence the device number, and hence `host_dev`: what the box cannot write is the host's own
    /// node. The positive control is the half that matters, because this is the second fix to this
    /// predicate and the first one broke the honest case while passing its own negative.
    #[test]
    fn a_box_cannot_forge_the_gpu_row_by_making_files_named_like_cards() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::FileTypeExt;
        let dir = std::env::temp_dir().join(format!("kern-gpurow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dev dir");
        std::fs::write(dir.join("nvidia7"), b"not a card").expect("regular file");
        std::fs::create_dir_all(dir.join("nvidia9")).expect("directory");
        // A symlink to a character device that really is one, which is how a box would borrow the
        // kind it cannot create. `/dev/null` is a character device on every host this runs on.
        std::os::unix::fs::symlink("/dev/null", dir.join("nvidia8")).expect("symlink");
        // The whiteout, named after a card the host DOES have, so the name half of the old predicate
        // matches and only the device number can refuse it. `mknod` through libc because
        // `std::fs` has no interface for it; the call is the same one a box makes.
        let white = std::ffi::CString::new(dir.join("nvidia0").as_os_str().as_bytes())
            .expect("no NUL in a temp path");
        let made = unsafe { libc::mknod(white.as_ptr(), libc::S_IFCHR | 0o600, 0) };
        assert_eq!(
            made,
            0,
            "the whiteout case cannot run if the kernel refuses the whiteout: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            std::fs::symlink_metadata(dir.join("nvidia0"))
                .expect("the whiteout")
                .file_type()
                .is_char_device(),
            "a whiteout that does not read as a character device would make this test vacuous"
        );
        assert_eq!(
            super::gpu_nodes_in(&dir, std::path::Path::new("/dev")),
            "",
            "a regular file, a directory, a symlink and a whiteout named like cards are not cards"
        );

        // POSITIVE CONTROL, so the emptiness above is the predicate and not a function that always
        // answers nothing. The host's own `/dev` is the only place a character device can be found
        // without privilege; a host with no card says so rather than passing in silence.
        if std::path::Path::new("/dev/nvidia0").exists() {
            let real =
                super::gpu_nodes_in(std::path::Path::new("/dev"), std::path::Path::new("/dev"));
            assert!(
                real.split_whitespace().any(|n| n == "nvidia0"),
                "the host's own card node must read as a card: {real}"
            );
        } else {
            eprintln!("skip: no /dev/nvidia0 on this host, so the positive half cannot run");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    use super::mem_cap_row;

    /// THE BRANCH THIS HOST CANNOT PRODUCE, which is the only reason the row exists.
    ///
    /// `enforced == None` means `box_cgroup_dir` found no kern leaf for the box's PID 1 - a host with
    /// no usable cgroup delegation, where the box sits in the cgroup-v2 ROOT and nothing caps it. A
    /// later pass measured exactly that and read the requested value as a cap in force, because
    /// the row said `64M` and stopped. On a delegated developer machine this state cannot be created,
    /// so a runtime test would silently skip; the logic is pure, so it is pinned directly.
    #[test]
    fn an_asked_for_cap_that_nothing_enforces_says_so_in_the_row() {
        assert_eq!(
            mem_cap_row(Some(64 * 1024 * 1024), None, None),
            "64M (requested, NOT enforced here)"
        );
    }

    /// And the common case stays QUIET: a cap that is held exactly as asked prints the number alone.
    /// If this ever gained a qualifier, every capped box on every host would carry noise, and the
    /// warning above would stop standing out - which is the only thing that makes it useful.
    #[test]
    fn a_cap_held_exactly_as_asked_prints_the_number_alone() {
        let row = mem_cap_row(Some(64 * 1024 * 1024), Some(64 * 1024 * 1024), None);
        assert_eq!(row, "64M");
        assert!(
            !row.contains("force") && !row.contains("NOT"),
            "the quiet case must carry no qualifier, got {row:?}"
        );
    }

    /// A DIFFERENT ceiling in force is named, not swallowed. Reachable in production through a fleet
    /// cap on `kern.slice` binding tighter than the request, or a `kern update` whose new value the
    /// registry entry has not recorded. Reporting only the request would name a ceiling the box does
    /// not have, which is the same class of defect as the arm above with the sign flipped.
    #[test]
    fn a_ceiling_that_differs_from_the_request_names_both() {
        assert_eq!(
            mem_cap_row(Some(64 * 1024 * 1024), Some(32 * 1024 * 1024), None),
            "64M (in force: 32M)"
        );
    }

    /// No cap asked: the same dash the rest of the block uses for "nothing to report", and it must not
    /// depend on what the kernel happens to hold. A box started with no `--memory` inside a slice that
    /// has one would otherwise report a limit the operator never asked for as though it were theirs.
    #[test]
    fn no_requested_cap_is_a_dash_whatever_the_kernel_holds() {
        assert_eq!(mem_cap_row(None, None, None), "-");
        assert_eq!(mem_cap_row(None, Some(64 * 1024 * 1024), None), "-");
    }

    /// A `memory.high` above the box is appended to EVERY arm, and the plain arms are unchanged
    /// without one: the common case must stay exactly as quiet as before.
    #[test]
    fn mem_cap_row_names_a_memory_high_above_the_box_in_every_arm() {
        let jetson = kern_isolation::OuterMemoryHigh {
            dir: std::path::PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/kern.slice",
            ),
            high: 80 * 1024 * 1024,
            ceiling: Some(512 * 1024 * 1024),
        };
        let tail =
            "; throttled above 80M by /user.slice/user-1000.slice/user@1000.service/kern.slice \
                    (memory.high)";
        let mib = 1024 * 1024;
        for (asked, enforced) in [
            (Some(512 * mib), Some(512 * mib)),
            (Some(512 * mib), Some(256 * mib)),
            (Some(512 * mib), None),
            (None, None),
        ] {
            let plain = mem_cap_row(asked, enforced, None);
            let with = mem_cap_row(asked, enforced, Some(&jetson));
            assert_eq!(with, format!("{plain}{tail}"), "arm {asked:?}/{enforced:?}");
            assert!(
                !plain.contains("throttled"),
                "a plain row mentions a throttle: {plain}"
            );
        }
    }
}

#[cfg(test)]
mod driver_row_tests {
    /// The driver's version comes from the driver's libraries and nothing else bound beside them.
    #[test]
    fn the_driver_version_is_read_from_the_drivers_own_libraries() {
        let line = |p: &str| format!("36 35 0:5 / {p} ro,relatime - overlay overlay rw\n");
        let jetson = [
            line("/usr/lib/aarch64-linux-gnu/nvidia/libgstnvcustomhelper.so.1.0.0"),
            line("/usr/lib/aarch64-linux-gnu/nvidia/libnvidia-egl-gbm.so.1.1.0"),
            line("/usr/lib/aarch64-linux-gnu/nvidia/libnvidia-glcore.so.540.4.0"),
            line("/usr/lib/aarch64-linux-gnu/nvidia/libnvidia-eglcore.so.540.4.0"),
        ]
        .concat();
        assert_eq!(
            super::driver_version_in_mountinfo(&jetson).as_deref(),
            Some("540.4.0")
        );
        let desktop = line("/usr/lib/x86_64-linux-gnu/libcuda.so.580.173.02");
        assert_eq!(
            super::driver_version_in_mountinfo(&desktop).as_deref(),
            Some("580.173.02")
        );
        assert_eq!(
            super::driver_version_in_mountinfo(&line("/usr/lib/libfoo.so.1.0.0")),
            None
        );
    }
}
