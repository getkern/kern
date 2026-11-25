//! `kern bench`: kern's box start measured on THIS machine, so a number in the README is something a
//! reader runs rather than something they are asked to trust.
//!
//! WHAT IT MEASURES, and nothing else: the wall time of the command a user would type,
//! `kern box <name> (--image IMG | --rootfs DIR) [--bind-rootfs] -- /bin/true`, from the spawn to the
//! exit, with the image already in the cache (a warm start: `kern bench` resolves it before timing).
//!
//! THE DISCIPLINE of the repo's own measurements (`scripts/ab-measure.py`), because a bench that
//! prints a bare ratio is an advert:
//!   * a WARM-UP is run and thrown away;
//!   * the FLOOR is printed: what spawning `/bin/true` costs here, below which no difference is real;
//!   * an A/A run of the same command in two interleaved series gives the noise of this machine NOW,
//!     as an interval: a difference inside it is not a difference;
//!   * a comparison (`--compare docker|podman`, only when asked: kern never runs another runtime on
//!     its own) is PAIRED, one run of each in turn, and reported as the median of the per-pair
//!     differences with a bootstrap interval, never as a ratio of two medians;
//!   * the load average is read before and after: a busy machine is said, not hidden.

use crate::error::Error;
use std::time::Instant;

/// What `kern bench` was asked to measure: the box flag and value it passes through (`--image` or
/// `--rootfs`), `--bind-rootfs`, the number of runs, and the options of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BenchArgs<'a> {
    pub(crate) flag: &'a str,
    pub(crate) value: &'a str,
    pub(crate) bind_rootfs: bool,
    pub(crate) runs: usize,
    pub(crate) compare: Option<&'a str>,
    pub(crate) json: bool,
}

/// Runs thrown away before any series: the first starts warm caches (page cache, the image's
/// layers, the dynamic loader) that every later run finds warm.
const WARMUP: usize = 3;
/// Bootstrap resamples for an interval: 2000 gives a stable 95% interval at these sizes.
const RESAMPLES: usize = 2000;

/// One series of wall times, milliseconds.
#[derive(Debug, Clone, Default)]
struct Series {
    ms: Vec<f64>,
}

impl Series {
    fn sorted(&self) -> Vec<f64> {
        let mut v = self.ms.clone();
        v.sort_by(f64::total_cmp);
        v
    }

    fn quantile(&self, q: f64) -> f64 {
        quantile_of(&self.sorted(), q)
    }
}

/// The `q` quantile of a sorted slice, linear between the two nearest ranks; 0 for an empty one.
fn quantile_of(sorted: &[f64], q: f64) -> f64 {
    match sorted.len() {
        0 => 0.0,
        1 => sorted[0],
        n => {
            let pos = q.clamp(0.0, 1.0) * (n - 1) as f64;
            let lo = pos.floor() as usize;
            let hi = pos.ceil() as usize;
            let w = pos - lo as f64;
            sorted[lo] * (1.0 - w) + sorted[hi.min(n - 1)] * w
        }
    }
}

/// xorshift64*: deterministic, so the same samples give the same interval and a report can be
/// re-derived from its own numbers.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// The 95% bootstrap interval of the median of `values`.
fn median_interval(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut medians = Vec::with_capacity(RESAMPLES);
    let mut sample = vec![0.0; values.len()];
    for _ in 0..RESAMPLES {
        for s in sample.iter_mut() {
            *s = values[rng.below(values.len())];
        }
        sample.sort_by(f64::total_cmp);
        medians.push(quantile_of(&sample, 0.5));
    }
    medians.sort_by(f64::total_cmp);
    (quantile_of(&medians, 0.025), quantile_of(&medians, 0.975))
}

/// Wall time of one command run to its end, its output discarded; `Err` names what failed.
fn time_once(argv: &[String]) -> Result<f64, String> {
    let (prog, rest) = argv
        .split_first()
        .ok_or_else(|| "nothing to run".to_string())?;
    let started = Instant::now();
    let status = std::process::Command::new(prog)
        .args(rest)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("cannot run {prog}: {e}"))?;
    let took = started.elapsed();
    if !status.success() {
        return Err(format!("`{}` exited with {status}", argv.join(" ")));
    }
    Ok(took.as_secs_f64() * 1000.0)
}

/// The 1-minute load average, from `/proc/loadavg`.
fn load1() -> Option<f64> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// This machine, in one line: CPU model, CPUs, kernel.
fn machine() -> String {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_else(|| "unknown CPU".to_string());
    let cpus = std::thread::available_parallelism().map_or(0, |n| n.get());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    format!("{cpu}, {cpus} CPUs, Linux {kernel}")
}

/// The argv of one box start, exactly what a user would type for the same flags.
fn box_argv(kern: &str, a: &BenchArgs, name: &str) -> Vec<String> {
    let mut v = vec![
        kern.to_string(),
        "box".to_string(),
        name.to_string(),
        a.flag.to_string(),
        a.value.to_string(),
    ];
    if a.bind_rootfs {
        v.push("--bind-rootfs".to_string());
    }
    v.extend(["--", "/bin/true"].map(String::from));
    v
}

/// The argv of one container start with another runtime: the same image and command, on its
/// default network, as a box is on kern's. It said `--network none` "as a box has none by default",
/// which stopped being true when a box got Docker's default network: the pair timed a box with a
/// NAT against a container without one.
fn other_argv(tool: &str, image: &str) -> Vec<String> {
    [tool, "run", "--rm", image, "/bin/true"]
        .map(String::from)
        .to_vec()
}

/// [`box_argv`], built once the network kern prepares ahead is ready (`netpool::settle`, bounded and
/// not timed: this runs before the clock starts), so every box is timed the way a box started on its
/// own is, and not half against a pool still refilling from the previous one.
fn ready_box_argv(kern: &str, a: &BenchArgs, name: &str) -> Vec<String> {
    crate::netpool::settle();
    box_argv(kern, a, name)
}

/// A unique box name per run, so a run never meets the previous one's leftovers.
fn name(i: usize) -> String {
    format!("kern-bench-{}-{i}", std::process::id())
}

/// One series of `runs` starts of `argv_for(i)`, after the warm-up; stops at the first failure.
fn series(runs: usize, argv_for: &dyn Fn(usize) -> Vec<String>) -> Result<Series, String> {
    for i in 0..WARMUP {
        time_once(&argv_for(1_000_000 + i))?;
    }
    let mut s = Series::default();
    for i in 0..runs {
        s.ms.push(time_once(&argv_for(i))?);
    }
    Ok(s)
}

/// Two series of `argv_for` run in turn (A, A', A, A', ...): the A/A control.
fn interleaved(
    runs: usize,
    a: &dyn Fn(usize) -> Vec<String>,
    b: &dyn Fn(usize) -> Vec<String>,
) -> Result<(Series, Series), String> {
    for i in 0..WARMUP {
        time_once(&a(2_000_000 + i))?;
        time_once(&b(3_000_000 + i))?;
    }
    let (mut sa, mut sb) = (Series::default(), Series::default());
    for i in 0..runs {
        // The order alternates too, so neither series is always the one that runs second.
        if i % 2 == 0 {
            sa.ms.push(time_once(&a(i))?);
            sb.ms.push(time_once(&b(i))?);
        } else {
            sb.ms.push(time_once(&b(i))?);
            sa.ms.push(time_once(&a(i))?);
        }
    }
    Ok((sa, sb))
}

/// The per-pair differences `b - a`.
fn paired(a: &Series, b: &Series) -> Vec<f64> {
    a.ms.iter().zip(&b.ms).map(|(x, y)| y - x).collect()
}

/// Run `kern bench`: the series, the report, and a JSON copy saved for later comparison.
pub(crate) fn run(args: &BenchArgs) -> Result<(), Error> {
    let fail = |e: String| Error::Sandbox(format!("bench: {e}"));
    if let Some(tool) = args.compare {
        if args.flag != "--image" {
            return Err(Error::Usage(
                "bench --compare needs --image (the other runtime runs the same image)",
            ));
        }
        if tool != "docker" && tool != "podman" {
            return Err(Error::Usage("bench --compare docker|podman"));
        }
    }
    let kern = std::env::current_exe()
        .map_err(|e| fail(format!("cannot name kern's own binary: {e}")))?
        .to_string_lossy()
        .into_owned();
    let say = |t: &str| {
        if !args.json {
            eprintln!("{t}");
        }
    };
    let load_before = load1();
    if let Some(tool) = args.compare {
        say(&format!(
            "kern bench: {tool} pull {} (not timed)",
            args.value
        ));
        time_once(&[
            tool.to_string(),
            "pull".into(),
            "-q".into(),
            args.value.to_string(),
        ])
        .map_err(|e| fail(format!("{e} (is {tool} installed and running?)")))?;
    }
    say("kern bench: the floor (spawning /bin/true)");
    let floor = series(args.runs, &|_| vec!["/bin/true".to_string()]).map_err(fail)?;
    say("kern bench: kern box");
    let boxes = series(args.runs, &|i| ready_box_argv(&kern, args, &name(i))).map_err(fail)?;
    say("kern bench: A/A, the same box start in two interleaved series");
    let (aa_a, aa_b) = interleaved(
        args.runs,
        &|i| ready_box_argv(&kern, args, &name(4_000_000 + i)),
        &|i| ready_box_argv(&kern, args, &name(5_000_000 + i)),
    )
    .map_err(fail)?;
    let aa = paired(&aa_a, &aa_b);
    let aa_ci = median_interval(&aa);
    let compared = match args.compare {
        None => None,
        Some(tool) => {
            say(&format!(
                "kern bench: paired with {tool}, one start of each in turn"
            ));
            let (k, o) = interleaved(
                args.runs,
                &|i| ready_box_argv(&kern, args, &name(6_000_000 + i)),
                &|_| other_argv(tool, args.value),
            )
            .map_err(fail)?;
            let d = paired(&k, &o);
            let (lo, hi) = median_interval(&d);
            Some((
                tool.to_string(),
                k,
                o,
                quantile_of(&sorted(&d), 0.5),
                lo,
                hi,
            ))
        }
    };
    let load_after = load1();
    let cpus = std::thread::available_parallelism().map_or(1.0, |n| n.get() as f64);
    let busy = [load_before, load_after]
        .into_iter()
        .flatten()
        .any(|l| l > cpus * 0.25);
    let what = format!(
        "{} {}{}",
        args.flag,
        args.value,
        if args.bind_rootfs {
            " --bind-rootfs"
        } else {
            ""
        }
    );
    let json = bench_json(
        args,
        &what,
        &floor,
        &boxes,
        &aa,
        aa_ci,
        compared.as_ref(),
        load_before,
        load_after,
    );
    let saved = save(&json);
    if args.json {
        println!("{json}");
        return Ok(());
    }
    let p = crate::ui::Palette::detect();
    let row = |label: &str, s: &Series| {
        format!(
            "  {label:<34} median {:>7.2} ms   p10 {:>7.2}   p90 {:>7.2}",
            s.quantile(0.5),
            s.quantile(0.1),
            s.quantile(0.9)
        )
    };
    let sb = boxes.sorted();
    let avg = boxes.ms.iter().sum::<f64>() / boxes.ms.len().max(1) as f64;
    println!(
        "{b}kern bench{z}  {} runs, {what}, after {WARMUP} discarded, image in the cache",
        boxes.ms.len(),
        b = p.b,
        z = p.z
    );
    println!("  machine: {}", machine());
    // HOW THE BOXES WERE TIMED, said beside the number it shapes: each one after the network kern
    // prepares ahead was ready (the wait is not timed), which is a box started on its own, not one
    // in a burst.
    if crate::netpool::is_enabled() {
        println!(
            "  network: kern's default NAT, each box timed once the NAT prepared ahead was ready \
             (KERN_NET_POOL=0 times a box that starts its own)"
        );
    } else {
        println!("  network: kern's default NAT, each box starting its own (KERN_NET_POOL=0)");
    }
    println!(
        "  load average (1 min): {} before, {} after{}",
        load_before.map_or("?".into(), |l| format!("{l:.2}")),
        load_after.map_or("?".into(), |l| format!("{l:.2}")),
        if busy {
            "  ! not idle: the numbers carry the machine's other work"
        } else {
            ""
        }
    );
    println!(
        "  min {:.1} ms · median {:.1} ms · avg {:.1} ms · max {:.1} ms",
        sb.first().copied().unwrap_or(0.0),
        quantile_of(&sb, 0.5),
        avg,
        sb.last().copied().unwrap_or(0.0)
    );
    println!(
        "  {g}{:.0} boxes/sec{z} (serial)",
        1000.0 / avg.max(f64::MIN_POSITIVE),
        g = p.g,
        z = p.z
    );
    println!("{}", row("kern box", &boxes));
    println!("{}", row("floor: spawning /bin/true", &floor));
    println!(
        "  A/A noise now: median difference {:+.2} ms, 95% interval [{:+.2}, {:+.2}]; a difference inside it is not one",
        quantile_of(&sorted(&aa), 0.5),
        aa_ci.0,
        aa_ci.1
    );
    if let Some((tool, k, o, med, lo, hi)) = &compared {
        println!("{}", row("kern box (paired run)", k));
        println!("{}", row(&format!("{tool} run --rm (paired)"), o));
        println!(
            "  {tool} minus kern, per pair: median {med:+.2} ms, 95% interval [{lo:+.2}, {hi:+.2}]{}",
            if *lo <= 0.0 && *hi >= 0.0 {
                ": not distinguishable here"
            } else {
                ""
            }
        );
    }
    match saved {
        Some(path) => println!("  saved: {}", path.display()),
        None => println!("  (not saved: no data directory)"),
    }
    Ok(())
}

fn sorted(v: &[f64]) -> Vec<f64> {
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    s
}

type Compared = (String, Series, Series, f64, f64, f64);

#[allow(clippy::too_many_arguments)]
fn bench_json(
    args: &BenchArgs,
    what: &str,
    floor: &Series,
    boxes: &Series,
    aa: &[f64],
    aa_ci: (f64, f64),
    compared: Option<&Compared>,
    load_before: Option<f64>,
    load_after: Option<f64>,
) -> String {
    use kern_common::json_str;
    let s = |x: &Series| {
        format!(
            "{{\"median_ms\":{:.3},\"p10_ms\":{:.3},\"p90_ms\":{:.3},\"samples_ms\":[{}]}}",
            x.quantile(0.5),
            x.quantile(0.1),
            x.quantile(0.9),
            x.ms.iter()
                .map(|v| format!("{v:.3}"))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let opt = |v: Option<f64>| v.map_or("null".to_string(), |l| format!("{l:.2}"));
    let cmp = compared.map_or("null".to_string(), |(tool, k, o, med, lo, hi)| {
        format!(
            "{{\"tool\":{},\"kern\":{},\"other\":{},\"other_minus_kern_median_ms\":{med:.3},\"interval_ms\":[{lo:.3},{hi:.3}]}}",
            json_str(tool),
            s(k),
            s(o)
        )
    });
    format!(
        "{{\"json_schema\":1,\"kern\":{},\"when\":{},\"machine\":{},\"box\":{},\"runs\":{},\"warmup\":{WARMUP},\"load_before\":{},\"load_after\":{},\"floor\":{},\"kern_box\":{},\"aa\":{{\"median_ms\":{:.3},\"interval_ms\":[{:.3},{:.3}]}},\"compare\":{cmp}}}",
        json_str(kern_common::VERSION),
        crate::registry::now_unix(),
        json_str(&machine()),
        json_str(what),
        args.runs,
        opt(load_before),
        opt(load_after),
        s(floor),
        s(boxes),
        quantile_of(&sorted(aa), 0.5),
        aa_ci.0,
        aa_ci.1
    )
}

/// One JSON file per run in `$XDG_DATA_HOME/kern/bench/`, so two runs can be compared later.
fn save(json: &str) -> Option<std::path::PathBuf> {
    let dir = crate::kern_xdg_root("XDG_DATA_HOME", ".local/share")?.join("bench");
    std::fs::create_dir_all(&dir).ok()?;
    let p = dir.join(format!("bench-{}.json", crate::registry::now_unix()));
    std::fs::write(&p, format!("{json}\n")).ok()?;
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_are_the_nearest_ranks_interpolated() {
        let v = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(quantile_of(&v, 0.5), 3.0);
        assert_eq!(quantile_of(&v, 0.0), 1.0);
        assert_eq!(quantile_of(&v, 1.0), 5.0);
        assert!((quantile_of(&[1.0, 2.0], 0.5) - 1.5).abs() < 1e-9);
        assert_eq!(quantile_of(&[], 0.5), 0.0);
    }

    #[test]
    fn the_interval_holds_the_median_and_is_deterministic() {
        let v: Vec<f64> = (0..40).map(|i| 4.0 + f64::from(i % 7) * 0.1).collect();
        let (lo, hi) = median_interval(&v);
        let med = quantile_of(&sorted(&v), 0.5);
        assert!(lo <= med && med <= hi, "{lo} {med} {hi}");
        assert_eq!(median_interval(&v), (lo, hi), "same samples, same interval");
    }

    #[test]
    fn a_comparison_runs_the_same_image_and_command_on_the_default_network() {
        assert_eq!(
            other_argv("podman", "alpine:3.19"),
            ["podman", "run", "--rm", "alpine:3.19", "/bin/true"]
        );
        let a = BenchArgs {
            flag: "--image",
            value: "alpine:3.19",
            bind_rootfs: true,
            runs: 5,
            compare: None,
            json: false,
        };
        assert_eq!(
            box_argv("/k", &a, "n"),
            [
                "/k",
                "box",
                "n",
                "--image",
                "alpine:3.19",
                "--bind-rootfs",
                "--",
                "/bin/true"
            ]
        );
    }
}
