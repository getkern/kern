//! A `.dockerignore` (and kern-native `.kernignore`) matcher for `kern build`, deciding which paths of
//! the build context are EXCLUDED before a `COPY`/`ADD` reads them. Excluding `.git/`, `node_modules/`,
//! `.env`, secrets, and build artifacts keeps images small and - more importantly - stops a stray
//! `COPY . /app` from baking host secrets or the whole VCS history into the image.
//!
//! Docker semantics (deliberately matched, including the traps that surprise `.gitignore` users):
//! - Leading/trailing `/` are STRIPPED - `/build`, `build`, `build/` are the same; there is NO
//!   anchoring like `.gitignore`.
//! - Rules are evaluated IN ORDER and the LAST match wins, so a `!re-include` must come AFTER the
//!   exclude that hid it.
//! - `*` matches a run of non-`/` (one path segment), `?` one non-`/` char, `**` any number of
//!   segments (incl. zero) - so `*.log` is NOT recursive but `**/*.log` is.
//! - A pattern that matches a directory excludes everything under it.
//! - `#` comments and blank lines are ignored.
//!
//! `.kernignore` is a kern-native alias with the SAME syntax; when both files exist its lines are
//! appended AFTER `.dockerignore`'s, so a kern rule can override (last-match-wins) a Docker one.

use std::path::Path;

/// One compiled ignore rule: its `/`-split pattern segments and whether it's a `!` re-include.
struct Rule {
    negated: bool,
    segs: Vec<String>,
}

/// A compiled set of ignore rules for one build context.
pub struct DockerIgnore {
    rules: Vec<Rule>,
    /// True if any rule is a `!` re-include - then an excluded directory can't be pruned wholesale
    /// (a descendant might be re-included), so the walk must descend into it.
    has_negation: bool,
}

impl DockerIgnore {
    /// Load the ignore rules for build context `ctx`: `.dockerignore` first, then `.kernignore`
    /// appended (so kern rules win under last-match). `None` when neither file exists (the caller then
    /// keeps its fast unfiltered copy - no behavior change for the common no-ignore-file case).
    pub fn load(ctx: &Path) -> Option<DockerIgnore> {
        let mut text = String::new();
        let mut found = false;
        for name in [".dockerignore", ".kernignore"] {
            if let Ok(s) = std::fs::read_to_string(ctx.join(name)) {
                found = true;
                text.push_str(&s);
                text.push('\n');
            }
        }
        found.then(|| DockerIgnore::from_str(&text))
    }

    /// Compile ignore-file `text` into a rule set. Public for unit tests.
    pub fn from_str(text: &str) -> DockerIgnore {
        let mut rules = Vec::new();
        let mut has_negation = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (negated, body) = match line.strip_prefix('!') {
                Some(rest) => (true, rest.trim()),
                None => (false, line),
            };
            // Leading/trailing `/` carry no meaning in dockerignore (no anchoring) - strip them, then
            // split into segments. An all-slashes/empty body is skipped.
            let body = body.trim_matches('/');
            if body.is_empty() {
                continue;
            }
            // Collapse redundant separators (`foo///bar` == `foo/bar`) by dropping empty segments.
            let segs: Vec<String> = body
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if segs.is_empty() {
                continue;
            }
            if negated {
                has_negation = true;
            }
            rules.push(Rule { negated, segs });
        }
        DockerIgnore {
            rules,
            has_negation,
        }
    }

    /// Whether the context-relative path `rel` (forward slashes, no leading `./`) is EXCLUDED. Applies
    /// every rule in order; the last one that matches decides (a `!` rule re-includes).
    pub fn excluded(&self, rel: &str) -> bool {
        let path: Vec<&str> = rel
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut excluded = false;
        for r in &self.rules {
            if pattern_matches(&r.segs, &path) {
                excluded = !r.negated;
            }
        }
        excluded
    }

    /// Whether a directory at `rel` can be PRUNED (skipped entirely) during the copy walk: only when
    /// it's excluded AND there are no `!` re-includes anywhere (else a descendant might be re-included,
    /// so we must descend). A conservative, correctness-preserving optimization for the common case.
    pub fn can_prune_dir(&self, rel: &str) -> bool {
        !self.has_negation && self.excluded(rel)
    }
}

/// Whether ignore `pat` (segments) matches context path `path` (segments). A pattern matches when it
/// matches SOME prefix of the path - so a pattern naming a directory (`node_modules`) also excludes
/// everything beneath it (`node_modules/lib/x`).
fn pattern_matches(pat: &[String], path: &[&str]) -> bool {
    (1..=path.len()).any(|k| segs_match(pat, &path[..k]))
}

/// Segment-wise match with `**` (any number of segments, incl. zero) spanning separators; `*`/`?`
/// match within a single segment only.
fn segs_match(pat: &[String], path: &[&str]) -> bool {
    match pat.split_first() {
        None => path.is_empty(),
        Some((head, rest)) => {
            if head == "**" {
                // `**` consumes 0..=path.len() leading segments.
                (0..=path.len()).any(|k| segs_match(rest, &path[k..]))
            } else if let Some((ph, pt)) = path.split_first() {
                wildcard_match(head, ph) && segs_match(rest, pt)
            } else {
                false
            }
        }
    }
}

/// Glob-match a single pattern SEGMENT against a single path SEGMENT: `*` = any run of chars (within
/// the segment), `?` = one char, everything else literal. No `/` ever appears in a segment.
fn wildcard_match(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    // Classic backtracking wildcard matcher (`*` greedy with a fallback star position).
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::DockerIgnore;

    fn ig(text: &str) -> DockerIgnore {
        DockerIgnore::from_str(text)
    }

    #[test]
    fn plain_names_and_directory_subtrees() {
        let i = ig(".git\nnode_modules\n.env\n");
        assert!(i.excluded(".git"));
        assert!(i.excluded(".git/config")); // subtree excluded
        assert!(i.excluded("node_modules/lib/x.js"));
        assert!(i.excluded(".env"));
        assert!(!i.excluded("src/main.rs"));
        assert!(!i.excluded("gitconfig")); // not a prefix of `.git`
    }

    #[test]
    fn star_is_not_recursive_but_double_star_is() {
        let i = ig("*.log\n**/*.tmp\n");
        assert!(i.excluded("app.log")); // top-level *.log
        assert!(!i.excluded("logs/app.log")); // `*` does NOT cross `/`
        assert!(i.excluded("a.tmp"));
        assert!(i.excluded("deep/nested/dir/x.tmp")); // `**` is recursive
    }

    #[test]
    fn leading_and_trailing_slashes_are_stripped_no_anchoring() {
        // `/build`, `build`, `build/` are identical - no `.gitignore`-style anchoring.
        for p in ["/build", "build", "build/"] {
            let i = ig(p);
            assert!(i.excluded("build"), "{p}");
            assert!(i.excluded("build/out.o"), "{p}");
        }
    }

    #[test]
    fn negation_re_includes_and_last_match_wins() {
        // Exclude all logs, but keep important.log - the `!` MUST come after.
        let i = ig("*.log\n!important.log\n");
        assert!(i.excluded("debug.log"));
        assert!(!i.excluded("important.log"));
        // Order matters: a later exclude beats an earlier negation.
        let j = ig("!important.log\n*.log\n");
        assert!(j.excluded("important.log"));
        // Re-include a whole subtree path.
        let k = ig("node_modules\n!node_modules/keep/**\n");
        assert!(k.excluded("node_modules/x.js"));
        assert!(!k.excluded("node_modules/keep/a/b.js"));
    }

    #[test]
    fn comments_blanks_and_prune_flag() {
        let i = ig("# a comment\n\n  .git  \n");
        assert!(i.excluded(".git/HEAD"));
        assert!(i.can_prune_dir(".git")); // no negations → prunable
        let j = ig(".git\n!.git/keep\n");
        assert!(!j.can_prune_dir(".git")); // a negation exists → must descend
    }

    #[test]
    fn redundant_slashes_and_degenerate_lines() {
        // Redundant separators collapse (`foo///bar` == `foo/bar`); a `///`/`!`/`#`-only line makes
        // no rule (and must not panic or match everything).
        let i = ig("//foo///bar//\n");
        assert!(i.excluded("foo/bar"));
        assert!(i.excluded("foo/bar/x"));
        let j = ig("///\n!\n#\n   \n");
        assert!(!j.excluded("anything"));
        // `**` in the middle, and a single-`*` segment matching exactly one path segment.
        assert!(ig("foo/**/bar\n").excluded("foo/x/y/bar"));
        assert!(ig("a/*/c\n").excluded("a/b/c"));
        assert!(!ig("a/*/c\n").excluded("a/b/x/c"));
    }

    #[test]
    fn nested_path_pattern() {
        let i = ig("foo/bar\n");
        assert!(i.excluded("foo/bar"));
        assert!(i.excluded("foo/bar/baz")); // subtree
        assert!(!i.excluded("foo")); // parent not excluded
        assert!(!i.excluded("foo/other"));
    }
}
