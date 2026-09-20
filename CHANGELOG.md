# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

## Unreleased

**kern no longer answers to `docker`.** A symlink named `docker` or `docker-compose` used to make
this binary rewrite a Docker command line into kern's own and run it. That is gone, with the 1330
lines behind it. The compatibility kern offers is with the FORMAT and the FLAGS, which is untouched:
`kern box` still takes `-p`, `-e`, `-v`, `-it`, `-m` and `--cpus`, and `kern compose` still reads a
`docker-compose.yml` unchanged, which is what Sentry's 57 services and Supabase's 13 run on. What
went is borrowing the other tool's name, which added nothing a caller could not get by typing `kern`
and cost what borrowed names cost: a benchmark on this machine measured kern, published the row as
`docker run --rm  4.2 ms`, and put it beside a real podman at 285 ms. A `docker` symlink now simply
runs kern, with kern's grammar and kern's errors.

**`--mount readonly=1` mounted the path WRITABLE, silently.** The value was compared against the
literal `true`, so every other spelling the reference honours fell through to writable with no
error. MEASURED value by value on Docker 29.1.3: `readonly=1`, `readonly=t`, `readonly=TRUE`,
`readonly=true` and a bare `readonly` all mount read-only, `readonly=false` mounts writable, and
`readonly=yes` is refused outright. kern honoured exactly one of them. This is the worst shape a
compatibility gap can take: the flag that asks for LESS privilege is the one that silently granted
more. The whole Go boolean set is now read, and a value outside it is refused rather than taken as
false.

**`--mount type=tmpfs,dst=/x,readonly` mounted writable.** Docker honours it; kern's `--tmpfs` spec
is `path[:size]` with no read-only form, so the key was parsed and dropped. Refused by name, which
is the rule this same release applied to `volume-label=` and had not applied here.

**`images <repo>` was dropped whenever a flag came first.** `images --filter dangling=false alpine`
and `images --format '{{.Tag}}' alpine` listed the ENTIRE cache with no error, because the scan
stopped at the first bare token instead of skipping past the flag that consumed it. It now uses the
same one-positional scan `login` uses, and a second name is refused as Docker refuses it.

**`network inspect -f '{{.Name}}' proxy` inspected a network called `{{.Name}}`.** Flag-first is an
order the reference accepts and the name scan did not skip flag values.

**`inspect --format` printed a label's control bytes raw, where `ps --format` strips them.** Two
renderers of one caller-supplied value disagreed about whether it reaches the terminal intact; one
of them was a terminal-injection surface.

**`{{json .Name}}` printed `/web` where Docker prints `"/web"`.** The `json` pipeline was stripped
as a wrapper for every key, including the scalars, so a value that should be JSON was not. An
earlier comment dismissed this as a shape nobody asks for, which was wrong: `{{json .State.Status}}`
is a common one, and the failure lands on the parser downstream rather than on the eye.

**`pull --quiet` parsed and did nothing.** It was added to the accepted-flag list and carried
nowhere, which is the no-op flag this CLI refuses everywhere else. It now suppresses the three
orientation lines and keeps the reference.

**A label whose value contained a comma became two labels, and the filter was wrong in both
directions.** The registry stores labels as one comma-joined `k=v` field, and the join was
unescaped, so `--label 'a=b,c=d'` was indistinguishable from two labels. MEASURED against both
reference implementations on this machine, which agree with each other and not with what kern did:

```text
  docker 29.1.3  inspect --format '{{json .Config.Labels}}'   {"a":"b,c=d"}
  podman         inspect --format '{{json .Config.Labels}}'   {"a":"b,c=d"}
  kern 0.9.35    ps --json .labels                            {"a":"b","c":"d"}
```

The read-back is the harmless half. `kern ps --filter label=c=d` MATCHED a box that had never
carried that label, and `--filter label=a=b,c=d`, the label it did carry, matched nothing. A filter
that reports a false positive is one an operator acts on. The separator and backslashes are now
escaped on the way in and decoded on the way out by one encoder and one decoder, and newlines go
with them because the registry record is line-delimited.

**`--label <bare key>` is accepted, and the message that refused it cited a rule that does not
exist.** The code required the `=` and called it "Docker's own rule". Measured: the reference
accepts `--label noequals` and renders `{"noequals":""}`. What is still refused is a leading `=`, an
empty key that names nothing and no filter can match.

**`--rm` and `--restart` were both applied.** `kern box --rm -d --restart always` started a box
supervised to come back forever and printed `restart=always - survives reboot`, which is the
opposite of what `--rm` asks for. The reference refuses the pair; so does kern now.

**`--mount` is parsed as CSV, not split on every comma.** The reference parses this value as CSV, so
a field may quote itself to carry a comma, and `--mount 'type=bind,"src=/a,b",dst=/x'` is valid
there (measured on Docker 29.1.3). kern answered the generic usage error, so a path containing a
comma could not be mounted through this flag at all.

**Docker's other `--mount` keys are refused BY NAME.** `bind-propagation`, `bind-nonrecursive`,
`volume-nocopy`, `volume-driver`, `volume-opt`, `tmpfs-mode` and `consistency` are each valid where
a caller copied them from, and kern has no knob behind any of them. They were already refused, by
the generic grammar dump, which is the right outcome reached with the wrong sentence: the reader was
handed the whole grammar and left to diff it by eye against what they wrote. A genuine typo still
gets the grammar, which is what a typo needs.

**`kern create` now names the route instead of only the missing verb.** `docker create` + `cp` +
`start` is how people seed files into a container before anything runs, and kern has no stopped box
to copy into, because `kern cp` enters the namespaces of a live PID 1. The hint points at `-v`,
`--tmpfs` and `--secret`, which is where that content goes here.

**`box --mount` and `box --name`, measured rather than guessed at.** The argv that an agent-sandbox
harness builds around a container runtime was read off a real one and each flag EXECUTED against the
published binary: of fifteen, twelve were already accepted under the same spelling and three were
not. Two of them land here.

  * `--mount type=bind|volume|tmpfs,src=…,dst=…[,ro]` is the named-field spelling of `-v` and
    `--tmpfs`, which is the form generated command lines emit. It is a TRANSLATION into those two
    flags and not a second mount path, so a `--mount` and the `-v` it equals cannot start behaving
    differently. A `type=` that disagrees with its `src` is REFUSED rather than reinterpreted:
    `type=bind,src=data,dst=/app` would have mounted an empty auto-created named volume, silently,
    because a bare source is a volume name and not a path.
  * `--name <box>` is Docker's spelling for the name kern takes positionally. The same field, so
    passing both is a usage error rather than a precedence rule: a line that says two things about
    one box has no reading that is not a guess.

**A label went in, could be filtered on, and never came back out.** `--label k=v` was recorded, and
`--filter label=` matched it on `ps`, but no surface printed it: `ps --json` and `inspect --json`
carried no such field and `--format` had no token for it. A caller could therefore tag a box and
then be unable to read its own tag back, which is the write-only half of a round trip.

  * `ps --json` and `inspect --json` now carry `labels` as an OBJECT, not the registry's
    comma-joined text: a consumer that has to re-split a string is doing the parsing the document
    exists to avoid. `{}` where Docker emits `null`, so an iterating caller gets an empty loop
    instead of a type error.
  * `ps --format` and `inspect --format` take `{{.Label "key"}}` and `{{.Labels}}`. An ABSENT key
    prints empty, as Docker's does, because the token exists to be paired with `--filter label=`,
    which has already proven the key is there; a missing quote is still an error, because that is a
    typo and not an absent label. Exited boxes keep no labels (the instance record is pruned and
    the breadcrumb carries only name/pod/command), so the token renders empty there rather than
    failing the row.

**`box --rm`, `network inspect` and the `image` verb group.** The rest of the measured gap.

  * `--rm` leaves no exit record: `kern ps -a` will not list the box and `kern wait` has nothing to
    read, exactly as `docker wait` has nothing to read for a container that removed itself. A box
    was ALREADY thrown away (its scratch and registry entry go at teardown); the hour-long
    `waitexit` breadcrumb was the only residue, and this drops it. On a detached box the supervisor
    does not write it at all rather than writing and deleting it, because that box outlives the
    command and a record that exists for a while is one `kern ps -a` can report. The compose exit
    key is NOT suppressed: it is a different record, read by `compose up`, and a one-off's `--rm`
    must not make a stack lose a service's status.
  * `network inspect <name> [--json] [-f T]` reports what kern actually holds: the `/24` its members
    are addressed from, and who is on it. `{{json .IPAM.Config}}` is answered because that block is
    real. `Gateway`, `Driver` and `Options` are ABSENT and not empty, because members reach each
    other over loopback aliases and nothing routes; emitting them as `""` would answer a script's
    question with a guess. A name that does not exist is REFUSED and named, so a script reaching for
    a default `bridge` (which kern has none of) fails instead of reading an empty document as an
    empty network.
  * `image ls|inspect|rm|pull|push|tag|history|save|load|build` is Docker's noun-first grouping,
    rewritten onto the verbs kern already has, so there is one parser per operation and this only
    chooses which. `image prune` is deliberately NOT aliased onto `kern gc --images`: Docker prunes
    dangling images by default and `gc --images` clears what no box references, which is a wider
    sweep, and on a verb whose whole risk is deleting too much the nearest thing is not the same
    thing.

**`images <repo>`, `images --format`, `pull --quiet`.** The last of the surface a caller arriving
from Docker types. `images <repo>` is the positional name filter, mapped onto
`--filter reference=<repo>` rather than given a field of its own, so the two spellings cannot select
different images; giving both is refused, because that command line has named two sets.
`images --format` renders the fields the cache holds and refuses the rest by name: there is no image
ID here and no creation date, only when this machine pulled it. `{{.Repository}}`/`{{.Tag}}` split
at the last colon only when what follows carries no `/`, so `localhost:5000/app` stays one
repository instead of becoming a repository and a tag that do not exist.

**`--mount volume-label=` is refused by name, not dropped.** It is a real Docker key, and kern's
named volumes carry a size quota and a creation time and nothing else. A label accepted and
discarded is one a later `--filter` will never match, so the message says which half is missing and
points at `--label`, which kern does record and filter on.

**`kern wait` was diagnosing a cause it could not know.** A box that left no exit record was
reported as "a foreground or -it box has no supervisor to capture one". With `--rm` that assertion
became wrong: a caller who had explicitly asked for no record was told its box ran in the
foreground. There are three causes and the record that would say which is the one that is missing,
so the line now names all three instead of picking one.

**`inspect --format` answers `{{json .NetworkSettings.Ports}}` and `{{json .Config.Labels}}`.** The
published-port map is how a caller learns where a service it just started is actually reachable, and
on a rootless runtime it is the one thing it cannot assume: kern republishes a privileged port above
1024, so a caller that trusts the number it asked for is wrong. The shape was MEASURED on Docker
29.1.3 rather than recalled, and four of its details are the kind an implementation from memory
gets wrong: the key is the port INSIDE the box with its protocol suffix (`"80/tcp"`), the value is
an ARRAY because one container port can be published on several addresses, `HostPort` is a string,
and the capitalisation is `HostIp` with a lower-case `p`. The `{{json …}}` pipeline is accepted as a wrapper on both.

**This release changes two flags that already existed, so it is a MINOR and not a patch.** The
stability note above says an incompatible change to a verb, a flag or a `--json` shape lands only on
a minor bump, and only after a deprecation entry one release earlier. There was no such entry and
there could not have been: both behaviours were defects, and announcing a defect for a release
before fixing it would leave the broken one in the field on purpose. The two:

  * **`-i` no longer allocates a pseudo-terminal**, on `box` and on `exec`. `-t`/`-it` do. A script
    that used `-i` to get a terminal must now say `-t`; every script that used it the way docker
    means it - `exec -i <box> psql … < file.sql` - stops hanging.
  * **`inspect --format` refuses a name kern holds no record of**, where it used to print `exited`
    and exit 0. A wait loop testing for `exited` ended immediately on a misspelled service and the
    script carried on as though the step had completed.

Everything else here is additive: new verbs, new flags, and fields added to `--json` documents that
consumers already have to ignore when unknown.

**A registry could reorder the line kern printed, without using a single control character.** The
three filters that scrub remote text before it reaches a terminal all tested `char::is_control()`,
which is the `Cc` category: C0, DEL and C1. The bidirectional overrides are `Cf`. Measured against a
hostile registry on loopback: `kern pull` carried U+202E, U+200B, U+200E and U+200F from the token
endpoint's `message` straight to the terminal, while correctly dropping ESC and carriage return. A
filter written against escape sequences, defeated by something that is not one. U+202E moves no
cursor; it reverses the order the characters after it are drawn in, which is enough to make a
refusal read as something else. One predicate now decides the rule for all three, and it names what
it removes rather than dropping a whole Unicode category.

The same body also had no length: 1 MB of a registry's own text reached the terminal, and curl's cap
allows eight. A diagnosis is a sentence, so it is capped at 200 characters with the overflow
announced, because a silently truncated message reads as the registry's whole answer.

`sh pentest/pentest-hostile-registry.sh` is the reproducer and is now part of `run-all.sh`. It found
this where a unit test could not: a test asserting "a registry message cannot inject terminal
escapes" had passed for as long as it existed, because it listed the characters somebody had thought
of. The suite is verified in both directions, red against the previous binary.

**A trailing backslash in a `command:` deleted a character, and sometimes an argument.** `command:
myapp C:\dir\` ran `myapp` with `C:dir` - the final backslash was read as an escape with nothing to
escape and dropped, and a `command:` that ENDED in a lone backslash lost that word entirely. POSIX
leaves the case unspecified because a shell reading a terminal asks for another line; there is no
next line in a compose file, and dash, bash and busybox ash all treat it as a literal. kern now
does too. FOUND BY AN ORACLE, not by a test: the exhaustive loop over 46656 inputs asserted only
that the splitter terminates, which no wrong split can violate, so the whole space is now put to
`/bin/sh` itself and compared word for word - 17523 of the inputs are valid shell and every one of
them must agree. The hand-written assertion for this case had encoded the wrong answer, and only an
authority outside the test could say so.

**`compose push` exited 0 having published nothing.** A service is pushed only when it declares
both `build:` and `image:`, which is right; every service that did not was announced as skipped and
the verb still reported success, so `compose push && deploy` deployed after publishing nothing. A
run that publishes at least one image is still a success even if it skips others. A run that
publishes NONE now says so with a status, and names the rule it applied.

**`ps --last N` printed the newest box last.** The flag asks a question about recency and the rows
came back oldest-first: the cut was made on one ordering and the rows were then rendered in
another, the registry's. Boxes created inside the same kernel tick also fell back to whatever order
the directory was read in. `--last` now renders newest-first and breaks a tie on the name, so the
same boxes give the same order every time. Plain `ps` is unchanged and still lists oldest-first.
The resolution is the kernel's: two boxes started within one tick are not ordered by this flag, and
nothing here claims otherwise.

**A pod name reaching the JOIN path was not validated, only the one reaching CREATE.** `pod create`
has always checked the name against the shared resource-name rule, because it becomes a directory;
`--pod <name>` took it straight from argv and handed it to `pods_root().join(name)` with nothing in
between, and `--network <name>` gave that path a second entrance. Nothing escapes in practice - the
join then requires `<dir>/holder` to hold a live pid AND `<dir>/netns` to match that process's
namespace inode, a conjunction an arbitrary directory does not satisfy - so this closes an asymmetry
rather than a hole. It is worth closing anyway: a name that cannot NAME a pod should be refused as a
name rather than as a lookup that happened to find nothing.

**`compose images` takes `--format json`, as `compose ps` does, and stopped calling an image nobody
has ever pulled "dangling".** The two verbs sit next to each other and a script reading one reads the
other, so a table where the other has JSON is the gap `ps --format` already closed once. The state is
now named: `cached`, `dangling`, `absent`, or `build` for a service with no `image:` to name. The
order of those three questions was wrong and had been: `image_stat` answers "dangling" for an image
with no payload, and an image that was never pulled has no payload either, so a ref nobody had
fetched was reported as a BROKEN local image - sending a reader to `rmi` something that does not
exist instead of to `pull` something that does.

**`kern build --check`: what kern does with a Dockerfile, without building it.** `compose config`'s
sibling. It parses the file the way a real build resolves it (Containerfile first, the same
`-f`/`--build-arg`) and prints a verdict per instruction: honoured, or DROPPED with what happens
instead. Nothing is pulled, no box starts, and the exit code is the answer - 0 if the file builds
here, non-zero carrying the refusal, so it can gate somebody else's CI. The question it answers is
the one nobody could answer without reading kern's source: "will my Dockerfile build here, and is
there a line kern will quietly not act on?" - and a build answers it only after downloading a base
image and running half the file.

A `COPY` from the context is CHECKED and not merely listed, because "this builds here" has to mean
it: the first version reported `builds here, and every line it contains has an effect` for a file
whose opening `COPY ../../etc/passwd` the build then refused, which is the one answer a gate must
never give. The rule is the copier's own, lifted out of it so the dry run can ask the question
without performing the copy. A glob and a `COPY --from` are left to the build: one names no file
until a directory is read, the other a filesystem that does not exist until that stage is built, and
refusing something that works is the worse of the two errors.

The report comes from the PARSER'S OWN instruction list, never from a second scan: a separate
scanner would be a second opinion about what a Dockerfile says, and two opinions drift. That is also
why `VOLUME` now leaves a trace instead of vanishing - it was dropped in the parser with a comment
and no output, so the build said nothing, the image said nothing, and only kern's source recorded
that the line had no effect. A real build now says it too, one line, at the step.

**`compose down -v` could not remove the one volume every stack has.** A volume carries the
ownership of whatever wrote it, which rootless means a SUBUID: `postgres:17` writes its data
directory as uid 999 inside the box, 100998 on the host, and an unprivileged caller cannot unlink
inside a directory that uid owns. `kern volume rm` has used the id-mapped remover for exactly this,
in a comment naming exactly this case, since before `down -v` existed; `down -v` used a plain
`remove_dir_all`. Two removers, one rule, and the one on the path everybody uses had drifted.
MEASURED on a ten-service stack: `down -v` answered `Permission denied (os error 13)` on
`<project>_postgres_data` and the error ended the loop, so the three volumes after it survived too -
a `reset.sh` reporting a reset that had removed nothing, and the next `up` reusing the old database,
which is the exact failure project-scoped volumes were introduced to end.

**An image's `LABEL`s are read, on both paths that produce an image.** The pull path did not parse
`config.Labels` and the build path discarded `LABEL` at the parser with a comment saying "metadata -
parsed and ignored", which described a gap rather than a decision: `docker images --filter label=`
cannot answer for an image whose labels were thrown away, and `org.opencontainers.image.*` is where
a build records its source and its version. `MAINTAINER` is recorded as `LABEL maintainer=`, which is
what Docker does with it. `images --filter` now takes all five of Docker's keys: `reference=`,
`dangling=`, `label=`, and `before=`/`since=`, the last two relative to another image's cache time -
the same value the PULLED column prints, so the filter and the column cannot disagree.

**`compose push` would have published images the file did not build.** The first version pushed
every service carrying an `image:`, which on an ordinary stack means `postgres:17` and
`rabbitmq:3-management` - images the file merely names and the cache merely pulled. MEASURED on a
two-service file: it went straight at `postgres:17` and got as far as squashing it before failing for
an unrelated reason; with credentials and a writable namespace it would have succeeded, publishing
somebody else's image under your name from a verb whose author expected it to publish theirs. `push`
now publishes what the file BUILDS: `build:` says the bytes are this project's, `image:` says where
they go, and a service with one and not the other is named as skipped.

**`compose wait` exited 0 whatever the service did.** The entire use of the verb is
`docker compose wait tests` in a CI job that branches on the status, which Docker documents as the
exit code of the first container to stop; printing the numbers and exiting 0 reports every failing
suite as a pass. The services are now polled together rather than in file order, since "first to
stop" is not "first in the file". `kern wait <box>` still prints and exits 0: it is older, its
contract is frozen with the CLI, and a script already reading its stdout is correct. The two are
spelled differently on purpose.

**`ps --last N` answered a different question from Docker's.** It ordered on "how long ago did this
box last do something" - `now - started` for a live one, `exited_ago` for a dead one - which are two
questions wearing one name: a box created an hour ago and finished a second ago came out NEWER than
one created a second ago. It now orders on the kernel start-time, the one clock both records hold and
the one that means CREATED, so `-n 2` is the two most recently created across both lists.

**`images --filter reference=alpine` matched nothing while `kern images` listed three.** A pattern
naming no tag now matches any tag; one that names a tag is still matched whole. Stated as kern's
rule rather than Docker's: this was not put to a daemon, and the reference filter's exact behaviour
there is not something this repository has measured.

**`up --no-deps` waited out its whole timeout on a dependency that had already completed.** A
condition is keyed to the run that satisfies it, which is right for an ordinary `up` and impossible
under `--no-deps`: the caller has said the dependencies will not be started, so requiring a
completion under THIS run's token asks for something that can never happen. MEASURED on the line a
real rebuild script runs, `up -d --build --force-recreate --no-deps <service>` against a stack
already up: kern waited 120 seconds and reported `timed out waiting for 'setup' to complete` about a
service that had completed minutes earlier and was sitting in `kern ps -a` with exit 0. Under
`--no-deps` the question is now "has it completed, ever, as far as kern still knows", answered from
the same exit record `kern ps -a` and `kern wait` read; and a condition that nothing in this
invocation can satisfy is refused AT ONCE, naming the flag, instead of being waited out.

**A new gate runs a real deployment's command shapes against a real stack.**
`scripts/deployment-cli-battery.py` brings up a three-service stack and runs the 42 distinct
command lines one deployment's scripts, `package.json` and CI actually contain - verbatim, because
a green line means the script needed no edit - plus the four `build:` shapes a compose file declares
and the token chain a real rebuild script wraps around them,
checking each one's exit code and output. It exists because the compose-compat rate measures what
kern does with a FILE, and every defect this release fixes was in the commands wrapped AROUND the
file, where no corpus was looking. It found one on its first run, the `--no-deps` timeout above.

**Eight `docker compose` verbs that did not exist: `wait`, `events`, `images`, `push`, `rm`, `top`,
`version`, and `kill`.** Seven are the box-level verb kern already had, scoped to one stack, which is
the shape `compose ps` established; `kill` is `stop` under the name Docker gives the harder one, and
inherits kern's existing statement that the grace comes from `--stop-timeout` rather than being
skipped. `top` reads the CGROUP rather than running a `ps` inside the box, so it answers for a
distroless or `FROM scratch` service too. `rm` removes what kern actually has to remove, the exit
record that keeps a finished service in `kern ps -a`, and refuses while a selected service is still
running. `create` and `scale` are now refused BY NAME with the reason the concept is absent: both
used to fall through and be read as a service name, so `compose f.yml create` answered "no such
service: create" and sent the reader to look for a service nobody wrote.

**`logs --since` and `--until`, on a box and on a stack.** The window is read from the timestamp
index `logs -t` already prints from, and takes the three spellings Docker takes: a duration back from
now (`30s`, `1h30m`), unix seconds, or RFC3339 UTC - the last of which is exactly what kern's own
`logs -t` prints, so its output feeds straight back in. A line the index cannot place in time is
KEPT: the index buckets from 100 ms and a log written before it existed has no marks at all, so
discarding what cannot be placed would silently lose real output. A value that does not parse is
refused with the three forms named, because a misread time shows the wrong window and wrong output
looks like output. `compose logs` also gains `-t` and `--no-log-prefix`; `-t` is two flags there and
the verb decides which, as it does under Docker (`logs -t` is timestamps, `down -t 30` is a grace).

**`ps --filter health=`, `ps --no-trunc`, `ps --last N`, `images --filter`, `stats --no-stream`.**
`health=` is the one a readiness loop writes, and it reads the health VERDICT rather than the merged
status column, so a paused box with a passing check is still `healthy` here; `none` is the box that
declares no healthcheck, which an empty string cannot express in a `k=v` filter. `--last N` counts
across live AND exited boxes on one ordering, because "the last N containers" is one question, and it
implies `-a`. `images --filter` takes the two keys the cache can answer (`reference=` with `*`,
`dangling=`) and refuses the others by name rather than accepting a filter that silently matches
everything. `stats --no-stream` names what kern has always done: a daemonless runtime has no stream
to tail, and `kern top` is the live view. `volume ls` and `network ls` take `--format json` as a
second spelling of `--json`; any other template is refused rather than printing a human table to a
caller that asked for fields. `cp -a/--archive` is refused with its reason: it preserves uid/gid, and
a rootless copy crosses a subuid range where the box's uid 999 is the host's 100998.

**`kern inspect --json` carries `status`, and one function decides that word everywhere.** The
document held `health`, which is empty for the majority of boxes, and not the field a script reaches
for first. `ps`, `inspect` and `inspect -f` now read one function for the word, which fixes what none
of them said before: a PAUSED box reported `running` from `inspect` while `kern ps` reported
`paused`, because `inspect` tested the health verdict for a word the health verdict never contains.

`inspect` still reports a box WHILE IT RUNS. A box that has exited is refused, by name and with its
code, pointing at `kern ps -a`; the value a script wants from it is served by `inspect -f
'{{.State.ExitCode}}'`, which reads the same exit record.

**`kern rmi` charged the image you named for somebody else's debris.** The orphan-layer sweep is
cache-wide, because that is the only way to find a layer whose last referrer has just gone, and every
byte it reclaimed was added to the "freed N" line. MEASURED on a working cache: one image built under
two names, `rmi` of the first printed `freed 140.3M`, `rmi` of the second printed `freed 140.3M`
again, and `du` on the layer store was unchanged across both - 280 MB claimed, nothing reclaimed. The
sweep still takes every orphan it finds, because the cache's health is not the caller's arithmetic;
only the layers the named image's own manifest listed are charged to it. With `-t` now repeatable,
two names for one image is the ordinary case on every release.

**`kern box --network <name>` joins a running pod, which is what a stack is.** `docker run --rm
--network <stack-net> <image> <cmd>` is how a one-off talks to a running stack: generate a token,
seed a database, run a migration. kern answered `--network <host|none>`, a usage line naming neither
of the two joinable things it has. A name now reaches the same slot `--pod` fills, and what the name
IS gets decided where the registry is already being read rather than in the parser: a running pod is
joined, a `kern network` is named as the different object it is (a compose file declares it
`external: true`; a single box cannot join one), and a name that is neither lists the pods that are
running.

**The teardown note contradicted the line four rows above it.** A stack whose services start and then
exit printed `compose up: 2 box(es) started.` and then `removed pod 'x' again: no service started, so
it held nothing`. The guard's condition is "does the pod hold anything NOW" and its sentence said
"nothing ever started", which are different statements that agree only when nothing did start. The
bring-up now tells the guard how many it started, so the two cases are said separately: nothing came
up, which sends a reader to the errors above, or everything that came up has already finished, which
sends them to `kern ps -a`.

**`up --force-recreate`, `up --no-recreate` and `up -V/--renew-anon-volumes` are honoured.** They
were refused, and the first of them ends a real rebuild script on its own line
(`up -d --build --force-recreate --no-deps <service>`, after a step wrote a file the definition does
not hash). kern's `up` compares a fingerprint and leaves a service whose definition still matches
running, which is Docker's default and the right one; these are the two overrides of that comparison,
and both are total, so neither can be defeated by a box that carries no fingerprint. Writing both at
once is refused by name rather than resolved by precedence. `-V` discards the anonymous volumes of
the services this `up` STARTS, not of the ones it leaves running: kern names an anonymous volume from
the service and its mount path instead of a random id, which is what makes it persist across `up`,
and the wider reading would delete storage from under a service nobody asked to touch.

**`kern compose <verb>` finds the file, like `kern up` already did.** `docker compose up -d` is
written from the directory that holds the file, and the verb form answered a usage dump naming a
positional `<file>` it did not have to require. The same four Docker names plus `kern.toml` are
searched, and the refusal when none is there now lists every name it tried (the hand-written sentence
had already drifted and omitted `docker-compose.yaml`). A bare `kern compose` still prints usage:
discovery answers which file, not which verb.

**`kern port <box> [<container-port>]`.** The compose form has answered this for a stack for some
time and the bare one did not exist, so a script holding a box name had nowhere to ask. It reads the
RUNNING box rather than the file, so it reports what was actually bound, which on a rootless runtime
is the whole point (a privileged port is republished above 1024). With no port it lists every mapping
in Docker's `<port>/<proto> -> <address>` form; `/tcp` or `/udp` narrows to exactly that protocol.
The compose verb now shares its selection code, so the two cannot drift.

**`inspect -f` is accepted, and no longer answers for a box that does not exist.** `--format` was
implemented and `-f`, the spelling every wait loop uses, was `unknown flag`. Worse, the lookup was
"is it running?", so every name that was not running rendered `.State.Status` as `exited` with exit
status 0: `until [ "$(kern inspect -f '{{.State.Status}}' setup)" = exited ]` ENDED IMMEDIATELY on a
misspelled service and the script carried on as though the step had completed. A name kern holds no
record of is now refused, and `.State.ExitCode` was added, since the question after "did it finish?"
is "did it finish well?".

**`kern login` checks the credentials before it stores them, and has a real `--password-stdin`.** It
stored whatever it was given and printed `logged in`: a deliberately wrong password for Docker Hub
was accepted and written over the existing entry, which holds one credential per registry. Two things
followed, and both were live: a CI job that pipes a token in continues on exit 0 and discovers an
expired one several steps later at the `push`, and a typo replaces a working credential with a broken
one. The pair is now verified against the registry through the same challenge the pull path uses, the
registry's own diagnosis is carried through, and nothing is written unless it is accepted. Login's
flags are also checked now: `--password-stdin` was read by nothing and appeared to work because stdin
is read anyway when it is not a terminal, so a misspelling would have behaved identically.

**A `command:` carrying an escaped quote was silently truncated.** Inside a quoted string the
splitter had no case for a backslash, so `\"` ENDED the string instead of escaping a quote in it, and
everything after it was split on whitespace and handed to `sh` as positional parameters instead of as
part of its `-c` script. A real stack found it: a service whose script prints
`echo \"…retry $i…\"` and then runs `nginx -g 'daemon off;'` printed the first two words, exited 0,
and never started nginx, with no warning at any layer. The backslash now follows POSIX in each of the
three contexts it means something different in: unquoted it escapes the next character and continues
a line, inside single quotes nothing is special, and inside double quotes it escapes exactly `$`,
`` ` ``, `"`, `\` and a newline while staying literal before anything else, so `"C:\path"` and
`"\n"` still reach the workload unchanged.

**`exec -i` allocated a pseudo-terminal, so `exec -i <box> psql … < file.sql` never returned.** `-i`
and `-t` were one flag. A PTY echoes its input, rewrites `\n` as `\r\n`, and never receives the EOF a
redirected file cannot send, so the canonical way to feed SQL, a migration or a fixture into a
running service hung and corrupted its own output on the way. They are now two flags, as they are on
docker: `-t`/`-it` allocate the terminal, `-i` keeps stdin attached and allocates nothing. stdin was
always inherited, so `-i` names what already happens and nothing else changes. `kern box` takes the
same split, for `run -i img < file`.

**`build -t a -t b` kept only the last name.** Both flags parsed, the second won, nothing was said.
A release pipeline writes `build -t repo:$VERSION -t repo:latest .` and pushes each name, so the
`push repo:$VERSION` on the next line failed on an image that had never existed. `-t` is now
repeatable and every name is applied to the finished image through the same content-shared path
`kern tag` uses, which references layers rather than copying them: N names cost one build and one
manifest write each. Every name is validated when it is read, so an invalid fourth `-t` is refused
before the build is paid for, and a name that cannot be applied fails the command rather than
warning, because the caller's next line is a `push` of exactly that name.
**`kern compose --help` ended with two lines about networks.** They are the tail of `network create`
in the full reference, and they were printed under `compose ps` as though they described it, because
the per-verb filter read a line's first word before its indentation and that continuation begins
"compose file names with `external: true`". A per-verb help now carries only lines that belong to the
verb, and three signatures that lacked the double space separating a command from its description
got it, so `kern box --help` no longer shows `compose cp` for ending its sentence with "the box".

**The GPU row in `kern doctor` is no longer a warning, and fits on the screen.** It fired on every
host with any DRM node, which on a Raspberry Pi or a Jetson is a display core, and carried four lines
of MIG and SR-IOV vocabulary about the strength of a cap this binary has no flag to request. The card
and its tier are one line now with the qualification under it, and the full statement is printed
where a GPU is actually handed over: `kern box ... --plan`, under a profile that grants a render node.

**Three other `doctor` rows were a paragraph wide.** A passing row had nowhere to put a qualification
but the first line, so SELinux and systemd lingering ran to 169 and 181 characters while every
warning stayed under 70. A passing row takes a second line now, as a warning always could.

**The CPU topology a box sees was built in its overlay upper, and paid for twice.** `/sys/devices/system/cpu/cpu0`
through `cpuN` plus `online`/`possible`/`present` were written into the host-visible upper layer on
every start and unlinked again at teardown, and that teardown is on the caller's path: 404 of the 405
syscalls a box makes after its workload has already exited were that recursive delete, 14% of the wall
of a `--rootfs` start. They are on a tmpfs now, freed with the mount, which is the treatment `/dev` has
always had and why `/dev` was one entry in the upper where `/sys` was thirty-seven. The upper goes from
46 entries to 9, and a paired core-pinned run measures **148.7 us** faster, interval [+94.9, +210.0].
Behaviour is unchanged and pinned by a test: `nproc --all` and a tool counting `cpu[0-9]*` directories
both still see the cpuset. Best-effort with today's behaviour as the fallback, so a host that refuses
the mount still gets the topology.

**That same loop then re-resolved a ten-deep path once per CPU.** Every `cpu<N>` directory was created
through an absolute path, so a 28-way host made the kernel walk
`/run/user/1000/kern/scratch/<box>/merged/sys/devices/system/cpu` twenty-eight times and allocated a
string for each one. The directory is opened once now and each name goes to `mkdirat` from that
descriptor, written into a fixed buffer with no allocation: `mkdir` calls per box start go from 51 to
23, and a paired core-pinned run measures **10.6 us** faster, interval [+3.8, +16.8]. The old form
costs more the more cores a host has, since it pays that walk once per CPU. A host where the open
fails still gets the previous path. Behaviour is unchanged and pinned by a test that reads from inside
a box: a list cpuset of `0,2,4-6` yields exactly `cpu0 cpu2 cpu4 cpu5 cpu6`, no gaps filled and no
extras.

**`kern diff` answered "what did this box change?" with 41 lines of kern's own setup and none of the
box's.** Measured on the shipped binary: a box whose whole workload was `touch /tmp/mio.txt` listed
`/dev`, `/etc/hostname`, `/etc/hosts` and thirty-six lines of `/sys/devices/system/cpu/cpu0` through
`cpu27`, written by the CPU-topology setup on every start. The one real write went to a tmpfs and
never reached the overlay upper, so the signal was not buried, it was absent: the verb was 100% noise.
The upper is now stripped of what kern itself writes, and then of any directory left childless BY THAT
REMOVAL, so the lone `C /etc` a naive filter leaves behind goes too. `/etc` is not treated as kern's:
a workload writing `/etc/passwd` is a real change and still appears, and so does an empty directory the
workload made, because a directory is dropped only when every child it HAD was scaffolding. A test
asserts the property against a real box rather than the list, so the next piece of setup turns it red
by existing.

**The SDK paid a quarter of every cold box for a uid range its own posture made useless.** `kern box
--image` maps a sub-uid range by default, so that an image degrading privilege in its entrypoint
(postgres, nginx, apt's `_apt`) works; mapping it forks the two setuid helpers `newuidmap` and
`newgidmap`. Measured: `parent:idmap` is 22 us with a single-uid map and ~1048 us with the range, and a
box on the SDK's own argv goes 4298 to 3234 us, a paired core-pinned difference of **1083 us (25%)**,
interval [-1184, -952]. It bought that box nothing, and that is measured rather than argued:
`os.setuid(1000)` inside a cell is refused either way once `ALL` is dropped, EPERM with the range and
EINVAL without, because the capability the range serves is already gone. `pip install --target` with
network on installs the same files either way, and an image whose files are not root-owned
(`postgres:16-alpine`, `node:20-slim`) reads the same. So both bindings now pass `--no-uid-range`,
CONDITIONALLY: only when `ALL` is among the dropped capabilities, which is the default. `cap_drop=()`
is a documented choice that keeps the capabilities, and there the range does work, so it is kept - a
narrower set is treated the same way. A test fails if the two bindings stop agreeing on the condition.

**The SDK mount guard refused AWS and Azure and accepted Google Cloud.** The list of credential
directories a `mounts=` source may not contain covered eleven names and missed the third major cloud,
plus the GitHub CLI's token directory. Measured on the published 0.2.27 with each directory created
first, which is the step that matters: the first sweep read `~/.config/gcloud` as covered when the
real answer was "source does not exist" on a host that has no gcloud, and a refusal that is really a
missing path is a skip wearing a pass. Ten candidates were accepted once they existed. Added: `.oci`,
`.terraform.d`, `.databrickscfg`, `.boto`, `.s3cfg`, `.rclone.conf`, and, matched only under
`.config`, `gcloud`, `gh`, `doctl` and `rclone` - only under `.config`, because a bare `gh` component
would refuse `~/projects/gh/src`, and a guard that fires on ordinary work is one somebody turns off.
Deliberately NOT added, and said out loud rather than left implied: `.cargo`, `.m2` and `.gem` each
hold one credential file beside a package cache people legitimately mount, so refusing the directory
would break a real use; mounting `~/.cargo` still exposes `credentials.toml`. Both bindings carry the
same list and a test now fails if they drift. This is a guard rail against an agent being steered
into asking for the mount, not a sandbox boundary: the caller still has to ask.

**`kern network ls` and `kern pod ls` printed a name off disk without stripping terminal escapes.**
Both walk a state directory and render every entry verbatim, so what they show is what is on disk and
not what `create` accepted: the creation-time name check does not cover them, and the REFUSAL for the
same name two functions away already scrubbed it. Measured with a planted directory, both printed the
ESC and BEL bytes intact and the terminal obeyed them. Not reachable from inside a box - planting the
directory needs write access to kern's runtime dir, and `-v` refuses to mount that into a box by name
- so this is the layer under that refusal rather than a hole in it. `--json` was already correct on
both. The entry is still LISTED, neutralised, because hiding a directory kern acts on would be worse
than showing it safely. Found by running every list verb against the same planted name instead of
inspecting the one already known broken, which is what turned one table into two.

**Four tables had a fixed NAME width, and `kern history` printed two different boxes as one line.**
`kern ps` was widened to fit its longest name some releases ago; `stats`, `history`, `volume ls` and
`network ls` were not, each with its own number. The three that do not truncate (`stats` 16,
`network ls` 24, `volume ls` 28) shifted PID, MEM, CPU, SIZE, QUOTA and MEMBERS for the whole table
on any longer name, header included, so the header lined up with no row in it; 16 is passed by every
box the sandbox SDK starts, and 28 by a volume a compose stack leaves behind. `history` truncates
instead, and a project scope is 17 of its 20 characters: a stack with services `worker` and
`workqueue` gave two rows both reading `…-wo…`, different pids, no way to tell which log was which.
One rule for all five now, floored at each table's old width so short output is unchanged and
ceilinged rather than truncating, because the name is the identity `kern stop` and `kern logs` take.

**A piped `kern top` reported every box at 0% CPU.** The pane's per-box CPU% is a delta between two
samples, and the one-shot form a pipe selects took only one, so every box read `0%` unconditionally.
Measured: a box pegging a full core read `0%` across 24 consecutive snapshots while its own cgroup
`cpu.stat` and its workload's `/proc/<pid>/stat` ticks both said 100%, and the interactive tab said
`100%` at the same moment. The same call dropped the box-START rate, which is the only place an SDK
firing ~ms boxes shows up at all - the live list is empty by the time you read it. Both now take
their earlier sample before the 120 ms the function already sleeps for the host CPU%, so `kern top |
…` answers what the terminal answers. A wrong number costs more than a missing one here: the piped
form is what a script, a CI step or an agent reads, and `0%` does not look like a placeholder.

**The Boxes tab of `kern top` says what it lists.** Every other list pane has a caption and the row
budget reserves one for all of them, so this tab was spending the line on nothing; it now names the
pane, the word containers, and the command that makes one.

**`kern top` could not reach past the first screenful of any list.** Every pane drew its rows from
index zero, so on a host with 309 cached images the Images tab showed 25 and `… 284 more`, and no key
reached the 284: the selection walked off the bottom of the screen and the window never followed it.
Images, Builds, Boxes and Storage all had it. The drawn window now follows the selection, moving as
little as it can, and one status line reports what is hidden above AND below with the position in the
list. One line, because the frame budget reserves exactly one row for it and a second would push a
full tab past the terminal.

**A shifted key acts on the whole tab, after asking.** `D` deletes every cached image, every build
record, or every volume and its data; `S` stops every running box. Each one arms a confirmation whose
prompt names HOW MANY and what is lost, because "delete all?" says nothing about the blast radius of
the key about to be pressed. The targets are captured when the key is pressed rather than re-derived
on confirm, so what was on screen is what gets acted on, and a bulk action runs to the end and reports
how many of how many failed instead of stopping at the first.


**A cell could forge a sandbox verdict with one leading space.** The neutralisation that stops a box
printing `[sandbox: oom]` or `[exit 137]` and having a model read it as the sandbox's own verdict was
anchored at column 0, so ` [sandbox: oom]` (one space, a tab, a NBSP, a zero-width space or a BOM in
front) sailed through unlabelled - and a model reads the leading space as nothing. The anchor now
allows a run of invisible characters before the marker, on every surface that neutralises framing
(the MCP server, the LangChain renderer, the Pi extension). A marker with a WORD in front of it is
still left alone, because that is a sentence mentioning the frame rather than forging it.


**`kern build` reads a `Containerfile`.** Without `-f`, it looks for that name first and for
`Dockerfile` second, which is the order podman and buildah use. Both are read and neither is
deprecated: a build file is an input, and refusing to open one someone already has, because of what
it is called, would be a position rather than a behaviour. The order matters only in a context
holding both, which is a repository saying something about itself, and there the neutral name wins.

## v0.9.35 - 2026-09-17

Eight days of work since v0.9.32. Each line is the change; how a defect was found and why the fix is
shaped that way is in the commit it came from (`git log v0.9.32..v0.9.35`).

**Read these first if you are upgrading:** each compose service gets its own network namespace on a
bridge, so a port a service binds on its `127.0.0.1` stays private to it; `fault.type` reports a
different value for four events; and the SDKs refuse mounts they used to accept, with no opt-out.
Every one of them is described below.

**Sentry's official `install.sh` completes on kern, and the 57-service stack runs.** Measured end to
end against `getsentry/self-hosted` at 26.8.0: every image built, the migrations, `compose up
--wait` reporting `57 service(s) ready`, the web UI answering 200 and the API 200, then `down`
stopping 57 of 57 with nothing left. One edit to the official tree was needed and is not kern's to
make: its minimum-version gate compares `docker version` against Docker's numbering, and kern
reports kern's version. Twenty-one defects were fixed to get there, and fourteen of them are in the
`docker` and `compose` surfaces rather than in the sandbox.

**Each service gets its OWN network namespace on a bridge, which is Docker's arrangement.** A port a
service binds on its `127.0.0.1` stays private to it. `--pod` keeps the old single shared namespace,
which is faster and makes every loopback port reachable by every peer, and `kern compose <file>
config` prints which wiring a bring-up will use.

**Two networking defects that only some machines could see.** On a home or edge network a box had
internet and could not resolve a name, because pasta copies the host's nameserver into the box and
on such a network that address is the LAN router, which is also the gateway pasta impersonates; kern
passes `--dns-forward` now. And on every host whose NIC is called `eth0` (WSL2, most cloud VMs) a
multi-service stack had no outbound at all, a regression against v0.9.32: pasta named its tap after
the host's interface and collided with the name kern gives the workload's. kern names that interface
itself now, per namespace.

**`compose run` was missing most of what a script passes it.** `-d` detached nothing; `--name`,
`--entrypoint`, `-e`, `--user` and `--pull` were refused; the one-off started none of the
dependencies written with a `condition:`, which is how every real file writes them, and did not wait
for them. Its stdout is the workload's now, too: kern's build lines and pod narration went to the
same stream, so `state=$(docker compose run --rm -T svc ...)` captured kern's sentences ahead of the
answer.

**A service whose dependency failed was held back and then started anyway.** With a `condition:` on
a dependency that fails, the pre-exec gate refused the exec, and one second later the restart path,
running without that gate, ran the workload. In the same area: a `restart:` service never restarted
after its first exit, and a failed `up` left its surviving boxes rebuilding forever. A box that
never started is not a workload that exited, and the three cases are now told apart.

**A database that was ready in ten seconds reported `starting` for five minutes.** Docker 25+ splits
the probe cadence in two, `Interval` for the steady state and `StartInterval` for the start period,
and kern read only the first: an image declaring `Interval 300s, StartPeriod 300s, StartInterval 5s`
had its first probe land 300 seconds in, and everything gated on `service_healthy` waited with it.
Both are honoured now, from the image config and from a Dockerfile's `HEALTHCHECK --start-interval`,
and `kern box --health-start-interval <sec>` exposes it.

**An explicit `docker.io/` prefix broke every pull**, and it is not an exotic spelling: it is
Podman's recommended style and what Immich's official compose file ships. `docker.io` and
`index.docker.io` resolve to Docker Hub's API host now, and `docker.io/alpine` means
`library/alpine` exactly as bare `alpine` does.

**Defaults and refusals a real file runs into.** A service with no `pids_limit:` gets 2048 tasks,
not the sandbox's 512, because ClickHouse aborts under 512. `compose pull` no longer goes to a
registry for images the file said never to pull. `ulimits:` written as a one-line mapping is applied
instead of reaching the box with its braces. `network_mode: host` is applied as Docker applies it
and now SAYS what it removes. A GPU reservation says the service runs WITHOUT the device. A
dependency that never becomes healthy fails naming the box and carrying its own repair, rather than
advice about how to write a compose file.

**The sandbox SDKs: `fault.type` changes value for the same event, which is why 0.2.0 was a MINOR
bump.** An external `kern stop` was `oom` and is now `killed`; a workload that CHOOSES `exit 137` is
no longer a fault; a crash is `fault=None` with `128+signal`; a `KERN_BIN` that is not kern raises
instead of reporting success. `fault` is read from kern's own descriptor, so a cell cannot forge a
verdict from its output. 0.2.0 through 0.2.22 are on PyPI and npm, and 0.2.22 is what a bare
`pip install kern-sandbox` or `npm i kern-sandbox` resolves to today.

**A box that never started is a verdict of its own, not an exit code to guess at.** It is
`fault.type == "startup_failed"` from `run_code`/`run` and raises from `kernel()`. Branch on
`fault`, not on `exit_code`: a box that never ran exits 1 exactly like a script that did.

**The SDKs refuse a mount that would hand the box the sandbox's own control plane.** kern's state
(`$XDG_RUNTIME_DIR/kern`, `$XDG_DATA_HOME/kern`, the image cache, the config dir), the host's own
sources (`/`, `/etc`, `$HOME`, the docker socket) and any path with a credential directory in it
(`.ssh`, `.aws`, `.kube`, `.npmrc` and the rest). There is no opt-out, deliberately: a job that
needs one credential should be given that one file in the workspace. Workspace I/O refuses what it
cannot contain and says which: an absolute path, a `..` escape, a symlinked component at any depth,
a device planted at the name, a file over `max_bytes`.

**The MCP server names the kern that ran the code** (`[exit 0 in kern 0.9.32]`), and its tool
description leads with what a client's own shell cannot do. An independent test wired the server into Cursor
correctly and the agent answered from its own python, never calling the tool. An argument a tool
does not have is refused with `-32602` rather than dropped, and box output reaching a model has
terminal escapes stripped and both surfaces' framing neutralised, so a forged marker reads `[printed
by the code, not the sandbox: ...]`.

**`kern-pi` 1.0.1 on npm.** 1.0.0 asked for `kern-sandbox: ^0.1.41`, and for a zero-major version a
caret range stops at the next minor, so a Pi user's model was reading fault verdicts from before
this year's chain.

**Runtime and CLI.** A service stopped and started again was unreachable by its peers for 29
seconds, because its `veth` got a random MAC each time; a member's address is derived from its IP
now, as Docker's is, and the same restart takes 176 ms. A `build:` on a Debian or Ubuntu base could
not be built at all, because those images ship directories at mode 0700 owned by a subordinate uid.
`docker version --format` ignored its template and exited 0, so a script reading it carried on with
the wrong string. An image cached by an older kern is refreshed rather than re-fetched. `kern
inspect <image>` answers for an image, and a `--format` field kern cannot answer truthfully is
refused by name rather than answered wrongly. `EXPOSE` reaches the image config. `--memory 64` is 64
BYTES and the message says so. A FIFO as a volume source is refused instead of hanging the box
forever.

**`kern logs -t` prints when each line was written.** Docker has had `--timestamps` since
forever and a reader comparing a box's output against anything else needed it. The time comes from a
`<log>.idx` sidecar the log pump writes beside each log, so the log file itself stays byte-for-byte
what the box printed and the pump keeps its zero-copy `splice` path: nothing is parsed or reframed on
the way through. A mark is recorded at most every 100 ms, so a stamp is the start of the
bucket a line falls in and never later than the line itself. The index is bounded at a sixteenth of
the log's own cap: past that its marks are thinned by half and the interval doubles, so a box that
runs for days loses resolution instead of growing a file without limit. A log written by an older
kern has no index and prints `-` in the time column rather than a time nobody recorded, and so does a
rotated generation, because rotation makes every offset in the index mean a different byte.

**What `-t` is not.** `-f` is a diagnostic stream and not an audit log: under load a line written
between the tail read and the follow can be dropped, which is stated in `--help` rather than fixed
with machinery nobody asked for. Time is never reordered. And a byte-capped rotation splits whatever
line it lands in, so the first bytes of a fresh generation are the tail of a line that started in the
previous one; `-t` stamps that fragment like any other line, correctly but confusingly.

**The Pi extension neutralises box output that becomes model text.** A cell that prints
`[sandbox: oom]` or `[exit 137, ...]` is forging a verdict about itself in the channel a model decides
with, and the SDK's other two agent surfaces have refused that for a while: this one did not. It now
does, on the paths where bytes become text - a command's stdout and stderr, grep's file contents, a
directory listing, a glob's paths - and deliberately NOT on `readFile`, which returns a Buffer and
serves images: stripping control bytes there would corrupt every PNG the agent reads. Neutralise at
the text boundary, never at the byte boundary.

The stream is neutralised per LINE rather than per chunk. The markers are anchored at a line start
and output arrives in arbitrary pieces, so a chunk can begin mid-line and a marker can be split
across two: measured, per-chunk both misses a marker broken in half and labels one that is merely
quoted in the middle of a sentence.

**`kern logs -f` stopped showing output after the first rotation, and said nothing.** It followed an
open descriptor rather than the name, so when the pump renamed the active log and opened a fresh one
the follower kept polling a file nobody writes to any more. Measured: a box that printed 120 lines
after its rotation showed **zero** of them, while all three generations sat on disk. Rotation is the
default at 16 MiB, so this was every long-running box, and `kern attach` had it too. It follows the
name across rotations now, the way `tail -F` does and `tail -f` does not.

**A timestamp can no longer go backwards, whatever the index says.** At a rotation seam the last line
of one generation and the first of the next are answered by two different indexes, which measured 103
ms backwards across the seam. Rather than chase every ordering between a pump that renames, truncates
and compacts and a reader that polls, the reader holds a floor: a stamp is never older than one
already printed. The cost is stated in the code - across a seam the column repeats an instant instead
of showing a slightly older one - and it can never invent a time that is too new. A reader whose file
was rotated away says `-` instead, because the index in front of it describes a different file.

**`kern logs` could report that a busy box writes no log at all.** A rotation renames the active file
and opens a new one, and a reader that resolved the name in between found nothing, or opened a
descriptor to a file that had just been renamed away. Resolving and opening are one retried operation
now. Found at roughly 1 read in 6000 by a new concurrency battery,
`scripts/logs-timestamp-battery.py`, which drives six readers against a box rotating every few KB and
one whose index compacts underneath them, and looks for a time that goes backwards, a torn record read
as valid, and a line with no time column anywhere but at the end.

**The compatibility rate ships with its corpus and its definition.** The v0.9.32 claim of "14% to
94%" was the CEILING under a permissive definition; the strict one measures 35% on the same 259
files. Both numbers are in [DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md) with the census scripts that
produce them.

**Tests, gates and examples.** 1340 Rust, 512 Python and 110 Node tests, with the count gated
against the README. New batteries and gates, all in CI: `fault-taxonomy-battery.py` (27 cases),
`docker-vocabulary.py`, `md-links.py`, `launch-dryrun.py`, `e2e-semantic.py`,
`build-corpus-census.py`, `declared-bind-census.py`, and a `loopback-census.py` whose zero means
something. `examples/` moved from 103 flat files into eight directories, nothing deleted.


## v0.9.32 - 2026-09-09

**A published port now binds `0.0.0.0`, not `127.0.0.1`. Read this one.** `-p 8080:80` and a compose
`ports: "8080:80"` bind every interface, which is what Docker does and what a file written for Docker
means. Until now kern bound loopback and warned, so a stack that looked published was reachable only
from the host. `[kern] publish_bind` in `kern.toml` is a ceiling no file can widen, and an explicit
`127.0.0.1:8080:80` still means loopback.

**Docker Compose compatibility went from 14% to 94%**, measured before and after on the same neutral
corpus of 259 files, one per repository, sampled across 733 repositories: the share of files kern
runs with no behavioural difference from what the file says. [Corrected under Unreleased: 94% is the
ceiling, and this definition measures 35% on the same corpus.] What remains is dominated by keys asking
kern to be less confining than it is (`privileged: true`, `security_opt`) and by `network_mode: host`,
which one namespace per stack cannot express. The earlier "15% irreducible" was an artefact of a
corpus weighted toward those keys.

**Twelve compose keys stopped being warnings and became behaviour**, among them `mem_reservation`
(cgroup `memory.low`), `devices:`, `dns:`, `logging:`, `tty:`, `stdin_open:`, `secrets:` long syntax,
and an image's own `HEALTHCHECK` and `STOPSIGNAL`. A string `command:` is now an argv rather than a
shell line, a tagged block scalar folds, and an empty named volume is seeded from the image as Docker
does.

**`networks:` is a boundary, not a warning.** Under `--no-pod`, services with no network in common
cannot reach each other by name or by address, and `internal: true` is the absence of NAT rather than
a filter, so a published port does not open a way out. In a pod the two say something different, and
both are stated at bring-up. A key that is absent means the `default` network, which is 52 of 187
files rather than the 18 that name one.

**`${VAR:?message}` refuses the file instead of substituting an empty string.** A stack whose
password variable was unset started with an empty one.

**An image's file ownership survives the unpack**, so a service running as a non-root user can write
the directories its image gave it. A named volume inherits the image directory's owner and mode, not
only its contents, and `kern rmi` no longer reports a removal it did not perform.

**A service secret is written with the mode the Compose Specification mandates.** It was `0400` in a
`0700` directory, so no image running as a non-root user could read its own secret. `target:`, `uid:`
and `gid:` were read and dropped in silence; they are applied or named.

**`kern run` no longer pays for a systemd scope it does not need: 4.70 ms to 0.87 ms.** It bought its
caps with a transient `systemd-run --user --scope`, one per invocation; it now caps directly under
kern's delegated `kern.slice`, the way `kern box` already did.

```
                  median     p99      max
before             4.700    5.735   15.304 ms
after              0.870    1.267    1.487
```

The tail moved more than the median because a D-Bus round trip to a shared user manager is a queue.
Throughput at concurrency 200 goes from 86 to 4052 runs per second: a path that serialises on a
shared service gets worse as concurrency rises, and a benchmark at concurrency 1 reports that only as
"slow". Finding the delegated slice turned out not to be the same as being allowed to enter it:
cgroup v2 delegation containment needs write access to the `cgroup.procs` of the common ancestor, and
a host outside that tree gets the scope path rather than an uncapped run.

**`kern exec` stopped refusing where there was no cap to escape**, and its fail-closed refusal now
names both causes and the way through (`KERN_ALLOW_UNCAPPED=1`). A `--health-cmd` probe is never
refused. `kern exec` and every health probe now run with the image's environment rather than a bare
one, and `kern stop` sends the stop signal once instead of twice.

**`kern doctor` names the cgroup it probed** on every row that denies a cap, so the verdict can be
checked against `/proc/<pid>/cgroup` instead of taken on trust, and it asks about both directories a
box can be capped in. `kern inspect --json` gains `memory_max_enforced`, read back from the box's own
cgroup: `memory_max` is the value the box was started with, and on a host that caps another way the
two differ.

**A box's terminal has a name.** `tty` inside an alpine box printed "not a tty" while `isatty` said
otherwise, because the `-it` pair was allocated on the host and the box's private devpts does not
contain it. It is now allocated from the box's own devpts and the master passed back over a
socketpair, so both C libraries resolve it. Certified on Fedora 44, CentOS Stream 10, Rocky Linux
10.2, Debian 13, openSUSE Leap 15.6 and Ubuntu 24.04, three with SELinux Enforcing.

**CLI surface: six flags added, none changed or removed.** `--dns`, `--dns-search`, `--dns-option`,
`--log-max-size`, `--log-max-file`, `--secret-mode`. Additive, so nothing that runs today stops
running.

## v0.9.31 - 2026-09-09

**If you use `kern exec`, this release is the one that makes it obey the box's limits.** It did not.
A command run through `kern exec` was placed in the CALLER's cgroup, outside the box's `--memory` and
`--pids-limit`, and said nothing about it. Measured from the host by pid, with the box's own PID 1 as
the control and the exec'd process verified to be in the box's PID namespace:

```
box PID 1                  .../kern.slice/kern-box-<tag>-<pid>     capped
the kern exec'd process    .../app.slice/app-<the caller>.scope    the CALLER's cgroup
```

A fork bomb or a memory hog started with `kern exec` therefore ran without the ceiling the box was
given. Namespaces and seccomp always held; it is the resource cap that leaked. The placement now
happens BEFORE the namespaces are joined, which is the only order in which the kernel permits it:
afterwards the box's own cgroup is the root of its namespace and the common ancestor cannot be named,
so both `clone3(CLONE_INTO_CGROUP)` and a write to `cgroup.procs` answer ENOENT.

**The cost is real and is stated rather than hidden.** Placing before the `setns` means a
`cgroup.procs` write, which takes an RCU grace period: `kern exec` is back to 11.7-25.8 ms on a quiet
host against 1.7-2.2 without it. The faster path shipped in v0.9.3 was faster because it was not
applying the cap. `clone3(CLONE_INTO_CGROUP)` is still used where it is correct, on the box START
path, which places its child before entering any namespace.

**A command killed by the box's memory cap now says so.** `memory.oom.group` kills the whole box, the
exec'd command included, and it goes by SIGKILL, so the process that would explain it is the one being
killed. Before, the caller saw exit `-9` with empty stdout and empty stderr. A reporter now waits
outside the group and names the cause. The exit code is still `-9`: that part belongs to the kernel.

**A box whose registry record is lost stays visible.** kern's registry lives in
`$XDG_RUNTIME_DIR/kern/instances`, and `/run/user` is swept by `systemd-tmpfiles`, cleared on logout,
and deleted by anyone who reads it as scratch. The box does not care: it keeps running. Before, only
kern forgot, completely - the box vanished from `ps`, `kern stop <name>` answered "no running box",
and nothing could reach it again. `ps` now reads what the kernel still holds and names those boxes
with their supervisor pid on stderr, on hosts with a delegated cgroup and, through `/proc`, on hosts
without one. It does not invent a table row for them: there is no record, so there is no uptime, no
ports and no health to show.

**Multi-stage builds produce an image that runs.** `FROM <stage>` printed `built` and left an image
that failed at `kern box` with "no layers in manifest", because the final image rested on a stage's
overlay chain. The final image is now materialized, fail-closed. `COPY` also stopped flattening
directory modes: a rootfs shipping a 1777 `/tmp` or a 2755 setgid directory came out 0755, and the
program that needed it failed for a reason nothing in the Dockerfile explained.

**Compose reads files it used to refuse, and refuses files it used to accept in silence.** A
`command:` continuation line starting with `-` was read as a sequence entry, so `--source`, `-drive`
and `-netdev` broke a plain folded scalar; two real files from public repositories now parse. `!!str`
is accepted over a scalar and refused over a list or a map, where it used to be dropped in silence
and the box started with something else. `tmpfs:` has ONE grammar again: `kern box --tmpfs
/run:size=64m` used to fail on the exact spelling `kern compose` produced, while `/run:rw` and
`/run:exec` - both valid Docker - were read as sizes and refused. An IPv6 port refusal now names the
missing feature instead of suggesting a typo, and `/dev/shm` and `/dev/pts` say the mount is already
there rather than giving the generic refusal.

**`kern build prune` refuses arguments it used to ignore.** `kern build prune 0` was read as "keep
nothing", ran with the default 20, and reported "kept the 20 newest".

**Fixed, no interface change:** a memoised runtime path outlived the directory it named, so anything
that cleared `/run/user` left every later registry write in that process failing, for the life of the
process; the layer cache treated a sentinel without its directory as a hit, and the build then died
on a `mount(overlay)` ENOENT that named neither.

**Known and unchanged:** the resource caps are verified on one machine. CI does not start boxes, and
the second test's host has no cgroup delegation, so `--memory`/`--pids-limit` enforcement has one
witness. The squash that `FROM <stage>` and `push` share loses hard links and fills sparse files.
Compose networks do not isolate services from each other: one stack is one namespace, and `up` says so.

## v0.9.3 - 2026-09-07

**If you run kern on Ubuntu 23.10 or later, your install needs one action.** That is not a new
feature, it is the answer to "why does no box start", and it is here rather than under new
capabilities because it is the entry a reader scanning for "does this release affect me" needs to
find. Those releases ship `kernel.apparmor_restrict_unprivileged_userns=1`, which permits the
namespace and refuses the rootless uid map, so nothing starts. kern now ships the profile:

```
kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/kern
kern doctor
```

**CLI, additive:** `kern doctor --apparmor-profile` writes that profile to stdout and exits without
running any check. It exists because the install line has to be runnable by the person reading it,
and a repo-relative `packaging/apparmor/kern` is not: the release tarball carries the binary alone
and `cargo install` copies one file, so most readers have no `packaging/` directory. The binary
carries the profile instead. Nothing is removed or renamed.

**What that file does NOT do**, because installing one into `/etc/apparmor.d/` on a program's
say-so deserves the sentence: it grants exactly one permission, `userns`, and confines kern in no
way at all. Not its paths, not its capabilities, not its syscalls. Removing it returns the machine
to its previous state. It is deliberately not a confining profile: kern's job is to confine the
workload, and a second weaker mechanism aimed at kern itself would mostly invite the belief that it
was doing something.

The third command is not politeness. AppArmor attaches at `execve`, so a kern already running when
you load the profile does not pick it up. Measured on Ubuntu 24.04 with the restriction left at 1:
without the profile no box starts, with it `kern box`, `kern pod create` and the full acceptance
matrix all pass, and the sysctl is never touched.

`kern doctor` prints that install line, names the path it is running from because AppArmor attaches
by path, and offers `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` only after it, with
its cost: that one lifts the restriction for every program on the machine and is lost at reboot.

**`kern doctor` said "ready" on a stock Ubuntu 24.04, where no box can start.** Its userns probe
called `unshare(CLONE_NEWUSER)` and stopped there. Ubuntu 23.10 and later ship
`kernel.apparmor_restrict_unprivileged_userns=1`, which PERMITS the namespace and refuses the
rootless uid map, so the probe succeeded on a host where the very command doctor then suggested,
`kern box hello`, failed. Ubuntu is the most common distribution kern is installed on and that was
its default state.

The probe now runs the sequence a box actually runs, in the same order: unshare, deny setgroups,
write the uid map. Measured on a stock cloud image, both directions:

```
default                       ✘ the namespace is allowed and its uid map is REFUSED - no box can start
                              not ready - 1 blocker(s)
apparmor_restrict...userns=0  ✔ enabled
                              ready - `kern box` will run here
```

The AppArmor line no longer hedges with "if boxes fail with EPERM". It reports what the knob is set
to and leaves the verdict to the check that measured it, so a host carrying the restriction with a
profile for the kern binary is told it is fine rather than warned at.

**On a host whose SELinux policy refuses pasta's netns watch, the pod's pasta no longer exits by
itself.** kern retries with `--no-netns-quit` there ([#6](https://github.com/getkern/kern/issues/6)),
and a pasta started without the watch does not notice the namespace disappear, so `kern pod rm` and
`compose down` are what stop it rather than pasta stopping itself. Nothing to do differently; it
matters if you run a mixed fleet, because the hosts that take the retry and the hosts that do not
now have two different pasta lifecycles, and only the first depends on teardown running.

**`stdin_open:` and `tty:` in a docker-compose.yml no longer produce an alarm.** They used to warn
"ignored (unsupported)" matched on the KEY rather than the value, so `tty: false` warned about
nothing and a working stack was told a feature was missing
([#7](https://github.com/getkern/kern/issues/7)). A compose service is always detached, so `tty:`
has nothing to act on and is silent; `kern exec -it <service>` gives a real PTY in the running box
when one is wanted. `stdin_open: true` still warns, because it is a real difference from Docker: the
service's stdin is at EOF rather than held open, so a program that blocks on it exits at once.

**The Rust test suite had never been built for aarch64, though the binary always was.** So every
"the tests pass" statement this project has made was an x86_64 statement, silently, for as long as
ARM has been a supported target. Two lines caused it, both in test code and both invisible on
x86_64-gnu: `pthread_t` is a `c_ulong` on glibc and a `*mut c_void` on musl, and the pointer form is
not `Send`; and `ioctl`'s request parameter is a `c_ulong` on glibc and a `c_int` on musl. It now
builds and runs on ARM: **577/577 on a Raspberry Pi 5 (kernel 6.6) and on a Jetson (5.15-tegra)**,
on the hardware rather than under emulation. Under `qemu-user` one `flock` contention test fails
reproducibly and passes six times out of six on the boards, so that red is an emulation artifact and
not a name-collision bug on ARM.

That is the largest instrument defect in this cycle: not a probe reading the wrong thing, but a
whole suite that was never executed on a target kern ships for.

**A refused netns watch is only fatal in newer passt, and where it is not there is nothing to fix.**
Read out of three installed binaries rather than inferred:

| passt | ships in | on a refused watch |
|---|---|---|
| `0.0~git20230309` | Debian 12 | `inotify_init(): won't quit once netns is gone`, and it keeps the NAT |
| `0.0~git20240220` | Ubuntu 24.04 | `netns dir open: %s, exiting` |
| `0^20250919` | Fedora 43 | `netns dir open: %s, exiting` |

So a Raspberry Pi on Debian 12 needs no retry and never could have: issue #6 cannot occur against
the tolerant build. The condition became fatal between March 2023 and February 2024, which is
exactly the range the retry covers.

**Fixed: `--memory` and `--pids-limit` reported "accepted but NOT enforced here" over a box capped
exactly as asked.** Reported on WSL2 and reproduced on a Raspberry Pi 5 and a Jetson Orin Nano,
where `--memory 256m --pids-limit 64` printed both notices while the box's cgroup held
`memory.max=268435456` and `pids.max=64`. The check was right and was asked in the wrong place. It
read `/proc/self/cgroup`, and on the systemd-scope tier that is the SUPERVISOR, which kern parks in
a sibling leaf so a whole-box OOM cannot take it with the workload. From there the walk goes to the
ancestors and never reaches the box's leaf, which is a sibling rather than a parent; the only
ancestor carrying a memory ceiling is the scope, deliberately set to the request plus kern's
supervisor headroom, so "capped at or below the request" was false by design. Both notices were
wrong on the whole of that tier, and on the direct tier the check never runs at all, so it had never
once fired correctly.

The same mistake had a second instance, found by adding one diagnostic line to the reproduction
script rather than by reading the code. The `KERN_NO_SCOPE` opt-out warned from a point BEFORE the
box exists, where whether the cap will bind is not yet knowable, on the belief that the opt-out
skips the box's own cgroup as well as the scope. It does not. On x86_64 that printed "accepted but
NOT enforced here" while the box held `memory.max=268435456` and a 400 MB load was killed with exit
137. The warning now comes from one place on every box path, after the caps are written, against the
box's own cgroup. The Raspberry Pi finding the opt-out warning was written for is unchanged and
still reported: measured on a Pi 5 and a Jetson, the opt-out leaves `memory.max` and `pids.max` at
`max` and a 400 MB load survives, and kern says so. The notice now follows the cgroup rather than
the code path.

The enforcement byte on `KERN_STARTED_FD` was already correct: it takes the box's directory
explicitly, for this exact reason. So an SDK reading the byte saw "enforced" while a human reading
stderr saw the opposite, in the same run. Both now read one binding, so they cannot disagree. If you
scripted around the false notice, remove the workaround; if you concluded your caps were not
working, they were, and `--memory 256m` was killing at 256 MiB throughout.

**Fixed: a box refused for running out of process slots was told to check user namespaces.** A
independent test hit it with a tightened `ulimit -u`:

```
error: sandbox: fork(idmap helper) failed: Resource temporarily unavailable (os error 11)
hint: needs unprivileged user namespaces and a valid --rootfs directory
```

The message is exact and the hint names two things that are both already fine, because the code
could not have reached that fork otherwise. `EAGAIN` on a fork is a process-limit problem, and
`RLIMIT_NPROC` is per-UID and counted across the whole system, so another program owned by the same
user can exhaust it, and it counts TASKS rather than processes. That last clause is not a detail:
that test who reported the hint then compared `ulimit -u` against a process count, got 10 against
149, and concluded the kernel was accounting something unobservable. Measured here, an x86_64 desktop
owned 208 processes and 1918 tasks and the limit at which a single fork began to succeed was 1932, so
against the task count the threshold IS the count. The hint now names `ulimit -u`, the task count and
`LimitNPROC=`. Every other setup failure keeps the hint it had. Same shape as the pull hints, which branch on the message
rather than on the variant for exactly this reason.

**`kern --version` now says which build it is.** It answered `0.0.0` for every binary not cut by the
release workflow, which is every binary anyone compiles from source, so two builds of the same tree
were indistinguishable. That is not hypothetical: during the work above, a binary built ten minutes
before the fix was compared against one built after and reported as if it were the same program. A
independent test made the same point from the other side, noting that a test script had to print a
`sha256sum` to tell two builds apart, and that the workaround existed only because the binary could
not answer.

The version is still the tag and nothing is carved into the source. A release binary prints the tag
exactly as before (`kern 0.9.3`), because the workflow stamps `Cargo.toml` and that value passes
through untouched. A build from source prints `git describe` instead
(`kern v0.9.2-45-gf7622ee-dirty`): the nearest tag, the distance from it, the commit, and whether the
tree was dirty. Where git cannot answer, a source tarball or a vendored build, it falls back to
`0.0.0`, which is today's behaviour, so nothing regresses when the information is unavailable.

## v0.9.2 - 2026-09-06

**Cut for a defect the first person to try compose would hit.** A `docker-compose.yml` with ONE
service came up with no network at all, for the whole 0.9 line. The auto-pod was gated on two
services or more, on the reasoning that a pod's other job is letting services find each other and one
service has nobody to find; but the pod is also the only thing that attaches `pasta`, so a lone
service got no pod, no NAT and no `/etc/resolv.conf`.

It does not present as a missing network, which is why it survived: the image ships its own
`resolv.conf` and it looks healthy, so the failure surfaces as `Could not resolve host` and every
diagnosis goes after DNS. `curl http://1.1.1.1` from inside the box failed in **0 ms**. There was no
route. Reported from a Mac running Lima with a Fedora guest, but the platform was never the variable:
reproduced on x86_64 Linux with pasta installed, changing only the service count.

**Every compose test in this repo ran three services, which is how it shipped.** The single
`services:` in the Rust suite points at an unreachable registry and never starts a box, so the
one-service path had no coverage anywhere. `scripts/acceptance-matrix.sh` now has a case for it, with
its two new assertions exercised in `--self-check` including a negative control on the pre-fix
summary line. The case goes RED on the v0.9.1 binary and green here, confirmed by an external
independent test on their own host rather than only here.

### Fixed

- **A one-service compose stack had no egress.** The auto-pod condition tested a service COUNT while
  the property it stood in for was "does this stack need a managed network". It now creates a pod
  whenever any service is not on the host net, which is what the comment above it always said it did.
- **`kern pod ls` and `pod ls --json` reported double the members.** They counted lines in the pod's
  shared `hosts` file, and a compose member writes two of them (the qualified `<pod>-<service>` and
  the bare alias) while a `kern box --pod` member writes one. Measured on the shipped v0.9.1: 1, 2 and
  3 services read 2, 4 and 6, while `kern ps` read 1, 2 and 3. Both now read the registry `kern ps`
  reads, scanned once rather than per pod. The two views had been unified so they could not disagree;
  they could not, and both were wrong, while a third reader had the right answer.
- **`compose up` never said whether the stack had egress**, only that services could reach each other,
  so a stack with internet and one without printed the same sentence. On a reused pod that line is the
  only one printed. It now names the state, and `docs/DOCKER-COMPAT.md` lists all five instead of two.
- **`restart:` in a pod does not survive a reboot, and now says so.** A pod member is supervised
  in-process because a systemd unit that outlives the pod holder cannot re-join its namespace. The gap
  predates this release and reached only multi-service stacks; the auto-pod now reaches one-service
  stacks, so `up` prints a note instead of trading reboot-survival in silence.
- **`has_outbound` answered from `resolv.conf` alone.** Kill `pasta` while the holder lives and the
  file stays on disk, so the predicate reported egress for a pod with no route. It now also requires a
  live pasta, verified by `comm` because passt re-execs into an ISA variant and a pid can be reused.
  Found by an independent test reading the diff, not by a test here.
- **`kern killall --help`, `kern down --help` and `kern logout --help` printed the whole 184-line
  reference.** The per-verb match read only the first token of each line, and those three are
  documented as the second half of a pair. The test that missed them named fifteen verbs by hand; it
  now reads the list out of the reference, all 51.
- **Nine `kern --help` lines sat outside the description column**, `pod` by twenty because it did not
  fit; `pod` is two lines now. 76 verbs and 83 flags either side, checked by diffing both sets.
- **A damaged image-cache entry was repaired in silence under an SDK.** v0.9.1 gated kern's progress
  on a terminal and took the two repair lines with it, so in a pipe a cached image with no usable
  rootfs, or with no config, was re-fetched with nothing said. They are `kern: note:` now and reach a
  pipe; the ordinary "not cached, pulling once" stays gated. Found by
  `pentest/pentest-cache-edge.sh`, which asserts kern names the missing part.

## v0.9.1 - 2026-09-05

**Faster than v0.9.0 on a bare box start**, 2.300 ms against 2.346 in 21 of 24 paired batches, with
the OOM fix kept. The supervisor's sibling cgroup is created only where it is needed, a scope or
managed unit whose own cgroup is the one armed with `oom.group`: 0.165 ms back, 24 of 24, re-checked
in both layouts on four hosts and four systemd versions (249, 252, 255, 257).

**Cut for one defect the released binary had on most hosts.** `--egress-allow` in v0.9.0 could start
a box against a proxy nothing could reach, and on three of five hosts the pump never got the port
(`cannot bind 127.0.0.1:3128 in box: Address not available`). The pump now raises the box's loopback
itself and refuses to serve if it cannot, so readiness means reachable rather than bound. Reproduced
on an Arduino UNO Q and a Jetson Orin Nano with the shipped v0.9.0 aarch64 binary.
`scripts/acceptance-matrix.sh` exercises it, and says so instead of printing a tick on a host where
it cannot tell the fix from the defect.

### Fixed

- **The MCP server offered a language and then refused it.** The `run_code` schema advertised `sh`
  while a hand-written guard did not. The guard is the schema's list now, and a refusal names the
  accepted values.
- **`kern_execution_policy(cap_drop=("ALL",))` disabled the drop it asked for**, comparing a tuple
  against the string `"ALL"` and producing `drop_all_capabilities=False`. Only exact images convert;
  anything else raises and names the field to set.
- **kern's progress output no longer reaches a pipe.** Nineteen bare `eprintln!` lines now go through
  `progress!`, which prints only when stderr is a terminal. Errors, warnings and `kern: note:` still
  reach a pipe, because that is where they must arrive. `scripts/progress-is-tty-gated.py` keeps it
  true; converting the sites by hand found fourteen and missed five.
- **Three diagnostics reached `code_stderr` as though the workload had printed them**, lacking the
  `kern: ` prefix, plus five `kern compose:` lines whose prefix matched nothing.
- **A cgroup probe printed systemd's bus error onto kern's stderr.** `systemd-run ... -- true`
  inherited its stderr, so on a host with systemd installed but not booted the box's stderr carried
  `Failed to connect to bus`. Both streams are null now; the verdict was never in the output.
- **kern's diagnostics no longer land in a model's context.** `code_stderr`/`codeStderr` is stderr
  without kern's own lines, `runtime_notes`/`runtimeNotes` holds exactly what was removed, and
  `stderr` still holds every byte in order.
- **`kern_execution_policy` accepts `Sandbox`'s vocabulary**, `timeout_s` and `memory_mb` beside
  langchain's `command_timeout` and `memory_bytes`. Passing both halves of a pair is refused.
- **The OOM message never printed when kern runs as root or on a host with no systemd**, which is
  where the cap is most likely to be the only thing between a workload and the machine. The counter
  was read by walking kern's own cgroup ancestors, and on the direct-cap path the supervisor sat
  inside the cgroup `memory.oom.group` was about to kill. Verified on four hosts.
- **The registry recorded the supervisor's cgroup for every box**, and `kern stop` writes
  `cgroup.kill` into the path it records, so a stop would have killed the reporter.
- **A `-v` volume is mounted `nosuid`**, `/workspace` included. A `:ro` volume still fails hard.
- **`/dev/shm` reports the size the box actually has.** Unsized, `statvfs` reported half the host's
  RAM: a box held at 512 MiB told every workload it had 15.6 GB.
- **A warm interpreter could not import anything the image ships.** The driver ran `python3 -S`, so
  `import numpy` worked on a cold `run_code` and raised in a kernel cell. Dropped in both bindings.
- **`kern-sandbox` 0.1.36 on npm could not be installed**, its `package.json` depending on itself.
  Fixed in 0.1.37 and deprecated on npm.

### Changed

- **`deps_readonly` defaults to TRUE**, so a cell cannot change what the next cell imports. The route
  it closes is bytecode: a `.pyc` is validated on the source's timestamp and size, so a rewritten
  `.pyc` with the header re-pasted ran on the next import, invisible to `result.files`. A run-time
  write into `.deps` now gets `EROFS`; `deps_readonly=False` restores the old behaviour. It costs
  nothing at run time, the setup box compiling before the mount closes.
- **A timeout reports `exit_code = 137` in Python**, not `-9`, matching Node, the CLI and docker.
- **`integrations/pi` declares `engines: node >= 22`.** Measured: 20.18.1 fails at import, 22.11.0
  runs all 165 assertions.

### Added

- **`kern box --shm-size SIZE`**, for a workload needing `/dev/shm` sized differently from `--memory`.
- **`prewarm=N` in both bindings**: ~1.6 ms per call instead of ~37.8, measured over ssh, without
  giving up the fresh box, since a prewarmed box serves exactly one cell and is destroyed. A slot
  refills in ~70 ms, so N is a burst budget rather than throughput. Default `0` in the SDK, `1` in
  `kern-mcp`.
- **Every box gets a writable `/tmp`**, 64 MiB of tmpfs charged to the box's own memory cap. Nothing
  in it survives a call. `security_profile="untrusted"` gets none, deliberately.

**kern-sandbox 0.1.41** is documentation only, no code change from 0.1.40: the two package READMEs
moved their operational tail to `SANDBOX-NOTES.md` beside each binding. **0.1.40** answers an external
audit of the SDK, the pi extension and the LangChain integration.
