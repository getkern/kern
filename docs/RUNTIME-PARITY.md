# Where kern agrees with Docker and podman, and where it deviates on purpose

Every line here is a measurement, not a reading of a specification. Three runtimes, the same image,
the same command:

* **kern**, this tree, x86_64.
* **podman 4.9.3**, rootless, same host.
* **Docker 29.6.2**, rootful, aarch64 (a Jetson Orin Nano, the only host here with a Docker daemon).

The architecture differs on the Docker column. Nothing measured below depends on it: they are
identity, environment and mount rules, decided by runc and the daemon rather than by the ISA.

| # | Question | Docker 29.6.2 | podman 4.9.3 | kern | verdict |
|---|---|---|---|---|---|
| 1 | Supplementary groups for a bare numeric `USER` | `groups=0(root),1000(app)` | same | same | agree |
| 1b | ... for an explicit `--user 1000:1000` | `groups=1000(app)` | same | same | agree |
| 2 | `HOME` for a uid the image does not know | `/` | the WorkingDir | `/` | kern follows **Docker** |
| 3 | `wget http://localhost:PORT` at an IPv4-only listener | **fails** | works | works | kern follows **podman**, deliberately |
| 3b | ... on which network | the default `bridge` | rootless pasta | pod / bridge | see the entry |
| 4 | `HOSTNAME` in the environment | container id, = `hostname` | same | box name, = `hostname` | agree |
| 5 | Identity and cwd of a `HEALTHCHECK` | the container's user, its `WORKDIR` | same | same | agree |
| 6 | A privileged host port, rootless | not measured (see below) | refuses | moves it | kern deviates, documented |
| 7 | Submounts of a `-v` source | carried INTO the container | (as Docker) | left outside | kern deviates: EXPOSURE |
| 7b | ... and does `:ro` cover them | yes, `ro` inside, write refused | (as Docker) | n/a, they are not there | Docker has no `:ro` hole |
| 8 | `cpu_shares: 512` / `1024` / `2048` | `cpu.weight` 59 / 100 / 174 | not measured | same | agree (curve fitted to 10 points) |
| 9 | `mem_limit` alone | `swap.max` = the memory limit | not measured | `0` | kern deviates: STRICTER |
| 9b | `memswap_limit` present | `swap.max` = total minus memory | not measured | same, and the same two refusals | agree |
| 10 | `oom_score_adj` of PID 1 | the daemon's (0) | not measured | inherited from the session (100 here) | kern deviates: no daemon to reset it |
| 11 | `/etc/resolv.conf` | the daemon's DNS (`127.0.0.11`) | not measured | the host's nameservers | differs; peers resolve from `/etc/hosts` either way |
| 12 | `logging: max-size` | rotates into `max-file` files | not measured | one window, newest kept | differs: the first line of the window can be cut mid-line |
| 13 | `network_mode: host` | the host's interfaces | not measured | same (measured: `lo enp5s0 wlp4s0`) | agree |
| 14 | A named volume, two different uids | writer AND reader refused (`0:0 755`) | not measured | same | agree |
| 15 | UDP between peers | works (one network) | works | works in a pod, NOT under the relay wiring | kern deviates under `--no-pod`, and says so |

---

## 1. Supplementary groups come from the image's `/etc/group`

A `config.User` that names no group gets the memberships its name has in the image's own
`/etc/group`; `1000:0` and an explicit `--user 1000:1000` get none. runc's `GetExecUser` rule.

```
# Docker 29.6.2, image with `USER 1000` and `root:x:0:app`
uid=1000(app) gid=1000(app) groups=0(root),1000(app)
# same image, --user 1000:1000
uid=1000(app) gid=1000(app) groups=1000(app)

# podman 4.9.3, docker.elastic.co/kibana/kibana:8.19.16 (`User "1000"`)
uid=1000(kibana) gid=1000(kibana) groups=1000(kibana),0(root)
# podman, docker.elastic.co/elasticsearch/elasticsearch:8.19.16 (`User "1000:0"`)
uid=1000(elasticsearch) gid=0(root) groups=0(root)
```

kern matches. Before it did, Elastic's Kibana died on `EACCES` reading certificates its own
`setup` service had written `root:root` mode 640, while the Elasticsearch nodes, whose image
declares gid 0 outright, were green.

## 2. `HOME` for a uid the image does not know

```
# Docker 29.6.2: --user 1234 -w /opt/wd  ->  HOME=/
# podman 4.9.3:  --user 1000 on airflow  ->  HOME=/opt/airflow   (the image's WorkingDir)
```

kern prints `/`, following Docker and runc's default user. For a uid the image DOES know, all three
give that user's passwd home (`/home/airflow` for `--user 50000` on `apache/airflow:3.3.1`), which
is what makes `pip install --user` tooling work: with `HOME=/root` the interpreter looks for its
user site-packages in a directory that does not exist, and `airflow version` answers
`ModuleNotFoundError: No module named 'airflow'`.

## 3. `localhost` and an IPv4-only listener: kern deviates from Docker on purpose

Image `python:3.12-alpine`, listener `python -m http.server 5000` (IPv4 only), check
`wget -q -O- http://localhost:5000/`, which is how compose files everywhere spell a health check.

The Docker column is a container on the daemon's default `bridge` network, the podman column is
rootless pasta, and kern is a pod member. The network is named because this is the row most exposed
to "it depends on how the daemon is configured": what decides it is the hosts file and musl's
sorting, not the driver.

```
Docker 29.6.2   hosts: 127.0.0.1 localhost / ::1 localhost ip6-localhost ip6-loopback
                disable_ipv6=0, lo has ::1
                wget localhost   rc=1        <- FAILS
                wget 127.0.0.1   rc=0
podman 4.9.3    hosts: 127.0.0.1 localhost / ::1 ip6-localhost ip6-loopback
                wget localhost   rc=0
kern            follows podman: wget localhost rc=0
```

With both records present, musl prefers `::1` and busybox's `wget` uses the first address only, so
the name cannot reach an IPv4-only server. Docker has the defect; podman avoids it by not claiming
the name for `::1`; kern does the same. A dual-stack listener works everywhere and is why this is not
noticed more often.

This entry corrected a wrong explanation in kern's own source. It used to say a Docker container has
IPv6 disabled so its `::1` is demoted: measured false above, `disable_ipv6` is `0` and the check
still fails.

## 4. `HOSTNAME`

```
Docker 29.6.2:  env=b46a2216132c  uts=b46a2216132c
kern:           env=<box name>    uts=<box name>
```

Agree. kern used to leave it empty on the `exec` and health-probe paths while `hostname` answered
correctly, which broke Airflow's scheduler check (`airflow jobs check --hostname "$${HOSTNAME}"`).

## 5. A health check runs as the container's user, in its WorkingDir

```
# Docker 29.6.2: --user 1000:1000 -w /tmp, probe records `id` and `pwd`
uid=1000 gid=1000 groups=1000
/tmp
status: healthy
```

kern matches on both axes. Running the probe as box root is a false-green generator: it reads what
the workload cannot, reports healthy, and `depends_on: service_healthy` releases a dependent onto a
service that is about to die.

## 6. A privileged host port, rootless

```
$ podman run --rm -p 80:80 alpine true
Error: rootlessport cannot expose privileged port 80, you can add
'net.ipv4.ip_unprivileged_port_start=80' to /etc/sysctl.conf (currently 1024), or choose a larger
port number (>= 1024): listen tcp 0.0.0.0:80: bind: permission denied
```

kern moves the port instead (`80` to `8080`, `443` to `8443`), once for the whole stack, before
anything starts, and prints both numbers; `[kern] privileged_port = "refuse"` gets podman's
behaviour. The reason for the default is measured: 15 of the 39 samples Docker itself ships publish
a privileged port, `80` in fourteen of them.

**Not measured on Docker rootless**: the only Docker host available here runs a rootful daemon,
which binds 80 and therefore cannot answer the question. Nothing in kern depends on the answer, so
this is stated as a podman measurement and no claim is made about Docker rootless.

## 7. Submounts of a `-v` source

```
# Docker 29.6.2 (kernel 5.15.148-tegra), tmpfs at /tmp/kern-sub on the host, then -v /tmp:/x
2 mount lines under /x, and /x/kern-sub IS a mount point inside the container

# the same with -v /tmp:/x:ro
/x           ro,relatime
/x/kern-sub  ro,relatime
touch /x/probe-root      -> Read-only file system
touch /x/kern-sub/probe  -> Read-only file system
```

THE `:ro` HALF, measured because the first half alone does not say which property kern's deviation
protects. Docker's read-only covers the submounts too (5.15 is past the 5.12 that gave
`mount_setattr(MOUNT_ATTR_RDONLY, AT_RECURSIVE)` recursive coverage), so Docker has no read-only
hole here and kern's deviation is about EXPOSURE alone: a recursive bind would put another program's
filesystems inside the box. That is also why kern's error message leads with exposure and not with
`:ro` - the `:ro` argument is not even true of Docker.

Docker binds recursively; kern does not, so those filesystems stay outside the box. They belong to
whoever mounted them, and the box asked for a directory rather than for everything mounted under it.
The kernel then refuses such a bind when the submounts were inherited (`has_locked_children`), and
kern's error names the paths and the reason instead of reporting `Invalid argument`.

## 8. `cpu_shares`, and why the obvious formula is wrong twice

Ten points read off the daemon, one container per value:

```
shares       2     8   100   256   512  1024  2048   8192  65536  262144
cpu.weight   1     3    17    35    59   100   174    532   3023   10000
```

Neither of the two mappings that "look right" reproduces it. A linear scale on 1024 gives 50 where
Docker gives 59 and 6400 where it gives 3023; `1 + (shares - 2) * 9999 / 262142`, which two
independent reviewers and this codebase all remembered as runc's, gives 20 for 512 and would move
the DEFAULT off 100, which the table shows Docker does not do. kern now computes
`ceil(100 ^ ((l - 1)(l + 126) / 1224))` with `l = log2(shares)`, which reproduces all ten.

## 9. `memswap_limit` is a total; `memory.swap.max` is not

Six cases, all measured:

```
--memory 256m                    -> memory.max 268435456   swap.max 268435456
--memory 256m --memory-swap 512m -> memory.max 268435456   swap.max 268435456
--memory 256m --memory-swap 256m -> memory.max 268435456   swap.max 0
--memory 256m --memory-swap -1   -> memory.max 268435456   swap.max max
--memory-swap 512m (no --memory) -> refused: "You should always set the Memory limit when using
                                    Memoryswap limit"
--memory 512m --memory-swap 256m -> refused: "Minimum memoryswap limit should be larger than
                                    memory limit"
```

kern converts by subtraction and copies both refusals. It deviates on ONE row: with no
`memswap_limit`, Docker allows swap equal to the memory limit, so `mem_limit` is really a 2x total;
kern leaves the allowance at 0, so `mem_limit` is the total it appears to be. The failure mode of
the strict side is a loud early OOM; the failure mode of the other is a box growing quietly into
host swap.

## 10. `oom_score_adj`

A kern box inherits the caller's value (100 in a systemd user session here); a Docker container gets
the daemon's, which is 0. There is no daemon to reset it in a rootless runtime, and resetting it to
0 would make a box HARDER for the kernel to pick than the session that started it. The compose key
`oom_score_adj:` is refused by name rather than silently accepted.

## 12. The log window

`logging: options: max-size` is honoured: measured 1k -> 19 lines, 8k -> 224, no key -> all 500, and
the window kept is the most recent one (lines 481-499 of 500), which is the end that matters. Docker
rotates into `max-file` files and therefore never shows a partial line; kern's window can begin
mid-line (`empimento-481`). Nothing is lost that the cap would not have dropped anyway.

## 15. UDP between peers

In a pod the services share one namespace and UDP crosses. Under the relay wiring a peer is reached
through a per-service loopback alias served by a TCP relay, so a datagram does not cross at all. That
is now stated in the wiring note itself rather than only for services that DECLARE a UDP port,
because a service that binds one without declaring it is the common case and was getting silence.
