#!/bin/bash
# Differential chaos suite: every case of every round, run 1:1 with Docker and with kern.
#
# Each case is a directory holding a compose file and a run.sh that uses $COMPOSE; it runs in a
# fresh copy of that directory per engine (a case may rewrite its own files), with setup.sh run in
# the copy unless the source carries .setup-done (its setup already ran and its output was copied).
# The check lines a run prints (EXIT_*, *_OK, ...) are extracted, normalised (log prefixes, random
# ports, ids) and compared as a sorted set. A case PASSES when both engines print the same set, or
# when the difference is listed below as deliberate. The exit status is the number of cases that
# differ for a reason not listed.
#
# Usage: run-chaos.sh [set/case ...]        (no argument: every case)
# Env:   CHAOS_ROOT (default: this script's directory), CHAOS_WORK (default $CHAOS_ROOT/work),
#        KERN_GPU_GRANT=flag|config (flag: --allow-device-grants on GPU cases; config: the
#        operator's kern.toml is expected to set allow_gpu_grants = true).
set -u
ROOT=${CHAOS_ROOT:-$(cd "$(dirname "$0")" && pwd)}
WORK=${CHAOS_WORK:-$ROOT/work}
GRANT=${KERN_GPU_GRANT:-flag}
mkdir -p "$WORK" || exit 2

# set -> directory that holds its case directories. Each set is one round of real-world cases
# written by someone other than kern's authors, kept as written (see README.md).
suite_dir() {
  case $1 in
    set1 | set2 | set3 | set4) echo "$ROOT/$1" ;;
    *) return 1 ;;
  esac
}
SUITES="set1 set2 set3 set4"

# Cases that ask a compose file for a GPU: kern needs the operator's grant.
gpu_case() { case $1 in set1/case1 | set2/r2-3 | set3/g2) return 0 ;; esac; return 1; }

# Differences that are deliberate or that the case itself causes, with the reason printed.
expected() {
  case $1 in
    set1/case8 | set1/case7) echo "services that run concurrently print in either order; case 7 has no healthcheck on its proxy (a race in the file)" ;;
    set2/r2-9) echo "kern refuses a bind that leaves the project through a symlink (deliberate); r2-9abs is the same case with an absolute path" ;;
    set3/g1) echo "a failed migration under --exit-code-from: Docker exits 0, kern exits 1 (deliberate, owner decision)" ;;
    set3/g8) echo "Docker itself sometimes hangs on --abort-on-container-exit with a restart policy (measured: 600 s timeout)" ;;
    set4/x3b) echo "a race in the file: the consumer depends on the producer having STARTED, not written; Docker's slower container start wins it (5/5), kern's sometimes loses (3/5); with the consumer 1 s later both read 3/3" ;;
    *) return 1 ;;
  esac
}

markers() {
  # `curl -w '%{http_code}'` prints no newline, so `200EXIT_X:0` is two check lines; Docker's tables
  # are aligned with different padding than kern's, so runs of spaces are one space.
  sed -E 's/^[a-zA-Z0-9_.-]+ +\| //; s/^([0-9]{3})([A-Z][A-Z0-9_]{2,}:)/\1\n\2/; s/ +/ /g' "$1" |
    grep -aE '^[A-Z][A-Z0-9_]{2,}(:[^ ]*)?( .*)?$|^[0-9]{3}$' |
    grep -avE '^(WALL|NAME |ERROR|WARNING|Step|SHA256|S[12]:|M[12]:|PORT_LINE:)' |
    sed -E 's/^PORTS:.*/PORTS:<random>/; s/MATMUL .*/MATMUL <value>/' |
    sort
}

cases_of() {
  local d
  d=$(suite_dir "$1") || return
  for c in "$d"/*/; do
    c=${c%/}
    [ -f "$c/run.sh" ] && echo "$1/$(basename "$c")"
  done
}

list=("$@")
if [ ${#list[@]} -eq 0 ]; then
  for s in $SUITES; do
    while read -r c; do list+=("$c"); done < <(cases_of "$s")
  done
fi

docker_before=$(docker ps -aq | sort)
# The exited rows kern already lists, by name and pid: only the ones a case adds are its leftovers,
# as for Docker's containers above. Counting every row counted boxes of earlier runs on the host.
kern_rows() { kern ps -a 2>/dev/null | awk '/ exit [0-9]/ {print $1" "$2}' | sort; }
kern_rows_before=$(kern_rows)
same=0 expect=0 unexpected=0
report="$WORK/report.txt"
: > "$report"
for sc in "${list[@]}"; do
  suite=${sc%%/*}
  name=${sc#*/}
  src="$(suite_dir "$suite")/$name"
  [ -f "$src/run.sh" ] || { echo "$sc: no such case" | tee -a "$report"; unexpected=$((unexpected + 1)); continue; }
  for eng in docker kern; do
    case $eng in
      docker) C="docker compose" ;;
      kern)
        C="kern compose"
        if gpu_case "$sc" && [ "$GRANT" = flag ]; then C="kern compose --allow-device-grants"; fi
        ;;
    esac
    w="$WORK/$suite-$name-$eng"
    rm -rf "${w:?}"
    mkdir -p "$w"
    (cd "$src" && tar --exclude='./out.*' --exclude='./work' -cf - .) | (cd "$w" && tar -xf -)
    # Per-case hygiene the cases cannot do themselves (see the round-1 notes).
    case $sc in
      set1/case3 | set1/case3fix) : > /tmp/kern_case3_known ;;
    esac
    [ "$sc" = set1/case3 ] && [ "$eng" = docker ] && docker rmi kern-case3-ssh-ssh:latest >/dev/null 2>&1
    (
      cd "$w" || exit 2
      if [ -f setup.sh ] && [ ! -f "$src/.setup-done" ]; then sh setup.sh > setup.log 2>&1; fi
      [ -f compose-in-proj.yml ] && cp compose-in-proj.yml proj/docker-compose.yml
      start=$(date +%s)
      COMPOSE="$C" timeout 600 bash run.sh > "$WORK/$suite-$name.out.$eng" 2>&1
      echo "WALL:$(( $(date +%s) - start ))s" >> "$WORK/$suite-$name.out.$eng"
    )
    # WHAT THIS CASE LEFT RUNNING, counted before the cleanup below so a leak is reported, then
    # removed so the next case starts clean. The cleanup takes the case's own COMPOSE_FILE and
    # COMPOSE_PROJECT_NAME and every profile (Docker's `down` without the profile leaves a
    # profile-gated service running, measured on set3/g5).
    if [ "$eng" = kern ]; then
      n=$(kern ps -q 2>/dev/null | grep -c . || true)
    else
      n=$(docker ps -q | wc -l)
    fi
    [ "$n" -gt 0 ] && printf '%-18s LEFT %s running on %s\n' "$sc" "$n" "$eng" | tee -a "$report"
    (
      cd "$w" || exit 0
      [ -d proj ] && cd proj
      eval "$(grep -E '^export COMPOSE_(FILE|PROJECT_NAME)=' "$w/run.sh" 2>/dev/null)"
      COMPOSE_PROFILES='*' timeout 120 $C down -v > /dev/null 2>&1
    )
  done
  d="$WORK/$suite-$name.out.docker"
  k="$WORK/$suite-$name.out.kern"
  if diff -q <(markers "$d") <(markers "$k") > /dev/null; then
    same=$((same + 1))
    printf '%-18s SAME      %s\n' "$sc" "$(markers "$d" | tr '\n' ' ' | cut -c1-110)" | tee -a "$report"
  elif why=$(expected "$sc"); then
    expect=$((expect + 1))
    printf '%-18s EXPECTED  %s\n' "$sc" "$why" | tee -a "$report"
  else
    unexpected=$((unexpected + 1))
    printf '%-18s DIFFERENT\n' "$sc" | tee -a "$report"
    diff <(markers "$d") <(markers "$k") | sed 's/^/                   /' | tee -a "$report"
  fi
done

# What a run left behind: kern boxes and exited rows, and Docker containers created during the run.
left_kern=$(kern ps -q 2>/dev/null | grep -c . || true)
left_rows=$(comm -13 <(echo "$kern_rows_before") <(kern_rows) | grep -c . || true)
# Docker's legacy builder leaves one exited container per failed RUN step (set1/case3 builds a
# broken Dockerfile on purpose): no compose label, created during this run. Removed and counted apart.
build_leftovers=0
for id in $(comm -13 <(echo "$docker_before") <(docker ps -aq | sort)); do
  if [ -z "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id" 2>/dev/null)" ]; then
    docker rm "$id" > /dev/null 2>&1 && build_leftovers=$((build_leftovers + 1))
  fi
done
docker_after=$(docker ps -aq | sort)
left_docker=$(comm -13 <(echo "$docker_before") <(echo "$docker_after") | grep -c . || true)
{
  echo
  echo "cases: ${#list[@]}  same: $same  expected difference: $expect  UNEXPECTED: $unexpected"
  echo "left behind: kern boxes $left_kern, kern exited rows $left_rows, docker containers $left_docker (plus $build_leftovers failed-build step containers of Docker's builder, removed)"
} | tee -a "$report"
exit "$unexpected"
