#!/bin/sh
# Fan a per-FILE job across a directory: each input file is processed in its OWN
# capped, isolated box. Because every file gets a throwaway sandbox, a crash or a
# timeout on ONE file cannot take down the batch - the other boxes keep going.
# Results are collected back on the host via `-v` (the input dir is mounted :ro,
# so a job can never mutate your source data).
#
# Real-life: per-tenant log crunching, untrusted upload processing, a flaky
# converter you don't want to trust with the whole run at once.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/in" "$work/out"

# Four inputs. Each is "valid" (contains the marker OK) EXCEPT poison.txt, whose
# job will exit non-zero - standing in for a real crash/bad record. Its box fails
# in isolation; the other three still produce output.
printf 'OK alpha\nOK beta\n'   > "$work/in/one.txt"
printf 'OK gamma\n'            > "$work/in/two.txt"
printf 'no marker here\n'      > "$work/in/poison.txt"
printf 'OK delta\nOK epsilon\n'> "$work/in/three.txt"

echo "==> processing $(ls "$work/in" | wc -l) files, one capped box per file:"
ok=0; failed=0
for path in "$work/in"/*; do
  name="$(basename "$path")"
  # Each file gets its own box, capped in memory/CPU and time-bounded so a hang
  # can't wedge the batch. The job VALIDATES (grep -q OK) then transforms: files
  # without the marker exit 1 and their box fails - deliberately, in isolation.
  #
  # `set -e` would abort the whole script on the first failing box, so we guard
  # the call with `if` and tally the outcome ourselves.
  if "$kern" box "job-$name" --image alpine \
        --memory 128m --cpus 1 --timeout 30 \
        -v "$work/in:/in:ro" -v "$work/out:/out" -- \
        sh -c 'f="/in/'"$name"'"; grep -q OK "$f" || { echo "  [FAIL] '"$name"': no OK marker" >&2; exit 1; }
               tr a-z A-Z < "$f" > "/out/'"$name"'"; echo "  [ok]   '"$name"' -> $(wc -l < "/out/'"$name"'") lines"'
  then
    ok=$((ok + 1))
  else
    failed=$((failed + 1))
  fi
done

echo
echo "==> batch summary: $ok succeeded, $failed failed (the batch did NOT abort)."
echo "==> outputs collected on the host (only the successful jobs wrote a file):"
for f in "$work/out"/*; do
  [ -e "$f" ] || { echo "  (no outputs)"; break; }
  echo "  --- $(basename "$f") ---"; sed 's/^/    /' "$f"
done
echo
echo "done - poison.txt's box failed alone; the input dir was :ro and untouched;"
echo "the throwaway boxes are already gone."
