#!/bin/sh
# Eval an untrusted snippet from the shell - for agents that SHELL OUT instead of importing an SDK.
#
# Not every agent uses the Python `kern_sandbox` package. Plenty just build a command string and run
# it. This is the shell-native equivalent: hand a snippet (in ANY language the image provides) to a
# fresh `kern box`, locked down hard, and read back the exit code as your signal. Here we eval shell
# one-liners in an alpine box; to eval node / ruby / python instead, swap `--image` and the interpreter
# (e.g. `--image node ... node -e "<snippet>"`) - the isolation is identical.
#
# The lockdown on every eval:
#   --read-only    whole root read-only (writes fail)
#   --network none  no network at all (isolated netns, loopback only) - the model can't phone home
#   --memory/--cpus/--pids-limit   resource caps (RAM ceiling, CPU share, fork-bomb containment)
#   --timeout      wall-clock kill switch, so a runaway snippet can't hang the agent
# On top of that a box always has an always-on seccomp denylist (mount/ptrace/kexec/... -> SIGSYS) and
# a private PID namespace. We CAPTURE the exit code (never let it abort the script) - that code is the
# result the agent reacts to.
#
# Honest threat model: a KERNEL-boundary sandbox for YOUR OWN or SEMI-TRUSTED (agent-authored) code.
# seccomp is a denylist - right for agent code, not a hard multi-tenant wall (use a microVM for that).
set -eu
kern="${KERN:-kern}"
n=0

# Eval one untrusted shell snippet in a locked-down throwaway box; print the captured exit code.
eval_untrusted() {
  label="$1"; snippet="$2"
  n=$((n + 1))
  printf '%s\n  snippet: %s\n' "$label" "$snippet"
  # Disable errexit around the eval so a non-zero exit is DATA we capture, not a script abort.
  set +e
  "$kern" box "eval-$$-$n" --image alpine --read-only --network none \
    --memory 128m --cpus 0.5 --pids-limit 64 --timeout 5 -- \
    sh -c "$snippet"
  code=$?
  set -e
  printf '  -> exit code: %s\n\n' "$code"
}

# 1) A well-behaved snippet: computes and prints. exit 0 - the agent reads stdout + a 0 code.
eval_untrusted "1) a benign eval:" 'echo $((6 * 7))'

# 2) Exfiltration attempt: reach out to the network. There is none, so the connect fails and the
#    snippet exits non-zero - the agent sees a failure code, and nothing left the box.
eval_untrusted "2) an exfiltration attempt (no network):" \
  'wget -q -T 3 -O- http://1.1.1.1 && echo LEAKED || echo "no route out of the box"'

# 3) Write attempt on the read-only root: denied. Non-zero exit tells the agent the write failed.
eval_untrusted "3) a write attempt (read-only root):" \
  'touch /pwned && echo WROTE || echo "write denied (read-only)"'

# 4) A runaway loop: --timeout is the kill switch. The box is reaped and the snippet exits non-zero
#    (137/143 = killed by signal) instead of hanging the agent forever.
eval_untrusted "4) a runaway loop (killed by --timeout):" 'while true; do :; done'

echo "done - each snippet evaluated in its own locked-down box; the exit code is the agent's signal."
