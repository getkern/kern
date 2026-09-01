#!/bin/sh
# "curl https://.../install.sh | sh" - but safely. Before trusting an install script, run it in a
# disposable kern box: a writable overlay it can scribble on, but NO network and NO host mounts,
# so it can't phone home or touch your real machine. Watch what it does; the box vanishes after.
#
# Real-life: vetting a vendor install script, a postinstall hook, or a "just pipe this to sh".
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


# A stand-in for the script you fetched. Swap in your own (bind it read-only with -v).
script='echo "[script] hello"; echo "[script] trying to read your SSH key..."; \
        cat /root/.ssh/id_rsa 2>&1 || echo "[script] ...denied (isolated /root)"; \
        echo "[script] trying to phone home..."; \
        wget -qT3 -O- https://example.com >/dev/null 2>&1 && echo "[script] reached internet" \
        || echo "[script] ...no network"; \
        echo "[script] writing /usr/local/bin/backdoor"; echo x > /usr/local/bin/backdoor; \
        echo "[script] done"'

echo "==> running the untrusted script in an isolated box (no --net, no -v):"
"$kern" box vet --image alpine -- sh -c "$script"

echo
echo "It ran in a throwaway overlay with no network and no access to your files."
echo "The /usr/local/bin/backdoor it wrote is gone - it only existed inside the box."
