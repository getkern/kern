# Egress allowlist (`--egress-allow`): threat model & design

> Written **before** the code, on purpose. Egress filtering is the one feature where a half-honest
> implementation is worse than none: it invites a false sense of safety. This document states exactly
> what the allowlist enforces, what it does **not**, and why.

## What it is

`kern box … --egress-allow pypi.org,files.pythonhosted.org` gives a box outbound network access **only
to the listed domains** (and their subdomains). An agent can `pip install` from PyPI but cannot exfiltrate
to an arbitrary host. Without the flag the box's default is unchanged: **no outbound at all** (an isolated
loopback-only netns). `--egress-allow` is strictly *more* open than the default, never less.

## How it is enforced (the enforceable part)

1. **The box runs in an isolated network namespace.** It has loopback and nothing else: no route to the
   internet, no DNS, no default gateway. This is a **real kernel boundary**: the box, even as root in
   its user namespace, cannot add a route or an interface to reach the outside. This is the load-bearing
   property: everything below only matters because the box has no *other* way out.
2. **The only egress is a kern-controlled HTTP proxy.** kern runs two helper processes it owns, outside
   the box's control:
   - a **pump** joined to the box's network namespace, listening on `127.0.0.1:<port>` inside the box,
     that relays bytes to a host-side UNIX socket (UNIX sockets are not namespaced, so they bridge the
     box netns to the host without giving the box a network route);
   - a **filtering proxy** in the host network namespace, listening on that UNIX socket, that parses each
     request and dials out **only** to an allowlisted host.
   `HTTP_PROXY` / `HTTPS_PROXY` / `http_proxy` / `https_proxy` are set in the box to point at the pump.
3. **The proxy allowlists by the host the client names**: the `CONNECT host:port` target for HTTPS, or
   the request's `Host` / absolute-URI for plain HTTP. A host that is not the allowlist (or a subdomain of
   an entry) is refused with `403`, and no connection is dialed. An **IP-literal** target (`CONNECT
   1.2.3.4:443`) never matches a domain entry, so it is refused too.
4. **The proxy pins the dialed host to what it allowed.** It resolves and connects to the *allowlisted*
   name itself; the client cannot ask it to connect to one host and stream to another.

Because the box has no route except the proxy (point 1), a workload that simply ignores `HTTP_PROXY` and
tries to open a raw socket to `evil.com:443` gets `ENETUNREACH`: there is nowhere for the packet to go.
The proxy is not a suggestion; it is the only door.

## What it does NOT stop (state it plainly)

- **Domain fronting / shared-CDN egress.** The client asks to `CONNECT allowed.com:443`, the proxy dials
  `allowed.com`, and then the client speaks TLS with `SNI=evil.com` inside that tunnel. If `evil.com` and
  `allowed.com` are served by the *same* front (a shared CDN / IP), data can reach `evil.com`. The proxy
  can optionally parse the TLS ClientHello SNI and require it to equal the `CONNECT` host (kern does this
  when it can read the ClientHello), which closes the *naive* case, but ECH/ESNI and true same-endpoint
  fronting remain out of scope. **If your allowlist includes a big CDN domain, treat egress as open to
  everything on that CDN.**
- **DNS exfiltration** is not a channel here (the box has no DNS; the proxy resolves), but a covert
  channel *inside* an allowed TLS session (timing, payload to an allowed host that then forwards) is not
  something a network allowlist can see. This is an allowlist, not a DLP.
- **A kernel-level network escape.** The isolation is the netns (a real boundary), but the *filtering* is
  cooperative in the sense that it inspects an application protocol. For a workload you assume is actively
  hostile and sophisticated, a microVM with a real firewall is the stronger tool. `--egress-allow` is for
  **semi-trusted** code (an agent running `pip`/`npm`/`curl` you don't fully trust) that must not phone
  home, not for defeating a determined, protocol-aware adversary.

## Summary

| Property | Strength |
|---|---|
| Box has no egress except the proxy | **Hard** (isolated netns; kernel-enforced) |
| Non-allowlisted domain refused | **Hard** for a normal client (proxy refuses `CONNECT`, no dial) |
| IP-literal target refused | **Hard** (never matches a domain entry) |
| SNI ≠ CONNECT host on a shared CDN | **Soft** (best-effort SNI check; fronting on a shared endpoint remains) |
| Covert channel inside an allowed session | **Not addressed** (this is an allowlist, not DLP) |

The rule of thumb kern states everywhere applies here too: this is a strong control for first-party and
semi-trusted workloads, and it is honest about the microVM-shaped hole it does not fill.
