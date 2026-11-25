# Egress allowlist (`--egress-allow`): threat model & design

> Written **before** the code, on purpose. Egress filtering is the one feature where a half-honest
> implementation is worse than none: it invites a false sense of safety. This document states exactly
> what the allowlist enforces, what it does **not**, and why.
>
> **Status.** The three gaps this doc originally flagged are now closed: the box exits cleanly
> (the helper is spawned in the host PID namespace, before the box's `unshare(CLONE_NEWPID)`, so it
> never becomes the box-pidns zombie that used to deadlock teardown; a `-d` box's runner does the
> same before every attempt, `--restart` included); an allowlisted NAME that resolves to a
> loopback / link-local / `169.254.169.254` / RFC-1918 IP is refused (resolved-IP SSRF guard); and only
> ports 80/443 are tunnelled. The one hole that remains is inherent to any name-based HTTP-proxy
> allowlist and is stated plainly below: an allowed domain on a **shared CDN** reaches every other
> tenant of that CDN.

## What it is

`kern box … --egress-allow pypi.org,files.pythonhosted.org` gives a box outbound network access **only
to the listed domains** (and their subdomains). An agent can `pip install` from PyPI but cannot exfiltrate
to an arbitrary host. Without the flag the box's default is unchanged: **no outbound at all** (an isolated
loopback-only netns). `--egress-allow` is strictly *more* open than the default, never less.

## Addresses, ranges, `*` and `--egress-deny`

`--egress-allow` takes more than domains:

- an **address** or a **range**, `203.0.113.7` or `10.1.2.0/24` (IPv6 too, `2001:db8::/32`). A range
  written here may be **private**: `--egress-allow registry.internal,10.1.2.0/24` lets the box reach an
  internal registry by name, since the name may then resolve into that range;
- `*`, any **public** host, by name or by address.

`--egress-deny` takes domains, addresses and ranges that are refused **even when the allowlist covers
them**: deny wins, for the name in the request and for every address that name resolves to (one
resolved address inside a denied range refuses the whole name). Given alone, it means
`--egress-allow '*'` minus these:

```
kern box … --egress-deny github.com,203.0.113.0/24 --image python:3.12-slim -- …
```

Some addresses no rule opens, `0.0.0.0/0` included: loopback, link-local (the cloud metadata service,
`169.254.169.254`), multicast, broadcast and unspecified. A list kern cannot read is refused before the
box starts (`--egress-deny '*'` too: that is a box without a network).

## The client inside the box has to speak proxy

kern hands the box the allowlist as a **forward proxy** and exports `http_proxy`, `https_proxy` and
their uppercase spellings into its environment, so anything that honours those variables works with
no change: `curl`, `pip`, `npm`, Go, Python's `urllib` and `requests`.

One common client does not, and it is the one in the smallest image people reach for first. Alpine's
default `wget` is busybox's, and busybox does not implement the `CONNECT` tunnel that HTTPS through a
proxy needs. Measured with `--egress-allow example.com`:

| client | `http://` | `https://` |
|---|---|---|
| busybox `wget` (alpine's default) | works | **fails**, `wget: error getting response` |
| `curl` | works | works |

So a first attempt with `kern box … --image alpine --egress-allow example.com -- wget https://example.com`
reports a failure that is not the allowlist refusing anything: it is the client. `apk add curl` in the
image, or any of the runtimes above, and the same box reaches the allowlisted host and nothing else.

## Keys the box never holds: `--egress-secret`

```sh
export OPENAI_API_KEY=sk-...        # in the shell that starts the box, not in the box
kern box agent --image python:3.12 \
  --egress-secret host=api.openai.com,header=Authorization,env=OPENAI_API_KEY,scheme=Bearer \
  -e OPENAI_BASE_URL=http://api.openai.com/v1 -e OPENAI_API_KEY=unused \
  -- python agent.py
```

The box sends plain `http://` to the host, through the proxy, without the key. The proxy drops any
header of that name the box sent, adds the real one, and sends the request on as `https://` itself,
through this machine's `curl`, pinned to the address it vetted under the same rules as every other
request. The answer comes back with every verbatim copy of the key replaced by `[kern-secret]`.
`file=/path` reads the key from a file instead of a variable; `scheme=` puts a word before it.

Measured against `httpbin.org`, which echoes what it receives:

| request from the box | what the box gets |
|---|---|
| `GET http://httpbin.org/bearer`, no key | `200`, `"authenticated": true, "token": "[kern-secret]"` |
| the same with its own `Authorization: Bearer fake` | the upstream saw kern's key, not `fake` |
| `POST` with a body | body and `Content-Type` arrive, key added |
| a chunked stream (`/stream/3`) | 3 lines, as sent |
| `CONNECT httpbin.org:443` | `403`: a host with a key is reached only through the proxy's own request |

The key was not in the box's environment, in `kern inspect`, in any of the registry's files, or in
any process's arguments; the proxy holding it is not dumpable, so another process of the same user
cannot read its memory or environment.

What it does not do: a key the upstream sends back in pieces or transformed is not recognised. A body
sent with `Transfer-Encoding: chunked` is refused with 411, a WebSocket upgrade with 501. One rule per
host, matched by exact name (a subdomain gets no key). The host is added to `--egress-allow`.

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
   This is **fail-closed**: if either helper fails to start (or dies), the box's isolated netns still has
   no route, so the box gets *no* outbound rather than an unfiltered one. A helper failure can only make
   egress more restrictive, never open it.
3. **The proxy allowlists by the host the client names**: the `CONNECT host:port` target for HTTPS, or
   the request's `Host` / absolute-URI for plain HTTP. A host that is not the allowlist (or a subdomain of
   an entry), or that `--egress-deny` names, is refused with `403`, and no connection is dialed. An
   **IP-literal** target (`CONNECT 1.2.3.4:443`) never matches a domain entry: it passes only inside an
   allowed range, or as a public address under `*`, and never inside a denied range.
4. **The proxy pins the dialed host to what it allowed.** It resolves and connects to the *allowlisted*
   name itself; the client cannot ask it to connect to one host and stream to another. It connects only
   to a **public unicast** resolved address, or one inside a range the allowlist names (loopback /
   link-local / `169.254.169.254` / multicast never; RFC-1918 / ULA only when a written range covers
   them; nothing inside a denied range), which closes the SSRF where an allowlisted name resolves to a
   host-local service, and it tunnels **only ports 80 and 443**, so an allowlisted host's `:22` or
   `:6379` is not reachable.

Because the box has no route except the proxy (point 1), a workload that simply ignores `HTTP_PROXY` and
tries to open a raw socket to `evil.com:443` gets `ENETUNREACH`: there is nowhere for the packet to go.
The proxy is not a suggestion; it is the only door.

## What it does NOT stop (state it plainly)

- **Shared-CDN egress, over HTTPS only.** The client asks to `CONNECT allowed.com:443`, the proxy dials
  `allowed.com`, and then the HTTP request *inside* the TLS session carries `Host: other.com`. If both
  names are served by the same front (a shared CDN / IP), the CDN routes on that inner `Host` and the
  data reaches `other.com`. The proxy cannot see it: the header is inside TLS, and reading it would mean
  intercepting the session.
  **Over plain HTTP the same trick is REFUSED**, because there the header is in plaintext and this proxy
  reads it: a head whose `Host:` names a different host than the vetted request-target gets 403, and so
  does a head carrying more than one `Host:` line (RFC 9112 makes that message invalid, and the reason is
  this exact disagreement - we vet one field and an upstream may honour another). Measured from outside
  against the previous release, where `GET http://pypi.org/` with `Host: www.python.org` was served as
  `www.python.org`.
  **This is NOT the SNI-mismatch case, and checking the SNI would not close it.** Measured on 0.31.0 with
  an allowlist of `pypi.org`: `CONNECT pypi.org` carrying SNI *and* `Host: www.python.org` is served, and
  so is `CONNECT pypi.org` with **SNI `pypi.org`** - a certificate that matches the name the proxy
  allowed - and only the inner `Host` pointing elsewhere. A ClientHello check would pass that second case
  unchanged, which is why this document no longer names one as a planned hardening.
  **If your allowlist includes a domain on a big CDN, treat egress as open to every tenant of that CDN,
  including one an attacker registers there.** Allow only origins you know are not shared, or use the VM
  tier.
  🚨 **And the example this page uses is one of them.** Measured: `pypi.org` resolves into Fastly's
  range (`151.101.0.223`) and answers with Fastly cache headers (`x-served-by: cache-iad-...`), and
  `files.pythonhosted.org`, which is where `pip` actually downloads from, is a CNAME to
  `dualstack.python.map.fastly.net`. So an allowlist written to let `pip install` work has allowed
  Fastly, which is the most common reason anyone turns this flag on. The advice above is honest but it
  is not free: applied strictly it excludes PyPI.
  For installing packages there is a better-shaped answer already in the product, and it is the default:
  **the network stays off, and a one-time `setup=` runs in a network-on box that dies afterwards**, so
  the allowlist is never the thing standing between a long-lived box and the internet.
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
| Connecting an allowlisted NAME that resolves to a private/loopback/metadata IP | **Hard** (resolved-IP guard: the proxy refuses the WHOLE name if ANY resolved record is non-public: loopback / link-local / `169.254.169.254` / RFC-1918 / ULA / multicast, incl. IPv4-mapped IPv6 like `::ffff:127.0.0.1`. It does not "pick the public one" from a mixed record set, so a clever-DNS operator can't order/flip records to reach a host-local service.) |
| Restricting the PORT on an allowlisted host | **Hard** (only 80 and 443 are tunnelled; `:22`, `:6379`, … are refused) |
| An allowed domain on a SHARED CDN reaching every other tenant of it, over **HTTPS** | **Not addressed, and not addressable by this design**: the CDN routes on the HTTP `Host` INSIDE TLS, so a matching SNI does not help and only an intercepting proxy could see it |
| The same, over **plain HTTP** | **Hard**: the `Host:` header is in plaintext, so a head that names a host other than the vetted request-target is refused, as is a head with more than one `Host:` line |
| Covert channel inside an allowed session | **Not addressed** (this is an allowlist, not DLP) |

The rule of thumb kern states everywhere applies here too: this is a strong control for first-party and
semi-trusted workloads, and it is honest about the microVM-shaped hole it does not fill.
