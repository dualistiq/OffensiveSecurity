Host header attacks abuse the fact that many applications trust the client-supplied `Host` header (or headers that override it) when generating absolute URLs, routing requests internally, building cache keys, or constructing SQL/OS commands — instead of relying on a server-side, hardcoded value.

## Identifying vulnerabilities

1. **Send a duplicate Host header**

	```http
	GET / HTTP/1.1
	Host: vulnerable-example.com
	Host: 192.168.0.0
	```

	Some front-end/back-end pairs disagree on which header wins, which can be abused for request smuggling or cache poisoning if either value is reflected.

2. **Send a request with an absolute-form request line**

	```http
	GET https://vulnerable-example.com/ HTTP/1.1
	Host: 192.168.0.0
	```

	RFC 7230 requires servers to prefer the request-line URI over the `Host` header when both are present — many implementations don't, and this discrepancy is exploitable.

3. **Overwrite the `Host` header itself**

> [!note]
> Use Burp Repeater (or another tool that separates the `Host` header value from the actual connection target) rather than a raw browser/curl request. Otherwise the TCP connection itself will be routed to whatever IP/host you put in the `Host` header, instead of being sent to the real target with a spoofed header.

```http
GET / HTTP/1.1
Host: 169.254.169.254
```

Useful for probing SSRF-style behavior when the application makes internal callbacks (password reset links, webhooks, SSO redirects) using the `Host` header value.

4. **Inject Host-override headers**

	Try each of the following (server frameworks and CDNs vary widely in which ones they honor):

	```
	X-Forwarded-Host
	X-Host
	X-Forwarded-Server
	X-HTTP-Host-Override
	X-Original-Host
	Forwarded: host=
	```

> [!tip]
> Use the **Param Miner** extension (Burp BApp Store) to brute-force for header names the app treats specially, rather than testing each one manually — there are more of these than the shortlist above, and Param Miner also detects unkeyed input generally (useful for cache-poisoning discovery).

5. **Manipulate the port portion of the Host header**

	Some applications parse the hostname but skip validating the port, letting you smuggle arbitrary data through:

```http
	GET / HTTP/1.1
	Host: vulnerable-example.com:whoami
	Host: vulnerable-example.com:$(whoami)
	Host: vulnerable-example.com:1'or'1'='1
```

6. **Check password-reset / "forgot password" flows specifically**

	Many of these email a link built from the `Host` header. Set `Host` to an attacker-controlled domain and request a password reset for a victim account (or your own, to confirm the behavior first) — if the emailed link points at your domain, you can host a page to harvest the reset token.

## Exploiting Host header vulnerabilities

### [[Web cache Poisoning]]

If you've found an **unkeyed** header (the cache doesn't include it in the cache key, but the origin reflects its value into the response — e.g. a duplicated `Host` header, or an `X-Forwarded-Host` value dropped into a canonical link tag or absolute URL), and that reflected response gets cached, you can poison the cache: every subsequent visitor requesting that same cached URL receives your injected content (e.g. a malicious `<script>` src pointed at your domain).

### Server Side vulnerabilities

Probe the `Host` header for classic server-side injection, since it's frequently passed unsanitized into backend logic:

- **SQL Injection** — if the Host value is logged to or queried against a database (e.g. multi-tenant apps that look up a tenant by hostname)
- **OS Command Injection** — if the Host value is passed to a shell command (e.g. for generating internal certs, logging, or virtual-host resolution)
- **Header/Log Injection** — CRLF sequences in the Host value reflected into logs or headers

### Routing based SSRF

Routing-based SSRF is a more dangerous variant of classic SSRF: instead of the *application* making an outbound request to an attacker-controlled URL, you abuse the **routing/infrastructure layer itself** (load balancers, reverse proxies, service meshes) which is prevalent in cloud-native architectures. By manipulating the `Host` header, you can potentially get the front-end infrastructure to route your request to an unintended back-end service — internal admin panels, other tenants' services, or cloud metadata endpoints — that would otherwise be unreachable from the public internet.

Use **Burp Collaborator** or **Interactsh** to get out-of-band confirmation of blind SSRF (no reflected output required — you just need the DNS/HTTP callback to fire), combined with the identification techniques above to locate the injection point.

Interesting internal targets to probe for once you have a routing primitive:

- Private IP ranges: `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`
- Cloud metadata service: `169.254.169.254` (AWS/GCP/Azure IMDS)
- Localhost/loopback: `127.0.0.1`, `localhost`, and non-standard ports on the target itself
- Internal DNS names (`*.internal`, `*.local`, Kubernetes service names like `<svc>.<namespace>.svc.cluster.local`)

## Preventing

1. **Validate the Host header** against a strict allowlist of expected values on every request; reject anything that doesn't match.
2. **Whitelist permitted domains** at the infrastructure layer (load balancer / WAF) as well as in application code, so a single missed check doesn't expose the whole stack.
3. **Don't trust HTTP override headers** (`X-Forwarded-Host`, `X-Original-Host`, etc.) unless they're explicitly required and equally validated — ideally strip them at the edge if your architecture doesn't need them.
4. **Never build absolute URLs, redirect targets, password-reset links, or SQL/OS commands directly from the Host header** — use a hardcoded, server-side canonical hostname instead.
5. **Ensure front-end and back-end components agree** on which Host value is authoritative when duplicates or conflicting values (header vs. absolute-form request line) are present, to eliminate discrepancy-based smuggling/poisoning.

