Web cache deception is a security vulnerability that allows an attacker to get a web cache (CDN, reverse proxy, or the origin server's own cache) to store a page containing **dynamic, user-specific content** by tricking it into believing the requested resource is a **static** one. When a victim later requests the crafted URL, their private response gets cached; the attacker then requests the same URL and retrieves the victim's data straight from the cache.

This is the inverse problem of web cache **poisoning**: instead of injecting malicious content into the cache, the attacker abuses a *discrepancy* between how the cache and the origin server each parse the URL to get something private cached under an attacker-chosen path.

You can identify that a resource was cached by checking the response headers:

- `X-Cache: hit` — generic/Varnish/Nginx-style cache
- `Cache-Control` set to `public` with `max-age` greater than `0`
- `Age` header present and greater than `0` (indicates the response has been served from cache for that many seconds)
- `CF-Cache-Status: HIT` — Cloudflare
- `X-Cache: Hit from cloudfront` — CloudFront
- `X-Proxy-Cache: HIT` — Nginx
- `Akamai-Cache-Status: HIT` — Akamai
- `X-Varnish` header with two IDs — Varnish (the second ID indicates a cache hit)

A `MISS`/`EXPIRED`/`BYPASS`/`DYNAMIC` value on a repeat request is a strong signal the path is **not** being cached and the technique needs adjusting.

Here are the core techniques:

Path mapping discrepancies]]
delimiter discrepancies]]
URL Normalization discrepancies by the origin server
URL Normalization discrepancies by the proxy server

### Path mapping discrepancies

Some web servers/frameworks map any path with a trailing static-looking segment to the same dynamic route, while the cache only looks at the file extension to decide whether to cache.

`http://vulnerable.com/user/private`

Append a fake static filename as an extra path segment and check whether the response gets cached (repeat the request and look for the cache-hit headers above):

`http://vulnerable.com/user/private/crafted.js`

Try a range of extensions the cache is likely to treat as static, e.g. `.js`, `.css`, `.png`, `.jpg`, `.ico`, `.woff`, `.pdf`, `.txt` — different CDNs use different static-extension allowlists.

### Delimiter discrepancies

Some parsers stop reading the "path" at a delimiter character, treating everything after it as extra/ignorable, while the cache still keys on (or inspects the extension of) the full raw string. If the origin ignores everything from the delimiter onward but still serves the private page, and the cache is fooled into treating the request as a static file because of the trailing extension, you get deception:

`http://vulnerable-site.com/user/private;aaa.css`

List of delimiters worth fuzzing (raw and URL-encoded forms — always test both, since the cache and origin may decode inconsistently):

```
!
"
#
$
%
&
'
(
)
*
+
,
-
.
/
:
;

=
>
?
@
[
\
]
^
__
`
{
|
}
~
%21
%22
%23
%24
%25
%26
%27
%28
%29
%2A
%2B
%2C
%2D
%2E
%2F
%3A
%3B
%3C
%3D
%3E
%3F
%40
%5B
%5C
%5D
%5E
%5F
%60
%7B
%7C
%7D
%7E
```

`#` and `?` are especially interesting since many frameworks treat everything after them (fragment/query string) as non-path, but some caches include the query string in the file-extension check.

### URL Normalization discrepancies by the origin server

Here the **origin server** normalizes/collapses a path-traversal-like sequence before routing the request, while the **cache** evaluates the raw, un-normalized path to decide cacheability. We can (ab)use the traversal sequence `../` (and its encoded variants) for this:

`http://vulnerable-site.com/<static-directory>/..%2f<dynamic-page>`

The cache sees a path ending in what looks like it's still under `<static-directory>` (often with a static-looking extension appended) and caches it, while the origin server decodes `%2f` → `/`, resolves `../`, and actually serves `<dynamic-page>`.

Also test double-encoding (`%252e%252e%252f`), backslash variants (`..%5c`), and Unicode/overlong-UTF8 traversal encodings, since different origin frameworks normalize these differently.

### URL Normalization discrepancies by the proxy/cache server

This is the mirror image: the **cache/proxy** normalizes the path before generating its cache key, while the **origin** does not (or normalizes differently), so a path that looks dynamic to the origin looks static to the cache:

`http://vulnerable-site.com/<dynamic-path>%2f%2e%2e%2f<static-directory>`

Here the cache normalizes `%2f%2e%2e%2f` → `/../` → collapses the path down to `<static-directory>`, generates a cache key for a static resource, and stores the response — while the origin server (which does not normalize the same way) still routes the request to `<dynamic-path>` and returns the victim's private data.

## Exploiting

1. **Discover** which discrepancy technique works against the target by requesting a crafted URL twice and checking for cache-hit headers on the second request.
2. **Confirm data leakage** — verify the cached response genuinely contains sensitive, per-user content (session tokens, PII, CSRF tokens, API keys) and not just a generic/error page.
3. **Craft the delivery URL**, e.g. `http://vulnerable-site.com/user/private/malicious.css`.
4. **Deliver** the URL to the victim (phishing link, malicious `<img>`/`<link>` tag on a page the victim visits, stored XSS, etc.) so their authenticated request populates the cache.
5. **Retrieve the cached response** yourself, unauthenticated, from the same URL, and extract the victim's data.
6. If the cache is shared across all users (rather than keyed per-session), a single successful deception can compromise **many** victims until the cache entry expires or is purged.

Impact typically includes session hijacking (leaked session cookies/tokens), CSRF token theft (enabling further attacks), or exposure of PII/account details.

### Preventing

- Set `Cache-Control: no-store, private` (or `no-cache` if some caching is still desired but revalidation is required) on **all** endpoints that return dynamic, user-specific content.
- Configure the cache to key strictly on file extension **as validated by the origin**, not by pattern-matching the raw URL — or disable caching by extension entirely and use explicit allowlisting of static paths instead.
- Ensure the origin server and the cache/CDN use the **same URL normalization and parsing logic** (same handling of `../`, encoded delimiters, trailing segments, query strings) so neither can be fooled independently of the other.
- Where possible, have the cache honor `Vary` and cache-control directives from the origin rather than relying purely on file-extension heuristics.
- Add automated regression testing (e.g. request known deception patterns against staging/production and assert no `HIT` is returned for authenticated/dynamic routes) as part of CI.
