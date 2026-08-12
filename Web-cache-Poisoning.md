Web cache poisoning is a vulnerability that allows an attacker to get malicious content stored in a shared cache, so that it gets served to **other, unsuspecting users** who later request the same cached URL — turning a single successful attack into one with potentially massive blast radius (every visitor of a popular page until the entry expires or is purged).

To successfully exploit a web cache poisoning vulnerability, you first need to find an **unkeyed input**: a header, query parameter, or cookie that the *origin server* processes and reflects into the response, but that the *cache* does **not** include as part of its cache key. Since the cache key ignores it, the cache will happily serve the same cached (poisoned) response to every user, regardless of what value they themselves sent for that input.

## Methodology

1. **Find a cacheable, high-traffic page.** Impact scales with popularity, so prioritize pages likely to be requested by many users (homepage, login page, popular product/blog pages). Confirm the response is actually being cached by checking the HTTP response headers — covered in detail in [[Web-cache-deception]] (`X-Cache: hit`, `CF-Cache-Status: HIT`, `Age > 0`, etc.).

2. **Add a cache buster.** Use a unique, unkeyed query string parameter on every test request so you're never poisoning (or being served) the *real* cache entry that live users hit — you want your own isolated, disposable cache entry to experiment safely on.

   ```http
   GET /?cb=825ce5c1 HTTP/1.1
   Host: vulnerable-example.com
   ```

   Generate a fresh random value for each test iteration; reusing the same buster across tests will just keep hitting your own previous (possibly already-poisoned) entry and give misleading results.

3. **Identify an unkeyed input.** This can be an unkeyed header, unkeyed query parameter, or unkeyed cookie. Manually, you can send two identical requests with a different value for a candidate input and see if the cached response changes between them. At scale, use Burp's **Param Miner** extension to automate discovery — it will actively probe hundreds of common header/param names and flag which ones affect caching behavior.

4. **Check for reflection.** Once you've found an unkeyed input, check whether its value is reflected somewhere in the response body (or response headers) without proper sanitization/encoding. If it is, you can escalate from "just poisoning" to concrete impact — most commonly stored XSS, but also open redirects, or JS-file/CSS-file content substitution.

5. **Confirm the poison actually gets served from cache.** Send the malicious payload once (with the cache buster), then send a *second, clean* request with the **same cache buster and no malicious payload** — if the malicious content still comes back, you've confirmed the cache is serving your poisoned entry to any subsequent requester, not just reflecting live on every request.

6. **Escalate / weaponize.** Once confirmed on your cache-buster'd entry, remove the buster (or wait for/trigger the real cache key to be poisoned) so the payload is served on the actual live, popular URL to real victims.

### Attack construction

Below are common unkeyed-input categories and example payloads for each.

- Unkeyed header

  Headers are very commonly unkeyed even when their value is used server-side (canonical URLs, redirect targets, CORS reflection, etc.):

  ```http
  GET / HTTP/1.1
  Host: vulnerable-example.com
  X-Forwarded-Host: attacker-controlled.com
  ```

  If `X-Forwarded-Host` gets reflected into an absolute URL, canonical `<link>` tag, or a resource `src` attribute in the cached page, you can point it at an attacker-controlled domain and serve malicious JS/CSS to every subsequent visitor.

- Unkeyed query parameter

  Tracking/analytics parameters (`utm_content`, `utm_source`, `ref`, `fbclid`) are frequent offenders — they're intentionally excluded from cache keys (so `?utm_source=twitter` and `?utm_source=facebook` don't fragment the cache) but are often still reflected server-side for logging or personalization:

  ```http
  GET /?utm_content="><script>alert(document.domain)</script> HTTP/1.1
  Host: vulnerable-example.com
  ```

- Fat GET request

  Some servers accept a request body on a `GET` request and process it identically to query parameters, while the cache only keys on the URL/query string and ignores the body entirely:

  ```http
  GET /?param=<param-value> HTTP/1.1
  Host: vulnerable-example.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: <length>

  param="><script>alert(document.domain)</script>
  ```

  Because the cache key is derived only from the URL, an attacker can poison the cache via the body while every subsequent (bodyless) `GET /` to that same URL serves the poisoned response.

- Unkeyed cookie

  Cookies used for A/B testing, language/locale preferences, or feature flags are also commonly excluded from the cache key while still being reflected or used to alter the response:

  ```http
  GET / HTTP/1.1
  Host: vulnerable-example.com
  Cookie: language=<script>alert(document.domain)</script>
  ```

## Impact

- **Stored/persistent XSS** at scale — no need to trick each victim individually, since the cache does the distribution for you.
- **Defacement** of high-traffic pages.
- **Serving malicious JS/CSS resources** to every visitor by poisoning a cached static-asset response.
- Can be chained with [[Web cache deception]] concepts and with DOM clobbering or open-redirect primitives for further impact.

## Preventing

1. **Avoid caching responses that vary based on headers, cookies, or parameters** unless those inputs are properly included in the cache key (`Vary` header, or cache-key configuration on the CDN).
2. **Never reflect unsanitized user input** (headers, params, cookies) into HTML, JS, or redirect targets, regardless of whether that input is "just" used for logging/analytics.
3. **Disable unnecessary Host-header-derived or forwarded-header-derived logic** in code paths that generate cached content (canonical URLs, resource links) — use a hardcoded, server-side canonical hostname instead.
4. **Configure the cache to have the narrowest possible key** that still correctly reflects what actually changes the response — err on the side of including more inputs in the key rather than fewer.
5. **Regularly audit with Param Miner (or equivalent)** as part of routine testing/CI to catch newly introduced unkeyed inputs before they reach production.
