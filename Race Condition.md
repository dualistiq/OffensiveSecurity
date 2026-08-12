Race conditions are vulnerabilities where the **timing** of concurrent events influences the behavior and outcome of the program. They typically occur when shared data (a variable, a database row, a balance, a counter) is read and then written by multiple threads/requests without proper locking or atomicity, creating a **window** between the "check" and the "use" of that data. If two requests land inside that window at the same time, they can both act on the same stale state — a "collision" — producing a result the application logic never intended to allow.

## Detecting

To exploit a race condition, you first need to find a place where a collision **might** occur. This is usually more difficult than the actual exploitation itself — it requires understanding the application's business logic, not just firing traffic at it. Common places to look:

- **Authentication mechanisms** — rate-limiting bypass (e.g. brute-forcing an OTP/password by sending all guesses simultaneously, since a counter-based limiter may not increment atomically), account-recovery token reuse
- **Redeeming gift cards / coupon / promo codes** — using the same single-use code multiple times before the "already redeemed" flag is committed
- **Money transfers / balance operations** — withdrawing, transferring, or spending more than the account's actual balance ("balance overrun") by submitting multiple simultaneous requests before the balance is decremented
- **Voting / rating / "like" systems** — inflating a count beyond a single-vote-per-user limit
- **Any multi-step workflow** where step 1 checks a condition and step 2 (a separate request) acts on it, with app state read/written in between

This list is defined entirely by the application's logic and is **not limited** to the examples above — think in terms of "check-then-act" logic anywhere in the app, and ask whether that check and that act happen atomically.

## Types of race conditions

### Limit overrun race conditions

The classic case: an operation is supposed to be limited to a single use (redeem one gift card once, apply one discount code once, submit one vote once), but sending many identical requests **simultaneously** causes the limit check to pass for more than one of them, because each request reads the "not yet used" state before any of them has finished writing the "used" state back.

### Time-of-check to time-of-use (TOCTOU)

A broader class where there's a gap between when a condition is *checked* and when it's *used/acted upon*, and that gap is exploitable regardless of whether a hard "limit" is involved — e.g. checking a file's permissions and then operating on it, or checking session validity and then performing a privileged action, with attacker-controlled state changing in between.

### Multi-endpoint race conditions

Instead of racing many identical requests against a **single** endpoint, this abuses the timing gap **between two different endpoints** — e.g. racing a "change email" request against an "email verification" request, or racing "add item to cart" against "apply discount" and "checkout", so that state changes on one endpoint aren't yet reflected when the other endpoint reads it.

## Identifying and Exploiting

Once you've found a candidate location, first determine whether the target supports `HTTP/1.1` or `HTTP/2` — this determines which synchronization technique you'll use to land requests as close to simultaneously as possible. The two main tools are **Burp Repeater** (manual confirmation) and **Turbo Intruder** (scripted exploitation at scale).

- **HTTP/1.1 — last-byte sync**

  Send the request to Repeater, group it into a new tab, and duplicate it (~20-30 copies is generally enough). Select the **"Send group in sequence (single connection)"** with the **last-byte sync** option, which holds back the final byte of every request until all requests are queued, then releases them together — minimizing the network jitter between when each request actually completes and is processed server-side.

- **HTTP/2 — single-packet attack**

  Same underlying goal, but HTTP/2 allows an even tighter attack: since multiple HTTP/2 requests can be sent within a **single TCP packet**, network jitter is eliminated almost entirely (all requests arrive at the server in the same instant, rather than merely close together). This is the more reliable technique when the target supports HTTP/2 and should be preferred whenever available.

> [!tip]
> Before racing, "warm up" the connection with a throwaway request first — the very first request on a fresh connection is often slower (TLS handshake, connection pool initialization) and can throw off timing on the real attempt.

Once you've confirmed the target is a viable candidate for a race (using manual Repeater grouping as above), use a Turbo Intruder script to actually exploit the vulnerability at scale, since Repeater alone doesn't give you the response-diffing/counting tools needed to reliably detect a successful collision across many attempts.

Default script template (from the Turbo Intruder examples directory):

```python
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if it only supports HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, see https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )

    # the 'gate' argument withholds part of each request until openGate() is invoked
    # if you see a negative timestamp in the results, the server responded before the request was fully sent
    for i in range(20):
        engine.queue(target.req, gate='race1')

    # once every 'race1'-tagged request has been queued,
    # invoke engine.openGate() to release them all in sync
    engine.openGate('race1')


def handleResponse(req, interesting):
    table.add(req)
```

Practical tuning notes:

- Start with `concurrentConnections=1` for the single-packet HTTP/2 attack (all requests share one connection by design); increase `concurrentConnections` only when deliberately racing across multiple TCP connections (e.g. for multi-endpoint races where each endpoint needs its own request stream).
- Increase the loop count (`range(20)`) if the collision window is very narrow and 20 attempts aren't reliably landing a hit — but be mindful this also increases load/noise against the target.
- For **multi-endpoint** races, queue requests to each endpoint under **different gate names** (or the same gate, timed deliberately), then call `openGate()` for each at the precise moment you want them to fire relative to one another.
- Inspect response status codes, bodies, and (crucially) timestamps in the `table` output to confirm whether more than one request "won" the race — that's your proof of a successful collision.

## Preventing

1. Use **atomic database operations** (e.g. `UPDATE ... WHERE balance >= amount`, atomic increment/decrement) instead of separate read-then-write logic.
2. Apply **row-level locking** or transactions with appropriate isolation levels around check-then-act sequences.
3. Enforce **idempotency keys** on sensitive one-time operations (redemptions, payments) so a duplicate concurrent request is rejected outright rather than reprocessed.
4. Rate-limit and lock based on the **user/session**, not just on IP, and ensure the rate-limit counter itself is updated atomically.
5. Where feasible, serialize sensitive multi-step workflows server-side so concurrent requests for the same resource queue rather than race.
