# Agent Instructions

Educational Diffie-Hellman demo: two independent Flask services (Alice and
Bob) that exchange only public parameters over HTTP inside Docker, deployed
behind a Cloudflare Tunnel at `dh.maxthecoder.online`. Course deliverable —
no test suite, no CI, Spanish UI/comments.

## Hard rules

**Two apps, no shared memory.** `alice/` and `bob/` are separate containers
and processes. Never merge them, never share state via volumes, Redis, or
a database. Each process must compute its own private key, `S`, and `K`.

**The DH protocol carries only `{p, g, A}` (Alice→Bob) and `{B}`
(Bob→Alice).** Private keys (`a`, `b`) and the secret `S` must never be
sent between the two services. Bob's `GET /estado` is demo-only UI
introspection — do not treat it as part of the protocol, and do not add
similar endpoints that leak `K` outside of that documented purpose.

**Print every value to stdout.** Each process must log `p`, `g`, private
key, public key, `S`, `K`, and the equality check on every exchange —
`docker logs dh-alice` / `docker logs dh-bob` are the primary validation
path.

**Group parameters are fixed:** RFC 3526 MODP 2048-bit (group 14), `g = 2`,
256-bit exponents, `K = SHA-256(S)` hex. Do not "upgrade" to a different
curve or library that hides the math — the point is showing `pow(g, x, p)`.

**No published host ports.** Both services join the external Docker network
`services` (same network as `cloudflare-tunnel`). Traffic enters only via
the tunnel. Do not add `ports:` to `docker-compose.yml`.

**Try/except everywhere it matters:** key generation, parameter validation
on Bob's side, HTTP calls with timeouts, and `S`/`K` computation. Errors
return JSON with an appropriate status code and log to stdout.

## Language

Code comments, UI strings, commit messages, and docs are written in
**Spanish** (this is a Spanish-language course deliverable). AGENTS.md stays
in English for tooling consistency with other repos.

## Layout

```
alice/          Flask app + UI (public entry)
bob/            Flask app (internal only)
evidencias/     screenshots + docker logs (committed deliverable)
docker-compose.yml
setup_cloudflare.sh   # public hostname + CNAME via Cloudflare API
```

## Deploy

```sh
docker compose up -d --build
docker logs -f dh-alice   # watch validation
docker logs -f dh-bob
```

Cloudflare route (only if hostname changes): `bash setup_cloudflare.sh`.
It reads `~/.config/cloudflared/api.env` and must never echo the token.

## Evidence

After a behavior change, refresh files under `evidencias/` (screenshots of
both consoles showing matching `K`, and the UI check). Do not delete old
evidence without replacing it.
