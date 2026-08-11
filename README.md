# Riot Take Home

[![CI](https://img.shields.io/github/actions/workflow/status/jolehuit/riot_take_home/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/jolehuit/riot_take_home/actions)
![Elixir](https://img.shields.io/badge/Elixir-1.19.5-4B275F?style=flat-square&logo=elixir&logoColor=white)
![OTP](https://img.shields.io/badge/OTP-28-A2003B?style=flat-square)
![Server](https://img.shields.io/badge/server-Bandit-0B7261?style=flat-square)
![Tests](https://img.shields.io/badge/tests-49%20passing-3FB950?style=flat-square)

A small HTTP API with four POST endpoints over JSON: `/encrypt`, `/decrypt`, `/sign`, `/verify`. Elixir with Plug and Bandit, no framework, no database, two runtime dependencies (Plug and Bandit), about 330 lines of lib code.

## Run it

With Elixir, or with Docker:

```sh
mix deps.get
SIGNING_SECRET=change-me mix run --no-halt
```
```sh
docker build -t riot-take-home .
docker run --rm -e SIGNING_SECRET=change-me -p 4000:4000 riot-take-home
```

The server refuses to start without `SIGNING_SECRET`. The port defaults to 4000 (`PORT` to override). The four calls below were run against the server as written; the outputs are pasted, not typed.

```sh
curl -X POST localhost:4000/encrypt -H "content-type: application/json" \
  -d '{"name":"John Doe","age":30,"contact":{"email":"john@example.com","phone":"123-456-7890"}}'
# {"age":"enc:b64:MzA","contact":"enc:b64:eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9","name":"enc:b64:IkpvaG4gRG9lIg"}

curl -X POST localhost:4000/decrypt -H "content-type: application/json" \
  -d '{"name":"enc:b64:IkpvaG4gRG9lIg","age":"enc:b64:MzA","birth_date":"1998-11-19"}'
# {"age":30,"birth_date":"1998-11-19","name":"John Doe"}
# age is the number 30 again; the plaintext birth_date passed through untouched.

curl -X POST localhost:4000/sign -H "content-type: application/json" \
  -d '{"message":"Hello World","timestamp":1616161616}'
# {"signature":"Wn2CIuB4zTZELZHOMIL7wyXa0L2LrQDCGRy7loWdGhU"}
# The same payload with the keys reversed returns the same signature.

curl -i -X POST localhost:4000/verify -H "content-type: application/json" \
  -d '{"signature":"Wn2CIuB4zTZELZHOMIL7wyXa0L2LrQDCGRy7loWdGhU","data":{"timestamp":1616161616,"message":"Hello World"}}'
# HTTP/1.1 204 No Content   (permuted keys in data; tamper with data and you get 400)
```

## Endpoint contract

| Endpoint | Body | Success |
|---|---|---|
| `POST /encrypt` | a JSON object | 200, every depth-1 value encrypted and wrapped in a marker (a nested object becomes one string) |
| `POST /decrypt` | a JSON object | 200, exact inverse at depth 1; values that are not markers come back unchanged, with their original type |
| `POST /sign` | a JSON object | 200, exactly `{"signature": "<sig>"}`; HMAC-SHA256 over the canonical form, url-safe base64, no padding |
| `POST /verify` | `{"signature": <string>, "data": <object>}` | 204 empty body if valid, 400 otherwise |

**Marker:** `enc:<alg_id>:<data>`, e.g. `enc:b64:MzA`. The algorithm id travels with the value, so two ids (`b64`, `aesgcm`) coexist in one body with no migration.

**Status codes:** 200 / 204 as above; 400 on malformed JSON, empty body, non-object root, or a bad `/verify` shape; 413 over 1 MiB; 415 on a non-JSON content-type; 404 on an unknown route or wrong method. Errors are `{"error": "<message>"}`. No 500 is reachable from any input, including a marker naming a cipher the server cannot key: decryption of untrusted data never raises, it reports failure and the value passes through. Parser errors are caught without a request body ever reaching the logs.

## Design decisions

The design is layered so the core stands alone: the four endpoints over a single base64 cipher and one HMAC signer are the whole of the assignment, and the marker, the exact number handling, the second cipher and the second signer sit on top of that core, each defended below. Every claim here maps to a named test.

**Marker prefix, not a decode heuristic.** The obvious `/decrypt` rule, "if it decodes as base64 it was encrypted", is not usable: `"Riot"` decodes to valid UTF-8, `"MzA="` decodes to `"30"` which is valid JSON, a real GitHub node id decodes cleanly. The assignment's own plaintext examples, `"John Doe"` and `"1998-11-19"`, are invalid base64 only by a space and a hyphen, so a heuristic tuned to the example passes the example and corrupts real data. Every ciphertext therefore carries `enc:<alg_id>:`, and detection is an exact check. The cost, assumed: `/decrypt` only reverses what this service produced, so a hand-made bare-base64 string is left unchanged rather than guessed at.

**Encrypt the JSON encoding of the value, not its string form.** `/encrypt` encrypts `JSON.encode!(value)`, so `30` encrypts as `30` and `"30"` as `"30"`; decrypt decodes then JSON-parses, and types return by construction while `"30"` stays distinct from `30`. Coercing to strings would lose types and break the round trip.

**Numbers are preserved exactly, never normalised.** Normalising through a float collides: `12345678901234567890` and `…891` map to the same IEEE-754 double and would sign identically, which is a forgery primitive. Elixir integers are arbitrary-precision, so they are emitted exactly and the collision cannot happen (tested with that pair). The cost: `1` and `1.0` sign differently, which rubs against a strict reading of "value, not representation". A representation collision is an interoperability constraint; a value collision is a security defect. We keep the lesser one.

**Explicit recursive key sort, and a deliberate deviation from RFC 8785.** The canonical form is close to JCS (RFC 8785) for structure, but deviates on numbers on purpose: JCS mandates ECMAScript double-based number formatting, which collapses integers beyond 2^53, the exact collision the previous decision avoids. The sort is also explicit rather than trusting Erlang map order, which above 32 keys derives from runtime hashing and is not stable across OTP versions.

**A JSON object is required.** `/encrypt` acts on "properties at depth 1" and `/sign` "adds a signature property", both of which presuppose an object. A top-level array, string or number gets a clean 400 rather than an invented behaviour.

**`/sign` returns the signature alone.** The assignment's example response has exactly one key. Echoing the payload with a signature added was considered and rejected: the example is literal and the caller already holds the payload. `/verify` stays symmetric, accepting as `data` anything `/sign` accepts.

**Depth 1 on both sides.** A nested object becomes one string on encrypt, so `/decrypt` inspects depth 1 only and is the exact inverse: a marker-shaped string sitting deeper is user data and stays untouched. Recursive decryption was rejected because `/encrypt` can never produce a nested marker, so it could only corrupt plaintext.

**Plug, not Phoenix.** A minimal Phoenix API project pulls 16 packages against 13 here, and adds a supervision tree with PubSub and DNSCluster plus a nine-plug endpoint (Static, Session, MethodOverride) that four stateless endpoints never touch. It also routes JSON back through Jason, where this uses the standard-library `JSON`. In exchange, body parsing and error handling are written by hand in `router.ex`, visible and covered by the router tests. Note that in an existing Phoenix codebase these four routes would be a scoped pipeline in the current router rather than a new app, so the scaffold skipped here is scaffold that would not have been written there either. Plug is the layer Phoenix itself is built on.

**Two ciphers and two signers, not one of each.** The assignment asks for both algorithms to be swappable without touching the rest of the code, and a declared behaviour proves nothing where a second implementation proves it. `RiotTakeHome.Cipher` has base64 and AES-256-GCM; `RiotTakeHome.Signer` has HMAC-SHA256 and HMAC-SHA512. Each swap is one line of config and nothing else moves (tested). Base64 is the active default so every example here is reproducible byte for byte; AES-256-GCM takes a dedicated `ENCRYPTION_KEY`, kept separate from the signing secret because a value used to encrypt must not be the value used to sign, and derives its key with PBKDF2 (RFC 8018) via the OTP-native `:crypto.pbkdf2_hmac` rather than a bare hash.

## Tests

```sh
mix test
```

49 tests, 4 of them properties. Expected values (markers, signatures, canonical strings) were computed outside the code under test, so a test cannot inherit a bug from it.

| File | What it proves |
|---|---|
| `payload_test.exs` | The example produces the documented markers; round trip restores types; `"30"` stays distinct from `30`; a table of 8 false-positive strings passes through `/decrypt` untouched; nested and malformed markers are left alone; base64 and AES-GCM coexist; AES-GCM is non-deterministic and rejects tampering. |
| `canonical_test.exs` | Key permutations at every depth share one form; array order is preserved; a 40-key case shows the explicit sort does real work above 32 keys; large integers are exact. |
| `signature_test.exs` | Key order does not change the signature (anchored to an independent HMAC); the two integers one apart sign differently; `1` vs `1.0` differ, as a documented trade-off; verify rejects altered, wrong-size, non-string and nil signatures without crashing; the second signer works through the same behaviour and each rejects the other's signature on length. |
| `router_test.exs` | The HTTP contract: exact `/sign` shape, 204 with zero bytes, permuted `data`, every 400 / 413 / 415 / 404 case, the 1 MiB limit, and a root with a literal `"_json"` key. |
| `property_test.exs` | Over generated JSON (integers beyond 2^53, arbitrary UTF-8): encrypt-then-decrypt is the identity, the canonical form is construction-order independent and valid JSON, and sign-then-verify always passes. |

CI runs `mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix credo --strict` and `mix test`, pinned to the versions in `.tool-versions`.

## Out of scope

| Left out | Why |
|---|---|
| Key rotation, KMS, multiple active secrets | Real webhook signing needs it; two environment variables are the honest scope here. |
| Authentication, rate limiting | The assignment defines an anonymous API. |
| GenServer, supervision beyond the HTTP server | The service holds no state. |
| Telemetry, healthcheck, API versioning | Nothing here would consume them; the marker already carries the only thing that evolves. |
| Database, docker-compose | Nothing is stored; one container is the whole system. |
