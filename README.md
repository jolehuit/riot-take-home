# Riot Take Home

[![CI](https://img.shields.io/github/actions/workflow/status/jolehuit/riot-take-home/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/jolehuit/riot-take-home/actions)
![Elixir](https://img.shields.io/badge/Elixir-1.19.5-4B275F?style=flat-square&logo=elixir&logoColor=white)
![OTP](https://img.shields.io/badge/OTP-28-A2003B?style=flat-square)
![Server](https://img.shields.io/badge/server-Bandit-0B7261?style=flat-square)
![Tests](https://img.shields.io/badge/tests-61%20passing-3FB950?style=flat-square)

A small HTTP API with four POST endpoints over JSON: `/encrypt`, `/decrypt`, `/sign`, `/verify`. Elixir with Plug and Bandit, no framework, no database, two runtime dependencies, 490 lines in `lib/`, 363 of them code.

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

**Marker:** `enc:<alg_id>:<data>`, e.g. `enc:b64:MzA`. What follows the second colon is the base64 the assignment names; the prefix is metadata around it, not a different algorithm. Carrying the id with the value is what makes `/decrypt` detection an exact check rather than a guess at the bytes, and what lets two ids (`b64`, `aesgcm`) coexist in one body with no migration. Both are argued under Design decisions.

**Status codes:** 200 / 204 as above; 400 on malformed JSON, an empty body, a non-object root, an integer past 1000 digits, or a bad `/verify` shape; 413 over 1 MiB; 415 on a non-JSON content-type; 405 with an `Allow` header on a known route with another method; 404 on an unknown route. Errors are `{"error": "<message>"}`. No 500 is reachable from any input, including a marker naming a cipher the server cannot key: decryption of untrusted data never raises, it reports failure and the value passes through. Parser errors are caught without a request body ever reaching the logs.

## Design decisions

The four endpoints over one base64 cipher and one HMAC signer are the whole of the assignment. Everything past that core is defended here with the cost it carries; the derivations live in the tests named alongside.

### `/encrypt` and `/decrypt`

**Ciphertext carries a marker.** `/decrypt` is asked to detect encrypted strings and to leave unencrypted values unchanged, and base64 has no mark of its own, so no rule reading the bytes can do both: `"MzA="` decodes to `"30"`, which is valid JSON, and a decode-then-parse rule turns that plaintext into the number 30. Every value this service encrypts therefore carries `enc:<alg_id>:`, detection is an exact check, and no plaintext can be mistaken for it. The cost, assumed: a bare base64 string built elsewhere is left unchanged rather than guessed at. `payload_test.exs` holds the table of strings a heuristic corrupts.

**The value is JSON-encoded before it is encrypted.** `/encrypt` encrypts `JSON.encode!(value)`, so `30` and `"30"` produce different markers and each returns with its original type. Coercing to strings would break the round trip.

**Depth 1 on both sides.** A nested object becomes one string on encrypt, so `/decrypt` inspects depth 1 only and is the exact inverse: a marker-shaped string sitting deeper is user data and stays untouched. Recursive decryption could only corrupt plaintext, since `/encrypt` never produces a nested marker.

### `/sign` and `/verify`

**Integers keep their exact value.** Normalising through a float maps `12345678901234567890` and `…891` onto the same double, so the two would share a signature, which is a forgery primitive. Elixir integers are arbitrary-precision and are emitted as they arrived, tested with that pair in `signature_test.exs`. Against that, `1` and `1.0` sign differently. A representation collision is an interoperability constraint; a value collision is a security defect.

Exactness needs a bound, and the body limit is not one: converting a bignum back to decimal is quadratic, so a single 1 MB integer literal cost 24 s of CPU where 1 MB of text costs 1 ms. Integers past 1000 digits are rejected, which caps a full-size body under 50 ms measured and leaves every realistic value exact (`router_test.exs`).

**Explicit recursive key sort, deviating from RFC 8785 on numbers.** JCS mandates ECMAScript double formatting, which collapses integers beyond 2^53, the collision above. The sort is explicit rather than trusting Erlang map order, which above 32 keys derives from runtime hashing and is not stable across OTP versions (`canonical_test.exs`). Duplicate keys resolve first-wins, which is what the decoder hands over: the signature covers the decoded document, not the bytes that carried it, so a peer whose parser keeps the last value would canonicalise the same body differently.

**`/sign` returns the signature alone,** as the assignment's example response shows. `/verify` accepts as `data` anything `/sign` accepts.

### Swapping the algorithm

**Each behaviour has two implementations,** because a declared behaviour proves nothing where a second one proves it. `Cipher` has base64 and AES-256-GCM, `Signer` has HMAC-SHA256 and HMAC-SHA512. Each swap is one config line and nothing else moves, tested by flipping the config and driving the endpoints (`configuration_test.exs`). Base64 is the default, so every example above reproduces byte for byte.

**Why the AES key is derived.** AES-256-GCM takes exactly 32 bytes of key; an environment variable is a string of arbitrary length and unknown quality, so deriving is required here rather than optional. The derivation is PBKDF2 (RFC 8018) through `:crypto.pbkdf2_hmac`: the iteration count buys nothing against 32 random bytes, but it is the whole difference against a passphrase, and the service cannot tell which the operator supplied. HMAC carries no such constraint and gets no stretching: `/sign` passes `SIGNING_SECRET` straight to `:crypto.mac/4`. `ENCRYPTION_KEY` is kept separate from the signing secret (`aes_gcm_vector_test.exs`).

**The derivation runs once, at first use.** PBKDF2 at the OWASP floor costs about 70 ms, and the key is a pure function of the secret and a constant salt. Deriving it per value charged that cost per property: 200 marked values took 14.5 s, and since `/decrypt` accepts markers from anyone, that is CPU amplification on untrusted input. The key is held in `:persistent_term`, keyed on a fingerprint of the secret so a rotation re-derives. The same request now takes 0.09 s, and a test fails if the memo is removed.

### Framework and request shape

**No framework.** A minimal Phoenix API pulls 16 packages against 13 here, plus PubSub, DNSCluster and a nine-plug endpoint that four stateless routes never touch. In exchange, body parsing and error handling are written by hand in `router.ex`, covered by the router tests.

**A JSON object is required.** `/encrypt` acts on properties at depth 1 and `/sign` adds a signature property; both presuppose an object, so a top-level array, string or number gets a clean 400.

## Tests

```sh
mix test
```

61 tests, 4 of them properties: over generated JSON, encrypt-then-decrypt is the identity and sign-then-verify always passes (`property_test.exs`). Every expected value (markers, signatures, canonical forms, one AES-GCM ciphertext) was computed outside the code under test, so a test cannot inherit a bug from it. Two are worth naming: a 40-key case, because Erlang sorts smaller maps for free and would otherwise make the explicit sort look correct by accident; and an AES-GCM vector generated under node, which pins the salt, the iteration count, the nonce size and the variable the key is read from, all at once.

CI runs `mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix credo --strict` and `mix test`, pinned to the versions in `.tool-versions`.

## Out of scope

| Left out | Why |
|---|---|
| KMS, and overlapping secrets during a rotation | Changing a secret re-derives correctly, but accepting the old and the new at once is what real webhook signing needs; two environment variables are the honest scope here. |
| Authentication, rate limiting | The assignment defines an anonymous API. |
| GenServer, supervision beyond the HTTP server | The service holds no state. |
| Telemetry, healthcheck, API versioning | Nothing here would consume them; the marker already carries the only thing that evolves. |
| Database, docker-compose | Nothing is stored; one container is the whole system. |
