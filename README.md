# Riot Take Home

[![CI](https://github.com/jolehuit/riot-take-home/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jolehuit/riot-take-home/actions/workflows/ci.yml)
![Elixir](https://img.shields.io/badge/Elixir-1.19.5-4B275F?style=flat-square&logo=elixir&logoColor=white)
![OTP](https://img.shields.io/badge/OTP-28-A2003B?style=flat-square)
![Server](https://img.shields.io/badge/server-Bandit-0B7261?style=flat-square)
![Tests](https://img.shields.io/badge/tests-60%20passing-3FB950?style=flat-square)

A small HTTP API with four POST endpoints over JSON: `/encrypt`, `/decrypt`, `/sign`, `/verify`. Elixir with Plug and Bandit, no framework, no database, two runtime dependencies, 455 lines in `lib/`, 356 of them code.

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
# {"age":"MzA=","contact":"eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9","name":"IkpvaG4gRG9lIg=="}

curl -X POST localhost:4000/decrypt -H "content-type: application/json" \
  -d '{"name":"IkpvaG4gRG9lIg==","age":"MzA=","birth_date":"1998-11-19"}'
# {"age":30,"birth_date":"1998-11-19","name":"John Doe"}
# age is the number 30 again; the plaintext birth_date passed through untouched.

curl -X POST localhost:4000/sign -H "content-type: application/json" \
  -d '{"message":"Hello World","timestamp":1616161616}'
# {"signature":"5a7d8222e078cd36442d91ce3082fbc325dad0bd8bad00c2191cbb96859d1a15"}
# The same payload with the keys reversed returns the same signature.

curl -i -X POST localhost:4000/verify -H "content-type: application/json" \
  -d '{"signature":"5a7d8222e078cd36442d91ce3082fbc325dad0bd8bad00c2191cbb96859d1a15","data":{"timestamp":1616161616,"message":"Hello World"}}'
# HTTP/1.1 204 No Content   (permuted keys in data; tamper with data and you get 400)
```

## Endpoint contract

| Endpoint | Body | Success |
|---|---|---|
| `POST /encrypt` | a JSON object | 200, every depth-1 value JSON-encoded then base64-encoded (a nested object becomes one string) |
| `POST /decrypt` | a JSON object | 200, exact inverse at depth 1; values not detected as ciphertext come back byte for byte unchanged |
| `POST /sign` | a JSON object | 200, exactly `{"signature": "<sig>"}`; HMAC-SHA256 over the canonical form, lowercase hex |
| `POST /verify` | `{"signature": <string>, "data": <object>}` | 204 empty body if valid, 400 otherwise; extra top-level fields are ignored, verification covers `data` only |

**Detection:** a depth-1 string is replaced by its decoded value exactly when two conditions hold: it is valid standard base64 (strict alphabet and padding), and the decoded bytes are valid UTF-8 that parses as JSON within the integer bound. Any condition failing returns the value unchanged. The false positives this rule admits, and their cost, are argued under Design decisions.

**Status codes:** 200 / 204 as above; 400 on malformed JSON, an empty body, a non-object root, an integer past 1000 digits, or a bad `/verify` shape; 413 over 1 MiB; 415 on a non-JSON content-type; 405 with an `Allow` header on a known route with another method; 404 on an unknown route. Errors are `{"error": "<message>"}`. No 500 is reachable from any input: decryption of untrusted data never raises, it reports failure and the value passes through, including when the active cipher has no key to try. Parser errors are caught without a request body ever reaching the logs.

## Design decisions

The four endpoints over one base64 cipher and one HMAC signer are the whole of the assignment. Everything past that core is defended here with the cost it carries; the derivations live in the tests named alongside.

### `/encrypt` and `/decrypt`

**Detection reads the bytes, and its false positives are named.** The assignment names base64 as the algorithm and asks `/decrypt` to detect encrypted strings; base64 has no mark of its own, so detection is the two-condition rule above, and it cannot be exact. A value is returned unchanged unless it is valid standard base64 of valid JSON, which sorts every string into one of two classes. Most plaintext fails a condition and passes through: `"Riot"` and `"Sm9obiBEb2U="` decode but not to JSON, `"test"` decodes to invalid UTF-8, `"1998-11-19"` and `"John Doe"` are not base64 at all. But a plaintext that satisfies both conditions is indistinguishable from a ciphertext and is transformed: `"MzA="` becomes the number `30`, `"e30="` becomes `{}`, `"dHJ1ZQ=="` becomes `true`. That is the accepted cost of detecting bare base64, and it is pinned by tests rather than left implicit: `payload_test.exs` holds both halves of the table, the strings that must survive and the strings the rule claims.

**The value is JSON-encoded before it is encrypted.** `/encrypt` encrypts `JSON.encode!(value)`, so `30` and `"30"` produce different ciphertexts and each returns with its original type. Coercing to strings would break the round trip, and requiring valid JSON inside the base64 is also what keeps the detection's false-positive class as small as it is.

**Depth 1 on both sides.** A nested object becomes one string on encrypt, so `/decrypt` inspects depth 1 only and is the exact inverse: a base64-shaped string sitting deeper is user data and stays untouched. Recursive decryption could only corrupt plaintext, since `/encrypt` never produces a nested ciphertext.

### `/sign` and `/verify`

**Integers keep their exact value.** Normalising through a float maps `12345678901234567890` and `…891` onto the same double, so the two would share a signature, which is a forgery primitive. Elixir integers are arbitrary-precision and are emitted as they arrived, tested with that pair in `signature_test.exs`. Against that, `1` and `1.0` sign differently. A representation collision is an interoperability constraint; a value collision is a security defect.

Exactness needs a bound, and the body limit is not one: converting a bignum back to decimal is quadratic, so one 1 MB integer literal cost 24 s of CPU where 1 MB of text costs 1 ms. Integers past 1000 digits are rejected, which caps a full-size body under 50 ms measured. The bound covers what `/decrypt` emits as well as what the service accepts, since a ciphertext arrives as a string and its plaintext is only seen after decoding (`router_test.exs`).

**Explicit recursive key sort, deviating from RFC 8785 on numbers.** JCS mandates ECMAScript double formatting, which collapses integers beyond 2^53, the collision above. The sort is explicit rather than trusting Erlang map order, which above 32 keys derives from runtime hashing and is not stable across OTP versions (`canonical_test.exs`). Duplicate keys resolve first-wins, as the decoder hands them over: the signature covers the decoded document, not the bytes that carried it.

**`/sign` returns the signature alone,** as the assignment's example response shows. `/verify` accepts as `data` anything `/sign` accepts.

### Swapping the algorithm

**Each behaviour has two implementations,** because a declared behaviour proves nothing where a second one proves it. `Cipher` has base64 and AES-256-GCM, `Signer` has HMAC-SHA256 and HMAC-SHA512. Each swap is one config line and nothing else moves, tested by flipping the config and driving the endpoints (`configuration_test.exs`). Detection travels with the cipher behind the same callback: base64 lets the strict decode decide, AES-GCM lets the authentication tag decide. Since no algorithm id travels with a value, a swap is a clean cut, and values written by the previous cipher pass through unchanged instead of decrypting.

**The AES key is 32 raw bytes, checked at boot.** `ENCRYPTION_KEY` must be exactly 32 bytes, base64-encoded (`openssl rand -base64 32`). A malformed value refuses the boot, and so does an absent one when AES is the active cipher, so a swap cannot leave the service running without the key it needs. The cipher is deliberately minimal: keyed, non-deterministic and authenticated. Real key management, derivation and rotation included, is out of scope, and the key stays separate from `SIGNING_SECRET` (`aes_gcm_vector_test.exs`).

### Framework and request shape

**No framework.** A minimal Phoenix API pulls 16 packages against 13 here, plus PubSub, DNSCluster and a nine-plug endpoint that four stateless routes never touch. In exchange, body parsing and error handling are written by hand in `router.ex`, covered by the router tests.

**A JSON object is required.** `/encrypt` acts on properties at depth 1 and `/sign` adds a signature property; both presuppose an object, so a top-level array, string or number gets a clean 400.

## Tests

```sh
mix test
```

60 tests, 4 of them properties: over generated JSON, encrypt-then-decrypt is the identity and sign-then-verify always passes (`property_test.exs`). Every expected value (ciphertexts, signatures, canonical forms, one AES-GCM vector) was computed outside the code under test, with python or node, so a test cannot inherit a bug from it. Two are worth naming: a 40-key case, because Erlang sorts smaller maps for free and would otherwise make the explicit sort look correct by accident; and an AES-GCM vector generated under node, which pins the nonce size, the wire layout and the variable the key is read from, all at once.

CI runs `mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix credo --strict` and `mix test`, pinned to the versions in `.tool-versions`.

## Out of scope

| Left out | Why |
|---|---|
| Versioned ciphertext envelope | Production systems prefix ciphertexts with a version or algorithm id, which makes detection exact instead of heuristic and lets two algorithms coexist during a migration; recommended for anything past this assignment, which names bare base64. |
| KMS, key derivation, rotation | The operator supplies 32 raw bytes and changing them is a restart; deriving keys from passphrases and accepting the old and the new at once belong to real deployment key management, and two environment variables are the honest scope here. |
| Authentication, rate limiting | The assignment defines an anonymous API. |
| GenServer, supervision beyond the HTTP server | The service holds no state. |
| Telemetry, healthcheck, API versioning | Nothing here would consume them; four stateless routes have nothing to version. |
| Database, docker-compose | Nothing is stored; one container is the whole system. |
