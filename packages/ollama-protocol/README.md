# @afuera/ollama-protocol

Wire-compatible TypeScript port of the tunnel protocol from the author's
`ollama-uplink` project (`packages/protocol`): frame codec, session crypto,
and the `TunnelSession` multiplexer. An **unmodified** existing ollama-uplink
sidecar can talk to afuera-gateway using this package.

- Session keys: `HKDF-SHA256(ikm = SHA-256(PSK), salt = nonce_s || nonce_r,
  info = "s2r" | "r2s")` (32 bytes each direction).
- Frames: XChaCha20-Poly1305, random 24-byte nonce prepended, AAD =
  `utf8("<sessionId>:<direction>:<seq>")`, per-direction sequence numbers.
- Messages: JSON/UTF-8 (`hello`, `hello_ack`, `request_open`,
  `response_head`, `response_chunk`, `response_end`, `cancel`, `error`,
  `model_update`, `ping`, `pong`); binary bodies/chunks are base64 strings.

The unit tests pin the exact HKDF outputs the original implementation derives
(wire-compatibility test vectors). Behavioural differences vs. the original:
none in this package — it is a line-by-line port with doc comments translated
to this repo's conventions. The relay-side connection handling in
`apps/server` adds one deliberate hardening over the original relay: a new
sidecar connection only replaces an established one after it has proven the
PSK (first successfully decrypted frame) — see `docs/specs/ollama-relay.md`.
