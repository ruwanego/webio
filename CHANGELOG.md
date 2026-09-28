# Changelog

## Unreleased — production hardening

### Security
- **Static files: path traversal fixed.** `GET /../../etc/passwd` previously read any file the process could access. Paths containing `..` (plain or percent-encoded) are now rejected with `400`; files are served only if they resolve, after following symlinks, to a location inside the static root. Hidden entries (`.env`, `.git/…`) are never served, except `.well-known`.
- **Middleware no longer silently replaced.** `use_mw` kept only the last registered middleware, so registering an auth check followed by a logger removed the auth check. All middleware now runs in registration order.
- **Middleware sees a normalized path.** Repeated slashes are collapsed (`//admin` → `/admin`), so path-prefix checks cannot be bypassed with extra slashes.
- **WebSocket frames are size-bounded.** `WSFrame::read` allocated whatever 64-bit length a client declared (remote out-of-memory). Frames over `WS_MAX_FRAME_SIZE` (16 MiB) and unmasked client frames are now rejected with `InvalidData`. Use `WSFrame::read_with_limit` for a different bound.
- **Response splitting prevented.** Header names/values containing CR, LF or NUL are dropped when a reply is written.
- **Framing headers are engine-owned.** `Content-Length`, `Transfer-Encoding` and `Connection` set by handlers are ignored, so they cannot conflict with the chunked body.
- **Request smuggling surface removed.** Requests with `Transfer-Encoding` get `501`; conflicting or malformed `Content-Length` gets `400`; obsolete header folding gets `400`.

### Fixed
- Request heads larger than one 4 KB read, or split across TCP packets, were misparsed. The head is now read until `\r\n\r\n` (max 16 KiB / 100 headers, else `431`).
- Bodies from clients slower than 150 ms were silently truncated. Each request now has a total read deadline (default 30 s, `408` when exceeded).
- Binary bodies were corrupted by lossy UTF-8 conversion, and a `Content-Length` landing inside a multi-byte character could panic. The exact bytes are in the new `Req::body_bytes` field.
- Headers written without a space after the colon (`Content-Length:5`) were ignored.
- A handler panic leaked a connection slot forever and sent nothing. It now returns `500` and always releases the slot.
- Oversized bodies returned `403 Forbidden`; they now return `413 Content Too Large`.
- Every status line said `OK` (`HTTP/1.1 404 OK`). Correct reason phrases are now sent.
- `HEAD`, `204`, `304` and 1xx replies carried a body. They no longer do. `HEAD` falls back to the matching `GET` route.
- Static files of 500 KB or more were read fully into RAM. They are now streamed from disk in 64 KiB chunks. The static RAM cache is capped at 64 MiB in total.
- `favicon.ico` discovery no longer follows directory symlinks and stops at depth 8.
- `Req::save_to_file` dropped the part of the body already read by the engine and hid I/O errors. It now writes `body_bytes` and returns errors.
- `Req::form` did not percent-decode. Keys and values are now decoded.
- `Expect: 100-continue` is honoured, removing a ~1 s client-side stall on uploads (e.g. curl).
- Accept errors such as `EMFILE` no longer cause a busy loop.
- Connections beyond the limit now receive `503` with `Retry-After` instead of being dropped.
- `on_404` no longer panics if a loopback socket cannot be opened.
- A reply with status `101 Switching Protocols` now writes nothing and leaves the socket open for the WebSocket handler.

### Added
- `WebIo::try_run(host, port) -> io::Result<()>` — like `run`, returns bind errors instead of panicking. Supports IPv6 hosts.
- `WebIo::serve(listener)` — serve on an existing `TcpListener` (tests, socket activation).
- `WebIo::set_max_body_size`, `set_max_connections`, `set_timeouts`.
- `Req::body_bytes`, `Req::query()`, `utils::percent_decode`, `Method::as_str`.
- `WSFrame::fin`, `WSFrame::opcode`, `WSFrame::read_with_limit`, `WS_MAX_FRAME_SIZE`.
- `Date` header on every response.
- `impl Default for WebIo` and `Sha1`.
- Wire-level integration tests (`tests/http_behavior.rs`), unit tests for parsing, dates, SHA-1/Base64 and the RFC 6455 accept key; CI on Linux, macOS and Windows plus an MSRV (1.85) build.

### Compatibility notes
- `Req` gained a public field (`body_bytes`). Code that builds `Req` with a struct literal must add it; code that only receives `Req` is unaffected.
- `WSFrame` gained public fields (`fin`, `opcode`); same note.
- Unmasked client WebSocket frames are now an error (RFC 6455 §5.1 requires servers to reject them).
- Middleware now receives the normalized path instead of the raw request target.
