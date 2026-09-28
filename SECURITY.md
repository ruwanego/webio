# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") on this repository. Include a minimal reproduction (the raw HTTP request is ideal) and the affected version or commit.

You should receive an acknowledgement within 7 days.

## Deployment model

WebIO speaks plain HTTP/1.1 and does not implement TLS. In production, run it behind a reverse proxy or load balancer (nginx, Caddy, HAProxy, a cloud load balancer) that terminates TLS.

Built-in limits, all configurable on `WebIo`:

| Limit | Default | Response when exceeded |
| --- | --- | --- |
| Request head (request line + headers) | 16 KiB, 100 fields | `431` |
| Request body (`set_max_body_size`) | 10 MiB | `413` |
| Time to receive one request (`set_timeouts`) | 30 s | `408` |
| Per-write timeout while replying (`set_timeouts`) | 30 s | connection closed |
| Concurrent connections (`set_max_connections`) | 2000 | `503` |
| WebSocket frame payload (`WS_MAX_FRAME_SIZE`) | 16 MiB | `InvalidData` error |

Each connection uses one OS thread and handles one request (`Connection: close`). Size `set_max_connections` to what the host's thread and memory limits allow.

Not supported: `Transfer-Encoding` request bodies (`501`), keep-alive, HTTP/2, TLS.
