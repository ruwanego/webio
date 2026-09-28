//! Wire-level behaviour tests. Each test starts its own server on an
//! ephemeral port (`WebIo::serve`) and talks raw HTTP/1.1 over TCP, so the
//! exact bytes on the wire are checked.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use webio::*;

// --- helpers -------------------------------------------------------------

fn spawn(app: WebIo) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || app.serve(listener));
    addr
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn read_all(mut s: TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

/// Sends `raw` and returns the full response bytes (server closes after one reply).
fn roundtrip(addr: SocketAddr, raw: &[u8]) -> Vec<u8> {
    let mut s = connect(addr);
    s.write_all(raw).unwrap();
    read_all(s)
}

struct Resp {
    status: u16,
    head: String,
    body: Vec<u8>,
}

fn parse(raw: &[u8]) -> Resp {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("no header terminator");
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
    let rest = &raw[split + 4..];
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    Resp { status, head, body }
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n").expect("bad chunk");
        let size = usize::from_str_radix(std::str::from_utf8(&data[..line_end]).unwrap(), 16).unwrap();
        data = &data[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&data[..size]);
        assert_eq!(&data[size..size + 2], b"\r\n");
        data = &data[size + 2..];
    }
}

fn get(addr: SocketAddr, path: &str) -> Resp {
    parse(&roundtrip(addr, format!("GET {} HTTP/1.1\r\nHost: t\r\n\r\n", path).as_bytes()))
}

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "webio-test-{}-{}-{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn echo_app() -> WebIo {
    let mut app = WebIo::new();
    app.route(POST, "/echo", |req, _| async move {
        Reply::new(StatusCode::Ok).body(req.body_bytes)
    });
    app.route(GET, "/hello", |_, _| async {
        Reply::new(StatusCode::Ok).header("Content-Type", "text/plain").body("hello")
    });
    app
}

// --- static files --------------------------------------------------------

#[test]
fn static_files_are_confined_to_root() {
    let base = temp_dir("static");
    let assets = base.join("assets");
    std::fs::create_dir_all(assets.join("css")).unwrap();
    std::fs::write(assets.join("css/site.css"), "body{}").unwrap();
    std::fs::write(assets.join("my file.txt"), "spaced").unwrap();
    std::fs::write(assets.join(".env"), "SECRET=1").unwrap();
    std::fs::write(base.join("secret.txt"), "TOP SECRET").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(base.join("secret.txt"), assets.join("link.txt")).unwrap();

    let mut app = WebIo::new();
    app.use_static(assets.to_str().unwrap());
    let addr = spawn(app);

    let ok = get(addr, "/css/site.css");
    assert_eq!(ok.status, 200);
    assert_eq!(ok.body, b"body{}");
    assert!(ok.head.contains("Content-Type: text/css"));

    assert_eq!(get(addr, "/my%20file.txt").body, b"spaced");

    for attack in ["/../secret.txt", "/css/../../secret.txt", "/%2e%2e/secret.txt", "/css/%2E%2E/%2e%2e/secret.txt"] {
        let r = get(addr, attack);
        assert_eq!(r.status, 400, "{attack}");
        assert!(!String::from_utf8_lossy(&r.body).contains("TOP SECRET"), "{attack}");
    }
    assert_eq!(get(addr, "/..%2Fsecret.txt").status, 404);
    assert_eq!(get(addr, "/.env").status, 404);
    #[cfg(unix)]
    assert_eq!(get(addr, "/link.txt").status, 404, "symlink escaping the root must not be served");
}

#[test]
fn large_static_file_is_streamed_intact() {
    let dir = temp_dir("large");
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("big.bin"), &data).unwrap();
    let mut app = WebIo::new();
    app.use_static(dir.to_str().unwrap());
    let addr = spawn(app);
    let r = get(addr, "/big.bin");
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), data.len());
    assert!(r.body == data);
}

// --- middleware ----------------------------------------------------------

#[test]
fn all_middleware_runs_in_order_and_sees_normalized_path() {
    let seen = Arc::new(AtomicUsize::new(0));
    let mut app = WebIo::new();
    app.use_mw(|path| {
        if path.starts_with("/admin") {
            Some(Reply::new(StatusCode::Unauthorized).body("denied"))
        } else {
            None
        }
    });
    let s = Arc::clone(&seen);
    app.use_mw(move |_| {
        s.fetch_add(1, Ordering::SeqCst);
        None
    });
    app.route(GET, "/admin", |_, _| async { Reply::new(StatusCode::Ok).body("SECRET") });
    app.route(GET, "/open", |_, _| async { Reply::new(StatusCode::Ok).body("open") });
    let addr = spawn(app);

    for path in ["/admin", "//admin", "/admin?x=1", "///admin/"] {
        let r = get(addr, path);
        assert_eq!(r.status, 401, "{path}");
        assert_eq!(r.body, b"denied");
    }
    assert_eq!(seen.load(Ordering::SeqCst), 0, "later middleware must not run after an early reply");
    assert_eq!(get(addr, "/open").body, b"open");
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}

// --- robustness ----------------------------------------------------------

#[test]
fn handler_panic_returns_500_and_releases_slot() {
    let mut app = WebIo::new();
    app.route(GET, "/boom", |_, _| async { panic!("handler failure") });
    app.route(GET, "/ok", |_, _| async { Reply::new(StatusCode::Ok).body("ok") });
    let addr = spawn(app.set_max_connections(1));

    for _ in 0..3 {
        assert_eq!(get(addr, "/boom").status, 500);
    }
    thread::sleep(Duration::from_millis(100));
    let r = get(addr, "/ok");
    assert_eq!(r.status, 200, "slot must be released after panics");
}

#[test]
fn over_capacity_gets_503() {
    let app = echo_app()
        .set_max_connections(1)
        .set_timeouts(Duration::from_secs(3), Duration::from_secs(3));
    let addr = spawn(app);
    let holder = connect(addr); // occupies the only slot, sends nothing
    thread::sleep(Duration::from_millis(200));
    let r = get(addr, "/hello");
    assert_eq!(r.status, 503);
    assert!(r.head.contains("Retry-After: 1"));
    drop(holder);
}

#[test]
fn slow_request_times_out_with_408() {
    let app = echo_app().set_timeouts(Duration::from_millis(300), Duration::from_secs(3));
    let addr = spawn(app);
    let mut s = connect(addr);
    s.write_all(b"GET /hello HTTP/1.1\r\nHost: t\r\n").unwrap(); // never finishes the head
    let r = parse(&read_all(s));
    assert_eq!(r.status, 408);
}

// --- request parsing -----------------------------------------------------

#[test]
fn body_split_across_slow_writes_is_intact_and_binary_safe() {
    let addr = spawn(echo_app());
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 256) as u8).collect(); // not UTF-8
    let mut s = connect(addr);
    s.write_all(format!("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n", payload.len()).as_bytes()).unwrap();
    s.write_all(&payload[..10]).unwrap();
    thread::sleep(Duration::from_millis(400)); // longer than the old 150ms read timeout
    s.write_all(&payload[10..]).unwrap();
    let r = parse(&read_all(s));
    assert_eq!(r.status, 200);
    assert!(r.body == payload);
}

#[test]
fn header_without_space_after_colon_is_accepted() {
    let addr = spawn(echo_app());
    let r = parse(&roundtrip(addr, b"POST /echo HTTP/1.1\r\nHost:t\r\nContent-Length:5\r\n\r\nhello"));
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"hello");
}

#[test]
fn expect_100_continue_is_honoured() {
    let addr = spawn(echo_app());
    let mut s = connect(addr);
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n").unwrap();
    let mut first = [0u8; 25];
    s.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"HTTP/1.1 100 Continue\r\n\r\n");
    s.write_all(b"data").unwrap();
    let r = parse(&read_all(s));
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"data");
}

#[test]
fn malformed_requests_are_rejected_with_correct_status() {
    let app = echo_app().set_max_body_size(1024);
    let addr = spawn(app);
    let cases: &[(&[u8], u16)] = &[
        (b"POST /echo HTTP/1.1\r\nContent-Length: 999999\r\n\r\n", 413),
        (b"POST /echo HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400),
        (b"POST /echo HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", 400),
        (b"POST /echo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501),
        (b"GET /hello HTTP/2.0\r\n\r\n", 505),
        (b"GET /hello\r\n\r\n", 400),
        (b"GET hello HTTP/1.1\r\n\r\n", 400),
        (b"GET /hello HTTP/1.1\r\nBad Header: x\r\n\r\n", 400),
        (b"GET /hello HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", 400),
        (b"POST /echo HTTP/1.1\r\nContent-Length: 1\r\nExpect: something\r\n\r\n", 417),
    ];
    for (raw, want) in cases {
        let r = parse(&roundtrip(addr, raw));
        assert_eq!(r.status, *want, "request: {:?}", String::from_utf8_lossy(raw));
    }

    let mut huge = b"GET /hello HTTP/1.1\r\n".to_vec();
    huge.extend(std::iter::repeat_n(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n".as_slice(), 400).flatten());
    huge.extend_from_slice(b"\r\n");
    assert_eq!(parse(&roundtrip(addr, &huge)).status, 431);
}

#[test]
fn form_and_query_are_percent_decoded() {
    let mut app = WebIo::new();
    app.route(POST, "/form", |req, _| async move {
        let f = req.form();
        let q = req.query();
        Reply::new(StatusCode::Ok).body(format!(
            "{}|{}|{}",
            f.get("name").cloned().unwrap_or_default(),
            f.get("a&b").cloned().unwrap_or_default(),
            q.get("q").cloned().unwrap_or_default()
        ))
    });
    let addr = spawn(app);
    let body = "name=Jane+Doe%21&a%26b=x%3Dy";
    let raw = format!("POST /form?q=caf%C3%A9 HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let r = parse(&roundtrip(addr, raw.as_bytes()));
    assert_eq!(String::from_utf8(r.body).unwrap(), "Jane Doe!|x=y|café");
}

#[test]
fn save_to_file_keeps_every_byte() {
    let dir = temp_dir("upload");
    let target = dir.join("out.bin");
    let t = target.to_str().unwrap().to_string();
    let mut app = WebIo::new();
    app.route(POST, "/upload", move |mut req, _| {
        let t = t.clone();
        async move {
            let n = req.save_to_file(&t).unwrap();
            Reply::new(StatusCode::Ok).body(n.to_string())
        }
    });
    let addr = spawn(app);
    let payload: Vec<u8> = (0..100_000u32).map(|i| (i * 7 % 256) as u8).collect();
    let mut s = connect(addr);
    s.write_all(format!("POST /upload HTTP/1.1\r\nContent-Length: {}\r\n\r\n", payload.len()).as_bytes()).unwrap();
    s.write_all(&payload).unwrap();
    let r = parse(&read_all(s));
    assert_eq!(r.body, payload.len().to_string().as_bytes());
    assert!(std::fs::read(&target).unwrap() == payload);
}

// --- responses -----------------------------------------------------------

#[test]
fn head_falls_back_to_get_without_body() {
    let addr = spawn(echo_app());
    let raw = roundtrip(addr, b"HEAD /hello HTTP/1.1\r\nHost: t\r\n\r\n");
    let text = String::from_utf8(raw).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.ends_with("\r\n\r\n"));
    assert!(!text.contains("hello"));
    assert!(text.contains("Content-Type: text/plain"));
}

#[test]
fn status_line_reason_and_header_sanitizing() {
    let mut app = WebIo::new();
    app.route(GET, "/x", |_, _| async {
        Reply::new(StatusCode::Created)
            .header("X-Inject", "v\r\nSet-Cookie: stolen=1")
            .header("Transfer-Encoding", "identity")
            .body("made")
    });
    let addr = spawn(app);
    let r = get(addr, "/x");
    assert!(r.head.starts_with("HTTP/1.1 201 Created\r\n"));
    assert!(!r.head.contains("stolen"));
    assert!(!r.head.contains("identity"));
    assert!(r.head.contains("Date: "));
    assert_eq!(r.body, b"made");
}

#[test]
fn unknown_route_is_404() {
    let addr = spawn(echo_app());
    let r = get(addr, "/nope");
    assert_eq!(r.status, 404);
    assert!(r.head.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

// --- websocket -----------------------------------------------------------

#[test]
fn websocket_frame_size_is_bounded_before_allocation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let (mut server, _) = listener.accept().unwrap();

    // Masked binary frame declaring a 1 TiB payload.
    let mut frame = vec![0x82, 0x80 | 127];
    frame.extend_from_slice(&(1u64 << 40).to_be_bytes());
    client.write_all(&frame).unwrap();
    let err = WSFrame::read(&mut server).err().expect("must reject oversize frame");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    // A normal masked text frame still decodes.
    let mask = [9u8, 8, 7, 6];
    let mut ok = vec![0x81, 0x80 | 2, 9, 8, 7, 6];
    ok.extend(b"hi".iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    client.write_all(&ok).unwrap();
    let f = WSFrame::read(&mut server).unwrap();
    assert!(f.fin);
    assert_eq!(f.opcode, 1);
    assert_eq!(f.payload, b"hi");
}
