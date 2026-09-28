//! # WebIO Orchestration Engine
//! 
//! This module serves as the central controller for the WebIO framework. It 
//! manages the lifecycle of TCP connections, routing logic, and high-level 
//! features like **Smart Asset Caching** and **Global WebSocket Broadcasting**.
//! 
//! ### Key Orchestration Features:
//! * **Pre-emptive Multi-threading:** Spawns a dedicated OS thread per connection, 
//!   mimicking Go's concurrency model but with Rust's deterministic memory safety.
//! * **Smart RAM Cache:** Utilizes an `RwLock<HashMap>` to provide **~50µs** delivery 
//!   for "hot" assets (<500KB) while keeping large datasets on disk to prevent RAM exhaustion.
//! * **Global Client Registry:** Maintains a thread-safe `Arc<Mutex<Vec<TcpStream>>>` 
//!   allowing any thread to broadcast real-time data to all connected WebSocket clients.
//! * **Dynamic Nagle Control:** Allows developers to toggle `TCP_NODELAY` via `.set_nagle()`, 
//!   optimizing for either sub-millisecond API latency or high-throughput data syncs.


mod http;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::net::{TcpListener, TcpStream, Shutdown, ToSocketAddrs};
use std::io::{self, BufWriter};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::thread;
use std::path::{Path, PathBuf};
use std::panic::{self, AssertUnwindSafe};
use std::future::Future;

use crate::{core::*, mime};
use crate::utils::{find_file_recursive, encode_ws_frame};

use http::{ParseError, ReadLimits};

/// Default maximum request body size held in memory (10 MiB).
pub const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
/// Default maximum number of concurrently handled connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 2000;
/// Default time allowed to receive one full request (head + body).
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Default timeout for each socket write.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Files smaller than this are kept in the static-asset RAM cache.
pub const STATIC_CACHE_FILE_LIMIT: usize = 500 * 1024;
/// Upper bound on the total bytes held by the static-asset RAM cache.
pub const STATIC_CACHE_TOTAL_LIMIT: usize = 64 * 1024 * 1024;

/// Supported HTTP Methods.
pub enum Method {
    /// Requests a representation of the specified resource.
    /// 
    /// This is the most common method, used to **Retrieve Data** (like HTML, 
    /// images, or JSON) from the server without modifying any state.
    GET,
    /// Submits an entity to the specified resource.
    /// 
    /// Primarily used for **Form Submissions** or **Data Uploads**, 
    /// often resulting in a change in state or side effects on the server.
    POST,
    /// Replaces all current representations of the target resource.
    /// 
    /// Used for **Full Updates**, where the client sends a complete 
    /// version of the resource to overwrite the existing one.
    PUT,
    /// Applies partial modifications to a resource.
    /// 
    /// Ideal for **Incremental Updates**, allowing the client to 
    /// modify only specific fields instead of replacing the entire object.
    PATCH,
    /// Deletes the specified resource.
    /// 
    /// This method is used to **Permanently Remove** a file, database 
    /// record, or other resource identified by the URI.
    DELETE,
    /// Asks for a response identical to a GET request, but without the response body.
    /// 
    /// Extremely useful for **Meta-data Checks**, such as verifying file 
    /// size or MIME type via headers before committing to a full download.
    HEAD,
    /// Used to describe the communication options for the target resource.
    /// 
    /// Essential for **CORS (Cross-Origin Resource Sharing)**, where 
    /// browsers perform a "pre-flight" check to see which methods are permitted.
    OPTIONS,
    /// Establishes a tunnel to the server identified by the target resource.
    /// 
    /// Typically used for **SSL/TLS Proxying**, allowing secure 
    /// communication to pass through intermediate servers.
    CONNECT,
    /// Performs a message loop-back test along the path to the target resource.
    /// 
    /// Primarily a **Diagnostic Tool**, it echoes back the received 
    /// request so the client can see what changes proxies might be making.
    TRACE,
    /// Creates a duplicate of the source resource at the destination.
    /// 
    /// Primarily used in **File Management** to copy files or directories 
    /// without downloading and re-uploading the data.
    COPY,
    /// Moves a resource from one URI to another.
    /// 
    /// Equivalent to a **Rename** or **Cut-and-Paste** operation on a 
    /// remote file system.
    MOVE,
    /// Creates a new collection (folder/directory) at the specified location.
    /// 
    /// Used in **WebDAV** instead of `POST` or `PUT` to explicitly create 
    /// directory structures.
    MKCOL,
    /// Retrieves properties (metadata) for a resource.
    /// 
    /// This is the most used WebDAV method. it allows the client to ask: 
    /// "Is this a file or folder? What is its size? When was it modified?"
    PROPFIND,
    /// Used to "lock" a resource to prevent overwrite conflicts.
    /// 
    /// Essential for **Collaborative Editing**, ensuring only one user 
    /// can modify a file at a time.
    LOCK,
    /// Removes a lock previously established by the LOCK method.
    /// 
    /// Replaces the resource in a "read-only" or "shared" state so 
    /// other users can begin editing.
    UNLOCK
}
pub use Method::*;

impl Method {
    /// The method name as sent on the wire (e.g. `"GET"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            GET => "GET",
            POST => "POST",
            PUT => "PUT",
            PATCH => "PATCH",
            DELETE => "DELETE",
            HEAD => "HEAD",
            OPTIONS => "OPTIONS",
            CONNECT => "CONNECT",
            TRACE => "TRACE",
            COPY => "COPY",
            MOVE => "MOVE",
            MKCOL => "MKCOL",
            PROPFIND => "PROPFIND",
            LOCK => "LOCK",
            UNLOCK => "UNLOCK",
        }
    }
}

/// The central Application controller.
/// Manages routing, middleware, and the internal TCP lifecycle.
pub struct WebIo {
    routes: Vec<(String, String, Handler)>,
    pub mime_types: HashMap<String, String>,
    mw: Vec<Middleware>,
    handlers_404: HashMap<String, Handler>,
    static_dir: String,
    pub log_reply_enabled: bool,
    pub nagle_enabled: bool,
    pub clients: Arc<Mutex<Vec<TcpStream>>>,
    pub cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    pub banner_text: String,
    cache_bytes: AtomicUsize,
    max_body_size: usize,
    max_connections: usize,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl Default for WebIo {
    fn default() -> Self { Self::new() }
}

/// Decrements the active-connection counter when a worker ends, including
/// when the worker thread unwinds from a panic.
struct SlotGuard(Arc<AtomicUsize>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Streams a file from disk in 64 KiB chunks so large assets never sit in RAM.
struct FileBody(std::fs::File);

impl BodyStream for FileBody {
    fn next_chunk(&mut self) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match self.0.read(&mut buf) {
                Ok(0) => return None,
                Ok(n) => {
                    buf.truncate(n);
                    return Some(buf);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("WebIO: static file read error: {}", e);
                    return None;
                }
            }
        }
    }
}

impl WebIo {
    /// Initializes a new WebIo instance with an empty routing table.
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            mime_types: mime::default_mime_types(),
            mw: Vec::new(),
            handlers_404: HashMap::new(),
            static_dir: "assets".to_string(), // Default name ==> "assets"
            log_reply_enabled: false, // default value
            nagle_enabled: true, // Default to ON (High Throughput)
            clients: Arc::new(Mutex::new(Vec::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            banner_text: "🦅 WebIO Live:".to_string(), // Default banner_text ==> "🦅 WebIO Live:"
            cache_bytes: AtomicUsize::new(0),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            read_timeout: DEFAULT_READ_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }

    pub fn broadcast(&self, message: &str) {
        // Lock the global client list (recover the data if a holder panicked)
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        // Wrap the text message in the binary WebSocket protocol
        let frame = encode_ws_frame(message);

        // Send to everyone and automatically clean up "ghost" connections
        clients.retain_mut(|client| {
            io::Write::write_all(client, &frame).is_ok()
        });
    }

    /// Toggles TCP_NODELAY (Nagle's Algorithm)
    pub fn set_nagle(mut self, enabled: bool) -> Self {
        self.nagle_enabled = enabled;
        self
    }

    /// Sets the largest request body (in bytes) the engine will read into
    /// memory. Larger requests are answered with `413 Content Too Large`
    /// before the handler runs. Default: [`DEFAULT_MAX_BODY_SIZE`] (10 MiB).
    pub fn set_max_body_size(mut self, bytes: usize) -> Self {
        self.max_body_size = bytes;
        self
    }

    /// Sets how many connections may be handled at once. Connections beyond
    /// this limit receive `503 Service Unavailable`.
    /// Default: [`DEFAULT_MAX_CONNECTIONS`].
    pub fn set_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max.max(1);
        self
    }

    /// Sets socket timeouts.
    ///
    /// * `read` — total time allowed to receive one request (head and body).
    ///   Clients slower than this get `408 Request Timeout`.
    /// * `write` — time allowed for each socket write while sending a reply.
    ///
    /// Defaults: [`DEFAULT_READ_TIMEOUT`], [`DEFAULT_WRITE_TIMEOUT`].
    pub fn set_timeouts(mut self, read: Duration, write: Duration) -> Self {
        self.read_timeout = read;
        self.write_timeout = write;
        self
    }

    /// Logs the details of an HTTP reply, including method, path, status code, and processing time.
    ///
    /// # Parameters
    /// - `method`: The HTTP method of the handled request (e.g., "GET", "POST").
    /// - `path`: The URL path that was processed (e.g., "/api/data").
    /// - `status`: The HTTP status code of the outgoing reply (e.g., 200, 404).
    /// - `start`: The `Instant` timestamp when the request started, used to calculate reply latency.
    /// - `should_log`: A boolean flag indicating whether to perform logging. If `false`, the function returns immediately.
    ///
    /// # Behavior
    /// - If `should_log` is `false`, no log is produced.
    /// - If `true`, logs a timestamped message showing the reply details and the elapsed time since `start`.
    /// - The timestamp is formatted as HH:MM:SS (UTC) based on the current system time.
    /// - The log includes high-resolution timing (`start.elapsed()`) to measure the full lifecycle of the reply.
    fn log_reply(&self, method: &str, path: &str, status: u16, start: Instant, should_log: bool) {
        if !should_log {
            return;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        println!(
            "[{:02}:{:02}:{:02}] {} {} -> {} ({:?})",
            (now/3600)%24, (now/60)%60, now%60,
            method, path, status, start.elapsed()
        );
    }

    /// Configures the root directory for serving static assets (CSS, JS, Images, etc.).
    /// Example: app.use_static("src/assets");
    ///
    /// Only files that resolve (after following symlinks) to a location inside
    /// this directory are served. Paths containing `..` are rejected, and
    /// hidden entries (names starting with `.`, except `.well-known`) are
    /// never served.
    pub fn use_static(&mut self, path: &str) {
        self.static_dir = path.to_string();
    }

    /// Resolves `segments` inside the static root and returns a reply for the file.
    fn serve_static(&self, segments: &[String]) -> Option<Reply> {
        if segments.is_empty() {
            return None;
        }
        if segments.iter().any(|s| s.starts_with('.') && s != ".well-known") {
            return None;
        }
        let root = std::fs::canonicalize(&self.static_dir).ok()?;

        // 1. Direct Match (e.g., /css/style.css)
        let mut candidate = root.clone();
        for seg in segments {
            candidate.push(seg);
        }
        if let Some(path) = Self::confine(&root, &candidate) {
            return self.create_file_reply(&path);
        }

        // 2. Dynamic Discovery for favicon.ico
        // If the browser asks for /favicon.ico but it's not at the root, search all folders.
        if segments.len() == 1 && segments[0] == "favicon.ico" {
            let found = find_file_recursive(&root, "favicon.ico")?;
            let path = Self::confine(&root, &found)?;
            return self.create_file_reply(&path);
        }

        None
    }

    /// Returns the canonical path of `candidate` if it is a regular file located
    /// inside `root` (which must already be canonical).
    fn confine(root: &Path, candidate: &Path) -> Option<PathBuf> {
        let real = std::fs::canonicalize(candidate).ok()?;
        if real.starts_with(root) && real.is_file() {
            Some(real)
        } else {
            None
        }
    }

    fn create_file_reply(&self, path: &Path) -> Option<Reply> {
        let path_str = path.to_string_lossy().to_string();

        // --- STEP 1: FAST PATH (Check RAM Cache) ---
        {
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(content) = cache.get(&path_str) {
                return Some(self.build_reply_with_mime(path, content.clone()));
            }
        }

        // --- STEP 2: SLOW PATH ---
        let file = std::fs::File::open(path).ok()?;
        let len = file.metadata().ok()?.len();

        if len >= STATIC_CACHE_FILE_LIMIT as u64 {
            // Large file: stream from disk, never load it whole into RAM.
            let mut reply = self.build_reply_with_mime(path, Vec::new());
            reply.body = Box::new(FileBody(file));
            return Some(reply);
        }

        let content = std::fs::read(path).ok()?;
        if content.len() < STATIC_CACHE_FILE_LIMIT {
            let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
            let used = self.cache_bytes.load(Ordering::Relaxed);
            if !cache.contains_key(&path_str) && used + content.len() <= STATIC_CACHE_TOTAL_LIMIT {
                self.cache_bytes.fetch_add(content.len(), Ordering::Relaxed);
                cache.insert(path_str, content.clone());
            }
        }
        Some(self.build_reply_with_mime(path, content))
    }

    /// Sets (adds or updates) a single MIME type mapping in the registry.
    /// 
    /// If the extension already exists, the associated MIME type is updated 
    /// to the new value.
    /// 
    /// # Arguments
    /// * `ext` - The file extension (e.g., "webp").
    /// * `mime` - The corresponding MIME media type (e.g., "image/webp").
    /// 
    /// # Example
    /// ```
    /// use webio::*;
    /// let mut app = WebIo::new();
    /// app.set_mime("webp", "image/webp");
    /// ```
    pub fn set_mime(&mut self, ext: &str, mime: &str) {
        mime::set_mime_logic(&mut self.mime_types, ext, mime);
    }

    /// Sets multiple MIME type mappings at once.
    /// 
    /// Useful for bulk-updating the registry from a configuration list.
    /// 
    /// # Arguments
    /// * `types` - A vector of tuples containing `(extension, mime_type)`.
    /// 
    /// # Example
    /// ```
    /// use webio::*;
    /// let mut app = WebIo::new();
    /// app.set_mimes(vec![("woff2", "font/woff2"), ("wasm", "application/wasm")]);
    /// ```
    pub fn set_mimes(&mut self, types: Vec<(&str, &str)>) {
        mime::set_mimes_logic(&mut self.mime_types, types);
    }

    /// Removes a single MIME type mapping from the registry.
    /// 
    /// If the extension is not found in the registry, the function does nothing.
    /// 
    /// # Arguments
    /// * `ext` - The file extension to be removed (e.g., "php").
    /// 
    /// # Example
    /// ```
    /// use webio::*;
    /// let mut app = WebIo::new();
    /// // Disable serving of PHP files
    /// app.remove_mime("php");
    /// ```
    pub fn remove_mime(&mut self, ext: &str) {
        mime::remove_mime_logic(&mut self.mime_types, ext);
    }

    /// Removes multiple MIME type mappings from the registry at once.
    /// 
    /// Ideal for disabling entire categories of files (e.g., all video formats).
    /// 
    /// # Arguments
    /// * `exts` - A vector of file extensions to be removed.
    /// 
    /// # Example
    /// ```
    /// use webio::*;
    /// let mut app = WebIo::new();
    /// // Disable multiple video formats
    /// let to_remove = vec!["mp4", "webm", "avi", "mov"];
    /// app.remove_mimes(to_remove);
    /// ```
    pub fn remove_mimes(&mut self, exts: Vec<&str>) {
        mime::remove_mimes_logic(&mut self.mime_types, exts);
    }

    /// Internal helper to look up MIME types and construct a `Reply` object.
    /// 
    /// This method extracts the file extension from the provided `Path`, 
    /// performs a case-insensitive lookup in the registry, and sets the 
    /// `Content-Type` header accordingly.
    /// 
    /// # Fallback
    /// If no extension is found or the extension is unknown, it defaults 
    /// to `application/octet-stream`.
    fn build_reply_with_mime(&self, path: &Path, content: Vec<u8>) -> Reply {
        // 1. Extract the extension, convert to string, and handle case-sensitivity
        let ext = path.extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_lowercase()) // Ensures .JPG and .jpg both work
            .unwrap_or_default();
        
        // 2. Dynamic lookup in the HashMap
        // If the extension isn't found, it fall back to "application/octet-stream".
        let ct = self.mime_types.get(&ext)
            .map(|s| s.as_str())
            .unwrap_or("application/octet-stream");

        // 3. Build and return the Reply
        Reply::new(StatusCode::Ok)
            .header("Content-Type", ct)
            .body(content)
    }

    /// Registers a global middleware function.
    ///
    /// Middleware runs in registration order before routing. The first one
    /// that returns `Some(Reply)` ends the request cycle early; later
    /// middleware and the route handler do not run.
    ///
    /// The `&str` argument is the normalized request path: repeated slashes
    /// are collapsed (`//a///b` → `/a/b`) and the query string, if any, is
    /// kept (`/a/b?x=1`). Requests containing `..` segments are rejected with
    /// `400` before middleware runs.
    pub fn use_mw<F>(&mut self, f: F) where F: Fn(&str) -> Option<Reply> + Send + Sync + 'static {
        self.mw.push(Box::new(f));
    }

    /// Configures custom 404 handlers.
    ///
    /// The handler is invoked once at registration with a dummy request to
    /// read its `Content-Type`: a JSON handler is used for non-browser
    /// clients, any other handler for clients that accept `text/html`.
    pub fn on_404<F, Fut>(&mut self, handler: F)
    where
        F: Fn(Req, Params) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Reply> + Send + 'static,
    {
        let h: Handler = Box::new(move |r, p| Box::pin(handler(r, p)));
        let kind = Self::sniff_404_kind(&h);
        self.handlers_404.insert(kind.to_string(), h);
    }

    /// Runs `h` against a dummy request to classify it as a JSON or HTML 404
    /// handler. Falls back to `"html"` if the probe cannot run.
    fn sniff_404_kind(h: &Handler) -> &'static str {
        // A `Req` needs a real socket; create a throwaway loopback pair.
        let probe = || -> Option<String> {
            let listener = TcpListener::bind("127.0.0.1:0").ok()?;
            let stream = TcpStream::connect(listener.local_addr().ok()?).ok()?;
            let dummy_req = Req {
                method: "GET".into(),
                path: "/404_sniff".into(),
                body: String::new(),
                body_bytes: Vec::new(),
                headers: HashMap::new(),
                stream,
            };
            let sniff = panic::catch_unwind(AssertUnwindSafe(|| {
                block_on(h(dummy_req, Params(HashMap::new())))
            })).ok()?;
            sniff.headers.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.to_lowercase())
        };
        match probe() {
            Some(ct) if ct.contains("json") => "json",
            _ => "html",
        }
    }

    /// Defines a route with a specific method and path.
    /// Supports dynamic segments using `<name>` syntax (e.g., `/user/<id>`).
    ///
    /// Routes are matched in registration order. A `HEAD` request with no
    /// `HEAD` route falls back to the matching `GET` route (the body is not sent).
    pub fn route<F, Fut>(&mut self, method: Method, path: &str, handler: F)
    where F: Fn(Req, Params) -> Fut + Send + Sync + 'static, Fut: Future<Output = Reply> + Send + 'static,
    {
        self.routes.push((method.as_str().to_string(), path.to_string(), Box::new(move |r, p| Box::pin(handler(r, p)))));
    }

    /// Helper to determine the banner content.
    ///
    /// If `text` is empty, it returns the default framework message:
    /// `"🦅 WebIO Live:"`. Otherwise, it returns the user-provided string.
    fn rename_banner(text: &str) -> String {
        if text.is_empty() {
            "🦅 WebIO Live:".to_string()
        } else {
            text.to_string()
        }
    }

    /// Binds `host:port` and serves forever. Panics if the address cannot be bound.
    ///
    /// Use [`WebIo::try_run`] to handle bind errors, or [`WebIo::serve`] to
    /// supply an already-bound listener.
    ///
    /// ### Reliability & Safety:
    /// * **Thread-per-connection:** every connection gets a dedicated OS thread;
    ///   at most `max_connections` ([`WebIo::set_max_connections`]) run at once.
    ///   Further connections receive `503 Service Unavailable`.
    /// * **Panic isolation:** a panicking handler produces `500 Internal Server
    ///   Error` for that request only; the connection slot is always released.
    /// * **Bounded reads:** request heads are limited to 16 KiB, bodies to
    ///   `max_body_size`, and each request must arrive within the read timeout.
    pub fn run(self, host: &str, port: &str) {
        if let Err(e) = self.try_run(host, port) {
            panic!("WebIO: failed to serve on {}:{}: {}", host, port, e);
        }
    }

    /// Like [`WebIo::run`], but returns an error instead of panicking when the
    /// address is invalid or cannot be bound.
    pub fn try_run(self, host: &str, port: &str) -> io::Result<()> {
        let port: u16 = port.trim().parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid port: {:?}", port)))?;
        let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
        let listener = TcpListener::bind(&addrs[..])?;
        println!("{} http://{}:{}", Self::rename_banner(&self.banner_text), host, port);
        self.serve_loop(listener)
    }

    /// Serves forever on an already-bound listener (e.g. one bound to port 0
    /// in tests, or passed in by a process supervisor).
    pub fn serve(self, listener: TcpListener) -> io::Result<()> {
        if let Ok(addr) = listener.local_addr() {
            println!("{} http://{}", Self::rename_banner(&self.banner_text), addr);
        }
        self.serve_loop(listener)
    }

    fn serve_loop(self, listener: TcpListener) -> io::Result<()> {
        let app = Arc::new(self);
        let active = Arc::new(AtomicUsize::new(0));

        for conn in listener.incoming() {
            let stream = match conn {
                Ok(s) => s,
                Err(e) => {
                    // e.g. EMFILE: back off briefly instead of spinning.
                    eprintln!("WebIO: accept error: {}", e);
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };

            // Toggle Nagle's Algorithm (TCP_NODELAY) based on engine config
            let _ = stream.set_nodelay(!app.nagle_enabled);

            // --- SAFETY VALVE: connection limit (atomic reserve, no check-then-act race) ---
            if active.fetch_add(1, Ordering::SeqCst) >= app.max_connections {
                active.fetch_sub(1, Ordering::SeqCst);
                Self::reject_busy(stream);
                continue;
            }
            let guard = SlotGuard(Arc::clone(&active));
            let a = Arc::clone(&app);

            // OS-Level Isolation: a dedicated thread per connection.
            let spawned = thread::Builder::new()
                .name("webio-conn".to_string())
                .spawn(move || {
                    let _guard = guard; // released on return *and* on unwind
                    a.handle_connection(stream);
                });
            if let Err(e) = spawned {
                // The closure (with guard and stream) is dropped: slot released, socket closed.
                eprintln!("WebIO: failed to spawn worker thread: {}", e);
            }
        }
        Ok(())
    }

    /// Answers `503` without spawning a worker.
    fn reject_busy(stream: TcpStream) {
        let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
        let reply = Reply::new(StatusCode::ServiceUnavailable)
            .header("Content-Type", "text/plain; charset=UTF-8")
            .header("Retry-After", "1")
            .body("Server busy");
        let _ = http::write_reply(&mut &stream, reply, false);
        let _ = stream.shutdown(Shutdown::Write);
        // Discard request bytes that have already arrived, without blocking
        // the accept loop, so closing sends FIN rather than RST and the client
        // can read the 503.
        if stream.set_nonblocking(true).is_ok() {
            use std::io::Read;
            let mut buf = [0u8; 4096];
            while let Ok(n) = (&stream).read(&mut buf) {
                if n == 0 { break; }
            }
        }
    }

    // --- WORKER IMPLEMENTATION ---

    /// Full HTTP request-response lifecycle for one connection, run on its own
    /// OS thread.
    ///
    /// ### Protocol Execution Phases:
    /// 1. **Bounded ingestion:** reads the head (≤ 16 KiB, ≤ 100 headers) and a
    ///    `Content-Length` body (≤ `max_body_size`) within the read timeout.
    ///    Invalid requests get 400/408/413/417/431/501/505 and never reach a handler.
    /// 2. **Normalization:** collapses repeated slashes and rejects `..`.
    /// 3. **Middleware** in registration order.
    /// 4. **Routing** by method and segment count, `<name>` segments become `Params`.
    ///    Falls back to static files (GET/HEAD only), then the 404 handlers.
    /// 5. **Panic isolation:** any panic in middleware or handlers becomes a 500.
    fn handle_connection(&self, mut stream: TcpStream) {
        let start_time = Instant::now();
        let _ = stream.set_write_timeout(Some(self.write_timeout));

        let limits = ReadLimits { max_body: self.max_body_size, deadline: self.read_timeout };
        let parsed = match http::read_request(&mut stream, &limits) {
            Ok(p) => p,
            Err(ParseError::Closed) => return,
            Err(ParseError::Reject(status, message)) => {
                let _ = http::write_simple(&mut &stream, status, message);
                self.log_reply("-", "-", status as u16, start_time, self.log_reply_enabled);
                Self::lingering_close(stream);
                return;
            }
        };

        let method = parsed.method.clone();
        let target = parsed.target.clone();
        let is_head = method == "HEAD";

        let Some(canon) = http::canonicalize_target(&parsed.target) else {
            let reply = Reply::new(StatusCode::BadRequest)
                .header("Content-Type", "text/plain; charset=UTF-8")
                .body("Invalid path");
            self.finalize(stream, reply, &method, &target, start_time, is_head);
            return;
        };

        // The body has been fully read. Unless the handler may take over the
        // socket (WebSocket upgrade), close the read side so handlers that
        // loop on `req.stream.read()` see EOF immediately instead of blocking.
        let is_upgrade = parsed.headers.contains_key("upgrade");
        if !is_upgrade {
            let _ = stream.shutdown(Shutdown::Read);
        }
        let _ = stream.set_read_timeout(Some(self.read_timeout));

        let handler_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("WebIO: socket clone failed: {}", e);
                let reply = Reply::new(StatusCode::InternalServerError).body("Internal Server Error");
                self.finalize(stream, reply, &method, &target, start_time, is_head);
                return;
            }
        };

        let req = Req {
            method: parsed.method,
            path: parsed.target,
            body: String::from_utf8_lossy(&parsed.body).into_owned(),
            body_bytes: parsed.body,
            headers: parsed.headers,
            stream: handler_stream,
        };

        let reply = match panic::catch_unwind(AssertUnwindSafe(|| self.dispatch(req, &canon))) {
            Ok(reply) => reply,
            Err(_) => Reply::new(StatusCode::InternalServerError)
                .header("Content-Type", "text/plain; charset=UTF-8")
                .body("Internal Server Error"),
        };

        self.finalize(stream, reply, &method, &target, start_time, is_head);
    }

    /// Runs middleware, routing, static files and 404 handling for one request.
    fn dispatch(&self, req: Req, canon: &http::CanonicalPath) -> Reply {
        // --- MIDDLEWARE EXECUTION ---
        for mw_func in &self.mw {
            if let Some(early_reply) = mw_func(&canon.normalized) {
                return early_reply;
            }
        }

        // --- ROUTING & DISPATCH ---
        let method = req.method.as_str();
        let found = self.find_route(method, &canon.raw_segments)
            .or_else(|| if method == "HEAD" { self.find_route("GET", &canon.raw_segments) } else { None });
        if let Some((handler, params)) = found {
            return block_on(handler(req, Params(params)));
        }

        // --- STATIC ASSETS (GET/HEAD only) ---
        if method == "GET" || method == "HEAD" {
            if let Some(segments) = &canon.fs_segments {
                if let Some(reply) = self.serve_static(segments) {
                    return reply;
                }
            }
        }

        // --- Content-Type Aware Smart 404 ---
        let accept = req.headers.get("accept").cloned().unwrap_or_default();
        let h_404 = if accept.contains("text/html") {
            self.handlers_404.get("html")
        } else {
            self.handlers_404.get("json")
        };
        match h_404 {
            Some(h) => block_on(h(req, Params(HashMap::new()))),
            None => Reply::new(StatusCode::NotFound)
                .header("Content-Type", "text/plain; charset=UTF-8")
                .body("404 Not Found"),
        }
    }

    /// Finds the first route registered for `method` whose pattern matches `segments`.
    fn find_route(&self, method: &str, segments: &[String]) -> Option<(&Handler, HashMap<String, String>)> {
        'routes: for (r_method, r_path, handler) in &self.routes {
            if r_method != method { continue; }
            let route_segments: Vec<&str> = r_path.split('/').filter(|s| !s.is_empty()).collect();
            if route_segments.len() != segments.len() { continue; }
            let mut params = HashMap::new();
            for (r_seg, p_seg) in route_segments.iter().zip(segments.iter()) {
                if r_seg.len() >= 2 && r_seg.starts_with('<') && r_seg.ends_with('>') {
                    params.insert(r_seg[1..r_seg.len() - 1].to_string(), p_seg.clone());
                } else if r_seg != p_seg {
                    continue 'routes;
                }
            }
            return Some((handler, params));
        }
        None
    }

    /// After an error response, stop sending and briefly drain unread input
    /// so the kernel does not reset the connection before the client has
    /// read the response (RFC 9112 §9.6).
    fn lingering_close(stream: TcpStream) {
        use std::io::Read;
        let _ = stream.shutdown(Shutdown::Write);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut buf = [0u8; 8192];
        let mut drained = 0usize;
        while Instant::now() < deadline && drained < 1024 * 1024 {
            match (&stream).read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => drained += n,
            }
        }
    }

    // --- PROTOCOL FINALIZATION & SERIALIZATION ---

    /// Serializes the reply using HTTP/1.1 chunked transfer encoding, logs it,
    /// and closes the connection.
    ///
    /// * A `101 Switching Protocols` reply writes nothing and leaves the socket
    ///   open: the handler already completed a WebSocket handshake and owns
    ///   the connection through its cloned stream.
    /// * `HEAD`, 1xx, 204 and 304 replies are sent without a body.
    /// * `Content-Length`, `Transfer-Encoding` and `Connection` headers set by
    ///   handlers are ignored; the engine controls message framing.
    /// * Header names/values containing CR/LF are dropped.
    fn finalize(&self, stream: TcpStream, reply: Reply, method: &str, path: &str, start: Instant, is_head: bool) {
        let status = reply.status;
        if status == StatusCode::SwitchingProtocols as u16 {
            self.log_reply(method, path, status, start, self.log_reply_enabled);
            return;
        }
        {
            // 64KB buffer batches headers and first chunks into few syscalls.
            let mut writer = BufWriter::with_capacity(65536, &stream);
            let _ = http::write_reply(&mut writer, reply, is_head);
        }
        self.log_reply(method, path, status, start, self.log_reply_enabled);
        let _ = stream.shutdown(Shutdown::Both);
    }
}
