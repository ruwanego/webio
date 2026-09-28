//! Internal HTTP/1.1 wire handling: bounded request parsing and response
//! serialization. Not part of the public API.

use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::core::{Reply, StatusCode};

/// Maximum size of the request line plus all header lines.
pub(crate) const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Maximum number of header fields in one request.
pub(crate) const MAX_HEADERS: usize = 100;

/// A request whose head and body have been fully read from the socket.
pub(crate) struct ParsedRequest {
    pub method: String,
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Why a request could not be parsed.
pub(crate) enum ParseError {
    /// The peer closed the connection or sent nothing; there is nobody to answer.
    Closed,
    /// The request is invalid; answer with this status and message, then close.
    Reject(StatusCode, &'static str),
}

pub(crate) struct ReadLimits {
    pub max_body: usize,
    /// Total time allowed to receive the head and body of one request.
    pub deadline: Duration,
}

/// Reads exactly one request (head + Content-Length body) from `stream`.
///
/// Every read is bounded by an overall deadline so a client that drips bytes
/// cannot hold a worker thread forever.
pub(crate) fn read_request(stream: &mut TcpStream, limits: &ReadLimits) -> Result<ParsedRequest, ParseError> {
    let deadline = Instant::now() + limits.deadline;

    // --- 1. Read until the blank line that ends the head. ---
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(ParseError::Reject(StatusCode::RequestHeaderFieldsTooLarge, "Request head too large"));
        }
        match read_before(stream, &mut chunk, deadline) {
            Ok(0) => return Err(ParseError::Closed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if is_timeout(&e) => {
                return if buf.is_empty() {
                    Err(ParseError::Closed)
                } else {
                    Err(ParseError::Reject(StatusCode::RequestTimeout, "Request timeout"))
                };
            }
            Err(_) => return Err(ParseError::Closed),
        }
    };
    if head_end > MAX_HEAD_BYTES {
        return Err(ParseError::Reject(StatusCode::RequestHeaderFieldsTooLarge, "Request head too large"));
    }

    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| ParseError::Reject(StatusCode::BadRequest, "Request head is not valid UTF-8"))?;
    let mut lines = head.split("\r\n");

    // --- 2. Request line: METHOD SP target SP HTTP/x.y ---
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) => (m, t, v),
        _ => return Err(ParseError::Reject(StatusCode::BadRequest, "Malformed request line")),
    };
    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return Err(ParseError::Reject(StatusCode::BadRequest, "Invalid method"));
    }
    if !target.starts_with('/') || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(ParseError::Reject(StatusCode::BadRequest, "Invalid request target"));
    }
    match version {
        "HTTP/1.1" | "HTTP/1.0" => {}
        v if v.starts_with("HTTP/") => {
            return Err(ParseError::Reject(StatusCode::HTTPVersionNotSupported, "HTTP version not supported"));
        }
        _ => return Err(ParseError::Reject(StatusCode::BadRequest, "Malformed request line")),
    }

    // --- 3. Header fields ---
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut count = 0usize;
    for line in lines {
        count += 1;
        if count > MAX_HEADERS {
            return Err(ParseError::Reject(StatusCode::RequestHeaderFieldsTooLarge, "Too many headers"));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Obsolete line folding (RFC 9112 §5.2).
            return Err(ParseError::Reject(StatusCode::BadRequest, "Obsolete header folding"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(ParseError::Reject(StatusCode::BadRequest, "Malformed header line"))?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(ParseError::Reject(StatusCode::BadRequest, "Invalid header name"));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        match headers.get_mut(&name) {
            Some(existing) => {
                existing.push_str(", ");
                existing.push_str(value);
            }
            None => {
                headers.insert(name, value.to_string());
            }
        }
    }

    // --- 4. Body framing ---
    if headers.contains_key("transfer-encoding") {
        return Err(ParseError::Reject(StatusCode::NotImplemented, "Transfer-Encoding request bodies are not supported"));
    }
    let content_length = match headers.get("content-length") {
        None => 0,
        Some(raw) => parse_content_length(raw)
            .ok_or(ParseError::Reject(StatusCode::BadRequest, "Invalid Content-Length"))?,
    };
    if content_length > limits.max_body {
        return Err(ParseError::Reject(StatusCode::PayloadTooLarge, "Payload Too Large"));
    }

    let mut body: Vec<u8> = buf[head_end + 4..].to_vec();
    if body.len() > content_length {
        // Pipelined data after the body is not supported (Connection: close); drop it.
        body.truncate(content_length);
    }

    if body.len() < content_length {
        if let Some(expect) = headers.get("expect") {
            if expect.eq_ignore_ascii_case("100-continue") {
                let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            } else {
                return Err(ParseError::Reject(StatusCode::ExpectationFailed, "Unsupported Expect value"));
            }
        }
        body.reserve_exact(content_length - body.len());
        while body.len() < content_length {
            let want = (content_length - body.len()).min(chunk.len());
            match read_before(stream, &mut chunk[..want], deadline) {
                Ok(0) => return Err(ParseError::Closed),
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(e) if is_timeout(&e) => {
                    return Err(ParseError::Reject(StatusCode::RequestTimeout, "Request body timeout"));
                }
                Err(_) => return Err(ParseError::Closed),
            }
        }
    }

    Ok(ParsedRequest {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        body,
    })
}

/// One `read` call that fails with `TimedOut` once `deadline` has passed.
fn read_before(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(ErrorKind::TimedOut, "request deadline exceeded"));
    }
    stream.set_read_timeout(Some(remaining))?;
    loop {
        match stream.read(buf) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Accepts `N` or a list of identical values (`N, N`); rejects anything else.
fn parse_content_length(raw: &str) -> Option<usize> {
    let mut value: Option<usize> = None;
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: usize = part.parse().ok()?;
        match value {
            Some(v) if v != n => return None,
            _ => value = Some(n),
        }
    }
    value
}

/// RFC 9110 `tchar`.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// --- PATH HANDLING ---

/// The request path split into decoded, validated segments.
pub(crate) struct CanonicalPath {
    /// Raw (still percent-encoded) non-empty segments, used for route matching.
    pub raw_segments: Vec<String>,
    /// Percent-decoded segments, safe to join onto a filesystem root.
    pub fs_segments: Option<Vec<String>>,
    /// `/seg/seg` rebuilt from raw segments, with the query appended if present.
    pub normalized: String,
}

/// Splits the target into path segments, collapsing empty segments.
///
/// Returns `None` if the path contains a `..` segment (encoded or not), which
/// is rejected outright.
pub(crate) fn canonicalize_target(target: &str) -> Option<CanonicalPath> {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    let path = path.split('#').next().unwrap_or("");

    let mut raw_segments = Vec::new();
    let mut fs_segments = Some(Vec::new());
    for seg in path.split('/').filter(|s| !s.is_empty() && *s != ".") {
        let decoded = crate::utils::percent_decode(seg, false);
        if seg == ".." || decoded == ".." {
            return None;
        }
        let fs_unsafe = decoded.is_empty()
            || decoded == "."
            || decoded.contains(['/', '\\', '\0'])
            || (cfg!(windows) && decoded.contains(':'));
        match (&mut fs_segments, !fs_unsafe) {
            (Some(v), true) => v.push(decoded),
            _ => fs_segments = None,
        }
        raw_segments.push(seg.to_string());
    }

    let mut normalized = String::with_capacity(target.len());
    for seg in &raw_segments {
        normalized.push('/');
        normalized.push_str(seg);
    }
    if normalized.is_empty() {
        normalized.push('/');
    }
    if let Some(q) = query {
        normalized.push('?');
        normalized.push_str(q);
    }

    Some(CanonicalPath { raw_segments, fs_segments, normalized })
}

// --- RESPONSE SERIALIZATION ---

/// Headers that the engine owns; values set by handlers are ignored.
const ENGINE_HEADERS: [&str; 3] = ["content-length", "transfer-encoding", "connection"];

/// Serializes `reply` onto `writer` using chunked transfer encoding.
///
/// * Bodies are never sent for `HEAD`, 1xx, 204 and 304.
/// * Framing headers set by the handler are dropped (the engine controls framing).
/// * Header names/values containing CR, LF or NUL are dropped (response splitting).
pub(crate) fn write_reply<W: Write>(writer: &mut W, mut reply: Reply, is_head: bool) -> io::Result<()> {
    let status = reply.status;
    let no_body = is_head || (100..200).contains(&status) || status == 204 || status == 304;

    let mut head = String::with_capacity(256);
    head.push_str("HTTP/1.1 ");
    head.push_str(&status.to_string());
    head.push(' ');
    head.push_str(reason_phrase(status));
    head.push_str("\r\n");

    let mut has_date = false;
    for (k, v) in &reply.headers {
        if !is_valid_header_name(k) || !is_valid_header_value(v) {
            continue;
        }
        if ENGINE_HEADERS.iter().any(|h| k.eq_ignore_ascii_case(h)) {
            continue;
        }
        has_date |= k.eq_ignore_ascii_case("date");
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    if !has_date {
        head.push_str("Date: ");
        head.push_str(&http_date(SystemTime::now()));
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n");

    if no_body {
        head.push_str("\r\n");
        writer.write_all(head.as_bytes())?;
        return writer.flush();
    }

    head.push_str("Transfer-Encoding: chunked\r\n\r\n");
    writer.write_all(head.as_bytes())?;

    while let Some(data) = reply.body.next_chunk() {
        // An empty chunk would terminate the stream early; skip it.
        if data.is_empty() {
            continue;
        }
        writer.write_all(format!("{:X}\r\n", data.len()).as_bytes())?;
        writer.write_all(&data)?;
        writer.write_all(b"\r\n")?;
    }
    writer.write_all(b"0\r\n\r\n")?;
    writer.flush()
}

/// Writes a minimal plain-text response. Used for protocol-level rejections
/// where no handler runs.
pub(crate) fn write_simple<W: Write>(writer: &mut W, status: StatusCode, message: &str) -> io::Result<()> {
    let reply = Reply::new(status)
        .header("Content-Type", "text/plain; charset=UTF-8")
        .body(message);
    write_reply(writer, reply, false)
}

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_byte)
}

fn is_valid_header_value(value: &str) -> bool {
    !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Canonical reason phrase for a status code (RFC 9110). Unknown codes get an
/// empty phrase, which is valid on the wire.
pub(crate) fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

/// Formats `t` as an IMF-fixdate, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
pub(crate) fn http_date(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem / 60) % 60, rem % 60);

    // Civil-from-days (Howard Hinnant), valid for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };

    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let weekday = WEEKDAYS[days.rem_euclid(7) as usize];

    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        weekday, day, MONTHS[(month - 1) as usize], year, h, m, s
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn http_date_matches_rfc_example() {
        let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(http_date(t), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(http_date(leap), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn content_length_parsing() {
        assert_eq!(parse_content_length("42"), Some(42));
        assert_eq!(parse_content_length("7, 7"), Some(7));
        assert_eq!(parse_content_length("7, 8"), None);
        assert_eq!(parse_content_length("+7"), None);
        assert_eq!(parse_content_length("-1"), None);
        assert_eq!(parse_content_length(""), None);
        assert_eq!(parse_content_length("99999999999999999999999"), None);
    }

    #[test]
    fn canonical_paths() {
        let p = canonicalize_target("//a///b/?x=1").unwrap();
        assert_eq!(p.raw_segments, vec!["a", "b"]);
        assert_eq!(p.normalized, "/a/b?x=1");
        assert_eq!(canonicalize_target("/").unwrap().normalized, "/");
        assert!(canonicalize_target("/a/../etc/passwd").is_none());
        assert!(canonicalize_target("/a/%2e%2E/etc").is_none());
        assert!(canonicalize_target("/a/%2E%2E").is_none());
        // Encoded slash must never become a filesystem separator.
        assert!(canonicalize_target("/a%2Fb").unwrap().fs_segments.is_none());
        assert_eq!(
            canonicalize_target("/css/my%20file.css").unwrap().fs_segments.unwrap(),
            vec!["css", "my file.css"]
        );
    }

    #[test]
    fn reply_serialization_rules() {
        let reply = Reply::new(StatusCode::Ok)
            .header("X-Evil", "a\r\nSet-Cookie: pwned=1")
            .header("Content-Length", "999")
            .header("X-Ok", "fine")
            .body("hello");
        let mut out = Vec::new();
        write_reply(&mut out, reply, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(!text.contains("pwned"));
        assert!(!text.contains("999"));
        assert!(text.contains("X-Ok: fine\r\n"));
        assert!(text.ends_with("5\r\nhello\r\n0\r\n\r\n"));

        let mut out = Vec::new();
        write_reply(&mut out, Reply::new(StatusCode::NoContent).body("x"), false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(text.ends_with("\r\n\r\n") && !text.contains("chunked"));

        let mut out = Vec::new();
        write_reply(&mut out, Reply::new(StatusCode::Ok).body("body"), true).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("body"));
    }
}
