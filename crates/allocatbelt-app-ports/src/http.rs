//! Bounded HTTP/1.1 checksum exchange over allocatbelt's readiness TCP API.

use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::ops::{Deref, DerefMut};

use allocatbelt::runtime::Handle as BlockingHandle;
use allocatbelt::runtime::asynchronous::{AbortHandle, AsyncJob, AsyncJoinError, OwnedTaskScope};
use allocatbelt::runtime::io::AsyncWriteExt;
use allocatbelt::runtime::managed::{OperationPermit, OperationRequest, ResourceScope};
use allocatbelt::runtime::net::{NetHandle, TcpListener, TcpStream};
use allocatbelt::runtime::reactor::ReactorHandle;

use crate::memory::{checksum, pattern_byte};
use crate::{PortResult, join_message, message};

/// Largest accepted HTTP header block, including its terminator.
pub const MAX_HEADER_BYTES: usize = 512;
/// Largest request body in the functional example.
pub const MAX_BODY_BYTES: usize = 8192;
/// Largest complete request frame.
pub const MAX_REQUEST_BYTES: usize = MAX_HEADER_BYTES + MAX_BODY_BYTES;
const RESPONSE_HEADER: &[u8] =
  b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n";
const REQUEST_PREFIX: &[u8] = b"POST /checksum HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ";
const REQUEST_SUFFIX: &[u8] = b"\r\nConnection: close\r\n\r\n";
const MAX_RESPONSE_BYTES: usize = 128;
const REQUEST_READ_CHUNK: usize = 127;
const RESPONSE_READ_CHUNK: usize = 7;

/// Couples one endpoint with its accounting permit. The stream field is
/// declared first so Rust drops the socket before releasing its permit.
struct NetworkEndpoint {
  stream: TcpStream,
  _permit: OperationPermit,
}

struct AbortOnDrop<T> {
  job: Option<AsyncJob<T>>,
  abort: Option<AbortHandle>,
}

impl<T> AbortOnDrop<T> {
  fn new(job: AsyncJob<T>) -> Self {
    let abort = job.abort_handle();
    Self {
      job: Some(job),
      abort: Some(abort),
    }
  }

  fn abort(&self) {
    if let Some(abort) = &self.abort {
      abort.abort();
    }
  }

  async fn join(&mut self) -> Result<T, AsyncJoinError> {
    let result = match self.job.take() {
      Some(job) => job.await,
      None => return Err(AsyncJoinError::Cancelled),
    };
    self.abort = None;
    result
  }
}

impl<T> Drop for AbortOnDrop<T> {
  fn drop(&mut self) {
    self.abort();
  }
}

impl NetworkEndpoint {
  fn new(stream: TcpStream, permit: OperationPermit) -> Self {
    Self {
      stream,
      _permit: permit,
    }
  }
}

impl Deref for NetworkEndpoint {
  type Target = TcpStream;

  fn deref(&self) -> &Self::Target {
    &self.stream
  }
}

impl DerefMut for NetworkEndpoint {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.stream
  }
}

/// Bounds the one loopback transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpConfig {
  /// Deterministic request body size, at most [`MAX_BODY_BYTES`].
  pub body_bytes: usize,
  /// Payload seed.
  pub seed: u64,
}

impl Default for HttpConfig {
  fn default() -> Self {
    Self {
      body_bytes: 4096,
      seed: 0x1319_8a2e_0370_7344,
    }
  }
}

/// Parses one bounded `POST /checksum` request.
///
/// Returns `Ok(None)` until the complete header and declared body have
/// arrived. Extra bytes, oversized headers/bodies and malformed framing are
/// rejected, so one transaction owns exactly one request.
pub fn parse_request(bytes: &[u8]) -> io::Result<Option<&[u8]>> {
  if bytes.len() > MAX_REQUEST_BYTES {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "HTTP request exceeds its total bound",
    ));
  }
  let header_scan = &bytes[..bytes.len().min(MAX_HEADER_BYTES)];
  let Some(header_end) = find_header_end(header_scan) else {
    if bytes.len() >= MAX_HEADER_BYTES || bytes.len() > MAX_REQUEST_BYTES {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP header exceeds its bound",
      ));
    }
    return Ok(None);
  };
  let header_len = header_end + 4;
  if header_len > MAX_HEADER_BYTES {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "HTTP header exceeds its bound",
    ));
  }
  let header_bytes = &bytes[..header_end];
  if !header_bytes.is_ascii() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "HTTP header contains non-ASCII bytes",
    ));
  }
  let header = std::str::from_utf8(header_bytes)
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP header bytes"))?;
  let mut lines = header.split("\r\n");
  if lines.next() != Some("POST /checksum HTTP/1.1") {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "unsupported HTTP request line",
    ));
  }
  let mut content_length = None;
  for line in lines {
    let (name, value) = line
      .split_once(':')
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP header"))?;
    if name.is_empty() || !name.bytes().all(is_header_token) {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid HTTP header name",
      ));
    }
    if !value
      .bytes()
      .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
    {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid control byte in HTTP header value",
      ));
    }
    if name.eq_ignore_ascii_case("content-length") {
      if content_length.is_some() {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "duplicate Content-Length",
        ));
      }
      let value = value.trim_matches(|character| character == ' ' || character == '\t');
      if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "invalid Content-Length",
        ));
      }
      content_length = Some(value.parse::<usize>().map_err(|_| {
        io::Error::new(
          io::ErrorKind::InvalidData,
          "Content-Length overflows this platform",
        )
      })?);
    }
    if name.eq_ignore_ascii_case("transfer-encoding") {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Transfer-Encoding is outside the bounded port",
      ));
    }
  }
  let body_len = content_length
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length"))?;
  if body_len > MAX_BODY_BYTES {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "HTTP body exceeds its bound",
    ));
  }
  let frame_len = header_len
    .checked_add(body_len)
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP frame length overflow"))?;
  if bytes.len() < frame_len {
    return Ok(None);
  }
  if bytes.len() != frame_len {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "extra bytes after HTTP request",
    ));
  }
  Ok(Some(&bytes[header_len..frame_len]))
}

fn is_header_token(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
    || matches!(
      byte,
      b'!'
        | b'#'
        | b'$'
        | b'%'
        | b'&'
        | b'\''
        | b'*'
        | b'+'
        | b'-'
        | b'.'
        | b'^'
        | b'_'
        | b'`'
        | b'|'
        | b'~'
    )
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
  bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Encodes a bounded deterministic checksum request into caller-owned bytes.
/// Returns the exact frame length or `InvalidInput` when the destination is
/// too small or the requested body exceeds the port limit.
pub fn encode_request(out: &mut [u8], body_bytes: usize, seed: u64) -> io::Result<usize> {
  if body_bytes > MAX_BODY_BYTES {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "HTTP body exceeds its bound",
    ));
  }
  let mut decimal = [0u8; 20];
  let mut value = body_bytes;
  let mut digits = 0;
  loop {
    decimal[digits] = b'0' + (value % 10) as u8;
    digits += 1;
    value /= 10;
    if value == 0 {
      break;
    }
  }
  let header_len = REQUEST_PREFIX.len() + digits + REQUEST_SUFFIX.len();
  let frame_len = header_len + body_bytes;
  if frame_len > out.len() || header_len > MAX_HEADER_BYTES {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "HTTP request buffer is too small",
    ));
  }
  let mut cursor = 0;
  append(out, &mut cursor, REQUEST_PREFIX);
  for digit in decimal[..digits].iter().rev() {
    out[cursor] = *digit;
    cursor += 1;
  }
  append(out, &mut cursor, REQUEST_SUFFIX);
  for index in 0..body_bytes {
    out[cursor + index] = pattern_byte(seed, index);
  }
  Ok(frame_len)
}

fn append(out: &mut [u8], cursor: &mut usize, bytes: &[u8]) {
  let end = *cursor + bytes.len();
  out[*cursor..end].copy_from_slice(bytes);
  *cursor = end;
}

/// Encodes the fixed-size HTTP response body containing a checksum.
pub fn encode_response(checksum: u64, out: &mut [u8]) -> io::Result<usize> {
  let response_len = RESPONSE_HEADER.len() + 16;
  if out.len() < response_len || response_len > MAX_RESPONSE_BYTES {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "HTTP response buffer is too small",
    ));
  }
  out[..RESPONSE_HEADER.len()].copy_from_slice(RESPONSE_HEADER);
  for index in 0..16 {
    let shift = (15 - index) * 4;
    let digit = ((checksum >> shift) & 0xf) as u8;
    out[RESPONSE_HEADER.len() + index] = if digit < 10 {
      b'0' + digit
    } else {
      b'a' + digit - 10
    };
  }
  Ok(response_len)
}

/// Parses the one fixed-length success response, preserving partial reads.
pub fn parse_response(bytes: &[u8]) -> io::Result<Option<u64>> {
  let total_len = RESPONSE_HEADER.len() + 16;
  if bytes.len() < total_len {
    return Ok(None);
  }
  if bytes.len() != total_len || !bytes.starts_with(RESPONSE_HEADER) {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "invalid bounded HTTP response",
    ));
  }
  let mut checksum = 0u64;
  for &digit in &bytes[RESPONSE_HEADER.len()..] {
    let nibble = match digit {
      b'0'..=b'9' => u64::from(digit - b'0'),
      b'a'..=b'f' => u64::from(digit - b'a' + 10),
      _ => {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "invalid checksum response",
        ));
      }
    };
    checksum = (checksum << 4) | nibble;
  }
  Ok(Some(checksum))
}

/// Accepts and services one connection. This reusable handler contains no
/// listener/runtime setup, so a paced server can invoke it repeatedly.
pub async fn serve_connection(stream: TcpStream, resources: ResourceScope) -> PortResult<u64> {
  let network = resources.try_acquire(OperationRequest {
    disk: 0,
    network: 1,
  })?;
  let mut endpoint = NetworkEndpoint::new(stream, network);
  // Keep reads deliberately small so the normal transaction exercises
  // incremental parsing even when the kernel coalesces client writes.
  let mut request = resources.try_alloc_zeroed(MAX_REQUEST_BYTES)?;
  let mut used = 0usize;
  let body_checksum = loop {
    let Some(storage) = request.get_mut() else {
      return Err(message("HTTP request buffer is unexpectedly shared").into());
    };
    let read_end = used.saturating_add(REQUEST_READ_CHUNK).min(storage.len());
    let count = endpoint
      .read(&mut storage[used..read_end])
      .await
      .map_err(|error| message(format!("HTTP server read: {error}")))?;
    if count == 0 {
      return Err(message("connection closed before a complete HTTP request").into());
    }
    used += count;
    if let Some(body) = parse_request(&request.as_slice()[..used])? {
      break checksum(body);
    }
    if used == MAX_REQUEST_BYTES {
      return Err(message("HTTP request filled its buffer without completing").into());
    }
  };
  let mut response = resources.try_alloc_zeroed(MAX_RESPONSE_BYTES)?;
  let response_len = encode_response(
    body_checksum,
    response
      .get_mut()
      .ok_or_else(|| message("HTTP response buffer is unexpectedly shared"))?,
  )?;
  endpoint
    .write_all(&response.as_slice()[..response_len])
    .await
    .map_err(|error| message(format!("HTTP server response write: {error}")))?;
  endpoint
    .shutdown()
    .await
    .map_err(|error| message(format!("HTTP server shutdown: {error}")))?;
  drop(response);
  drop(request);
  Ok(body_checksum)
}

/// Runs one real loopback HTTP transaction through allocatbelt readiness I/O.
/// Socket listeners, handles and the reactor remain caller-owned; only this
/// request/connection is created here.
pub async fn loopback_transaction(
  scope: &OwnedTaskScope,
  blocking: BlockingHandle,
  reactor: ReactorHandle,
  resources: ResourceScope,
  config: HttpConfig,
) -> PortResult<u64> {
  if config.body_bytes > MAX_BODY_BYTES {
    return Err(message("HTTP config exceeds its body bound").into());
  }
  let listener = StdTcpListener::bind(("127.0.0.1", 0))?;
  let address = listener.local_addr()?;
  let listener = TcpListener::from_std(listener, &reactor)?;
  let server_resources = resources.clone();
  let server = scope
    .spawn(async move {
      let (stream, _) = listener.accept().await.map_err(join_message)?;
      serve_connection(stream, server_resources).await
    })
    .map_err(|error| join_message(error.kind))?;
  let mut server = AbortOnDrop::new(server);
  let client_result = transact_client(blocking, reactor, resources.clone(), address, config).await;
  match client_result {
    Ok(client_checksum) => {
      let server_checksum = server
        .join()
        .await
        .map_err(|error: AsyncJoinError| join_message(error))??;
      if client_checksum != server_checksum {
        return Err(message("client/server HTTP checksums differ").into());
      }
      Ok(client_checksum)
    }
    Err(error) => {
      server.abort();
      match server.join().await {
        Ok(Err(server_error)) => {
          Err(message(format!("{}; HTTP server failed: {server_error}", error)).into())
        }
        Err(server_error) => Err(
          message(format!(
            "{}; HTTP server task failed: {server_error}",
            error
          ))
          .into(),
        ),
        Ok(Ok(_)) => Err(error),
      }
    }
  }
}

async fn transact_client(
  blocking: BlockingHandle,
  reactor: ReactorHandle,
  resources: ResourceScope,
  address: SocketAddr,
  config: HttpConfig,
) -> PortResult<u64> {
  let net = NetHandle::new(blocking, resources.clone(), reactor, 1)?;
  // NetHandle uses a bounded blocking-pool connect, then registers the stream
  // with the same reactor used by the accepting side.
  let stream = net
    .connect(address)
    .await
    .map_err(|error| message(error.to_string()))?;
  let network: OperationPermit = resources.try_acquire(OperationRequest {
    disk: 0,
    network: 1,
  })?;
  let mut endpoint = NetworkEndpoint::new(stream, network);
  let request_capacity = REQUEST_PREFIX.len() + 20 + REQUEST_SUFFIX.len() + config.body_bytes;
  let mut request = resources.try_alloc_zeroed(request_capacity)?;
  let request_len = encode_request(
    request
      .get_mut()
      .ok_or_else(|| message("HTTP request buffer is shared"))?,
    config.body_bytes,
    config.seed,
  )?;
  // Two writes exercise request framing across calls; the server's parser is
  // also tested with bytewise feeds so syscall coalescing cannot hide splits.
  let split = (REQUEST_PREFIX.len() + 24).min(request_len);
  endpoint
    .write_all(&request.as_slice()[..split])
    .await
    .map_err(|error| message(format!("HTTP client request prefix write: {error}")))?;
  endpoint
    .write_all(&request.as_slice()[split..request_len])
    .await
    .map_err(|error| message(format!("HTTP client request suffix write: {error}")))?;
  let mut response = resources.try_alloc_zeroed(MAX_RESPONSE_BYTES)?;
  let mut used = 0usize;
  loop {
    let Some(storage) = response.get_mut() else {
      return Err(message("HTTP response buffer is unexpectedly shared").into());
    };
    let read_end = used.saturating_add(RESPONSE_READ_CHUNK).min(storage.len());
    let count = endpoint
      .read(&mut storage[used..read_end])
      .await
      .map_err(|error| message(format!("HTTP client response read: {error}")))?;
    if count == 0 {
      return Err(message("server closed before a complete HTTP response").into());
    }
    used += count;
    if let Some(result) = parse_response(&response.as_slice()[..used])? {
      drop(response);
      drop(request);
      return Ok(result);
    }
    if used == MAX_RESPONSE_BYTES {
      return Err(message("HTTP response filled its buffer without completing").into());
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{
    MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_REQUEST_BYTES, RESPONSE_READ_CHUNK, encode_request,
    encode_response, parse_request, parse_response,
  };
  use crate::memory::{checksum, pattern_byte};

  #[test]
  fn incremental_parser_accepts_every_fragment_boundary() {
    let body_len = 37;
    let mut frame = vec![0; MAX_HEADER_BYTES + body_len];
    let frame_len = encode_request(&mut frame, body_len, 9).unwrap();
    let expected = checksum(
      &(0..body_len)
        .map(|index| pattern_byte(9, index))
        .collect::<Vec<_>>(),
    );
    for split in 0..=frame_len {
      if split < frame_len {
        assert!(parse_request(&frame[..split]).unwrap().is_none());
      }
    }
    let full_frame = &frame[..frame_len];
    assert_eq!(
      checksum(parse_request(full_frame).unwrap().unwrap()),
      expected
    );
  }

  #[test]
  fn parser_rejects_oversized_body_duplicate_length_and_trailing_bytes() {
    let mut oversized = vec![0; MAX_HEADER_BYTES];
    let header = format!(
      "POST /checksum HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
      MAX_BODY_BYTES + 1
    );
    oversized[..header.len()].copy_from_slice(header.as_bytes());
    assert!(parse_request(&oversized[..header.len()]).is_err());

    let duplicate = b"POST /checksum HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
    assert!(parse_request(duplicate).is_err());

    let mut frame = vec![0; MAX_REQUEST_BYTES];
    let len = encode_request(&mut frame, 0, 1).unwrap();
    frame[len] = b'x';
    assert!(parse_request(&frame[..len + 1]).is_err());
  }

  #[test]
  fn parser_accepts_exact_header_and_body_limits_and_rejects_overlong_headers() {
    let prefix = b"POST /checksum HTTP/1.1\r\nContent-Length: 0\r\nX-Fill: ";
    let suffix = b"\r\n\r\n";
    let fill = MAX_HEADER_BYTES - prefix.len() - suffix.len();
    let mut exact_header = prefix.to_vec();
    exact_header.extend(std::iter::repeat_n(b'a', fill));
    exact_header.extend_from_slice(suffix);
    assert_eq!(exact_header.len(), MAX_HEADER_BYTES);
    assert_eq!(parse_request(&exact_header).unwrap(), Some(&b""[..]));

    let mut overlong_header = prefix.to_vec();
    overlong_header.extend(std::iter::repeat_n(b'a', fill + 1));
    overlong_header.extend_from_slice(suffix);
    assert!(parse_request(&overlong_header).is_err());

    let mut exact_body = vec![0; MAX_REQUEST_BYTES];
    let frame_len = encode_request(&mut exact_body, MAX_BODY_BYTES, 8).unwrap();
    assert!(frame_len <= MAX_REQUEST_BYTES);
    assert_eq!(
      parse_request(&exact_body[..frame_len])
        .unwrap()
        .map(<[u8]>::len),
      Some(MAX_BODY_BYTES)
    );
  }

  #[test]
  fn parser_rejects_invalid_names_controls_and_content_length_syntax() {
    for request in [
      &b"POST /checksum HTTP/1.1\r\nBad Name: v\r\nContent-Length: 0\r\n\r\n"[..],
      &b"POST /checksum HTTP/1.1\r\nX: nul\0byte\r\nContent-Length: 0\r\n\r\n"[..],
      &b"POST /checksum HTTP/1.1\r\nX: vertical\x0btab\r\nContent-Length: 0\r\n\r\n"[..],
      &b"POST /checksum HTTP/1.1\r\nContent-Length: \x0b0\r\n\r\n"[..],
      &b"POST /checksum HTTP/1.1\r\nContent-Length: 184467440737095516160\r\n\r\n"[..],
    ] {
      assert!(parse_request(request).is_err(), "accepted {request:?}");
    }

    let valid_ows = b"POST /checksum HTTP/1.1\r\nContent-Length:\t0 \t\r\n\r\n";
    assert_eq!(parse_request(valid_ows).unwrap(), Some(&b""[..]));
  }

  #[test]
  fn oversized_input_is_rejected_before_header_search() {
    let input = vec![b'x'; MAX_REQUEST_BYTES + 1];
    assert!(parse_request(&input).is_err());
  }

  #[test]
  fn response_parser_keeps_partial_progress_and_checksum() {
    let mut response = [0; super::MAX_RESPONSE_BYTES];
    let len = encode_response(0xfedc_ba98_7654_3210, &mut response).unwrap();
    for split in 0..len {
      assert_eq!(parse_response(&response[..split]).unwrap(), None);
    }
    assert_eq!(
      parse_response(&response[..len]).unwrap(),
      Some(0xfedc_ba98_7654_3210)
    );
  }

  #[test]
  fn bounded_response_reads_require_multiple_parser_steps() {
    let mut response = [0; super::MAX_RESPONSE_BYTES];
    let len = encode_response(0x1234, &mut response).unwrap();
    assert!(len > RESPONSE_READ_CHUNK);
    let mut received = Vec::with_capacity(len);
    let mut fragments = 0;
    for fragment in response[..len].chunks(RESPONSE_READ_CHUNK) {
      received.extend_from_slice(fragment);
      fragments += 1;
      let parsed = parse_response(&received).unwrap();
      if fragments < len.div_ceil(RESPONSE_READ_CHUNK) {
        assert_eq!(parsed, None);
      } else {
        assert_eq!(parsed, Some(0x1234));
      }
    }
    assert!(fragments > 1);
  }
}
