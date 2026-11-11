//! Request-owned temporary data in a [`Region`]: each worker thread owns
//! one region, parses every request it handles into pieces of it, and
//! resets it when the request is done, so the memory of one request is
//! freed at once and the next request reuses the same chunks.
//!
//! A made-up request format keeps the example self-contained; it is not
//! taken from, and says nothing about, any real service.
//!
//!   cargo run --release -p allocatbelt --example region_request

use std::sync::mpsc;

use allocatbelt::{Allocatbelt, Region, RegionError, RegionOptions};

/// This process's allocations go to allocatbelt too; the regions would
/// take their chunks from its heap either way.
#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// A parsed request: every field borrows from the worker's region.
struct Request<'r> {
  method: &'r str,
  path: &'r str,
  headers: &'r [(&'r str, &'r str)],
  body: &'r [u8],
}

/// Parses `raw` ("METHOD PATH\nName: value\n...\n\nbody") into `region`.
fn parse<'r>(region: &'r Region, raw: &str) -> Result<Request<'r>, RegionError> {
  let (head, body) = raw.split_once("\n\n").unwrap_or((raw, ""));
  let mut lines = head.lines();
  let (method, path) = lines
    .next()
    .and_then(|l| l.split_once(' '))
    .unwrap_or(("GET", "/"));
  let mut headers = Vec::new();
  for line in lines {
    if let Some((name, value)) = line.split_once(':') {
      headers.push((
        region.alloc_str(name)? as &str,
        region.alloc_str(value.trim())? as &str,
      ));
    }
  }
  Ok(Request {
    method: region.alloc_str(method)?,
    path: region.alloc_str(path)?,
    headers: region.alloc_slice_copy(&headers)?,
    body: region.alloc_slice_copy(body.as_bytes())?,
  })
}

/// Handles one request with scratch data from `region` only; returns the
/// response line (owned: it leaves the request).
fn handle(region: &Region, raw: &str) -> Result<String, RegionError> {
  let req = parse(region, raw)?;
  // Scratch space for the handler: a histogram of the body's bytes.
  let counts = region.alloc_slice_fill(256, 0u32)?;
  for &b in req.body {
    counts[usize::from(b)] += 1;
  }
  let distinct = counts.iter().filter(|&&c| c > 0).count();
  Ok(format!(
    "{} {}: {} headers, {} body bytes, {} distinct",
    req.method,
    req.path,
    req.headers.len(),
    req.body.len(),
    distinct
  ))
}

fn main() {
  let (results, collected) = mpsc::channel();
  std::thread::scope(|s| {
    for worker in 0..4 {
      let results = results.clone();
      s.spawn(move || {
        // One region per worker, with a limit per request's data.
        let mut region = Region::with_options(
          RegionOptions::new()
            .with_chunk_size(16 << 10)
            .with_retain_bytes(64 << 10)
            .with_limit_bytes(1 << 20),
        );
        for i in 0..250 {
          let raw = format!(
            "POST /items/{worker}/{i}\nHost: example\nX-Try: {i}\n\n{}",
            "payload ".repeat(i % 40)
          );
          // The pieces of this request go when `scope` resets the region.
          let line = region.scope(|r| handle(r, &raw));
          results.send(line).ok();
        }
        results
          .send(Ok(format!("worker {worker}: {:?}", region.stats())))
          .ok();
      });
    }
  });
  drop(results);
  let lines: Vec<Result<String, RegionError>> = collected.iter().collect();
  let failed = lines.iter().filter(|l| l.is_err()).count();
  for line in lines.iter().flatten().filter(|l| l.starts_with("worker")) {
    println!("{line}");
  }
  println!("{} requests, {failed} failed", lines.len() - 4);
  assert_eq!(failed, 0);
}
