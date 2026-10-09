use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream as StdTcpStream};
use std::thread;
use std::time::Duration;

use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::net::TcpStream;
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig};
use allocatbelt_app_ports::memory::pattern_byte;
use allocatbelt_app_ports::relay::{RelayInputs, RelaySession};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  const PAYLOAD_BYTES: usize = 32 * 1024;
  const SCRATCH_BYTES: usize = 4096;
  const PEER_TIMEOUT: Duration = Duration::from_secs(10);

  let left_listener = TcpListener::bind("127.0.0.1:0")?;
  let right_listener = TcpListener::bind("127.0.0.1:0")?;
  let left_address = left_listener.local_addr()?;
  let right_address = right_listener.local_addr()?;
  let left_relay = StdTcpStream::connect(left_address)?;
  let (left_peer, _) = left_listener.accept()?;
  let right_relay = StdTcpStream::connect(right_address)?;
  let (right_peer, _) = right_listener.accept()?;
  drop((left_listener, right_listener));

  left_peer.set_read_timeout(Some(PEER_TIMEOUT))?;
  left_peer.set_write_timeout(Some(PEER_TIMEOUT))?;
  right_peer.set_read_timeout(Some(PEER_TIMEOUT))?;
  right_peer.set_write_timeout(Some(PEER_TIMEOUT))?;

  let sent_left: Vec<u8> = (0..PAYLOAD_BYTES)
    .map(|index| pattern_byte(0x1a2b_3c4d, index))
    .collect();
  let sent_right: Vec<u8> = (0..PAYLOAD_BYTES)
    .map(|index| pattern_byte(0x5e6f_7788, index))
    .collect();
  let expected_left = sent_left.clone();
  let expected_right = sent_right.clone();
  let left_peer_thread = thread::spawn(move || -> std::io::Result<Vec<u8>> {
    let mut peer = left_peer;
    peer.write_all(&sent_left)?;
    peer.shutdown(Shutdown::Write)?;
    let mut received = Vec::new();
    peer.read_to_end(&mut received)?;
    Ok(received)
  });
  let right_peer_thread = thread::spawn(move || -> std::io::Result<Vec<u8>> {
    let mut peer = right_peer;
    let mut received = Vec::new();
    peer.read_to_end(&mut received)?;
    let reply: Vec<u8> = (0..PAYLOAD_BYTES)
      .map(|index| pattern_byte(0x5e6f_7788, index))
      .collect();
    peer.write_all(&reply)?;
    peer.shutdown(Shutdown::Write)?;
    Ok(received)
  });

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 8,
  })?;
  let reactor_handle = reactor.handle();
  let a = TcpStream::from_std(left_relay, &reactor_handle).map_err(|error| error.error)?;
  let b = TcpStream::from_std(right_relay, &reactor_handle).map_err(|error| error.error)?;
  let resources = ResourceScope::new(ResourceLimits {
    // This ledger covers only relay scratch and its two imported endpoints.
    // Blocking setup, peer sockets/threads and payload Vecs are outside it.
    managed_memory: 2 * SCRATCH_BYTES,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 2,
  });
  let inputs = RelayInputs {
    a,
    b,
    a_to_b: resources.try_alloc_zeroed(SCRATCH_BYTES)?,
    b_to_a: resources.try_alloc_zeroed(SCRATCH_BYTES)?,
  };
  let mut session = RelaySession::new(inputs, &resources)?;
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 2,
    max_scopes: 1,
  })?;
  let copied = runtime.block_on(session.run())??;
  let output = session.finish();
  let left_received = left_peer_thread
    .join()
    .map_err(|_| std::io::Error::other("left peer panicked"))??;
  let right_received = right_peer_thread
    .join()
    .map_err(|_| std::io::Error::other("right peer panicked"))??;

  if copied != (PAYLOAD_BYTES as u64, PAYLOAD_BYTES as u64)
    || left_received != expected_right
    || right_received != expected_left
    || output.progress.unwritten != (0..0, 0..0)
  {
    return Err(std::io::Error::other("relay payload or progress mismatch").into());
  }
  drop(output);
  runtime.shutdown(AsyncShutdown::Drain)?;
  let snapshot = resources.snapshot();
  if snapshot.managed_memory != 0 || snapshot.network_ops != 0 {
    return Err(std::io::Error::other("relay retained managed resources").into());
  }
  reactor.shutdown()?;
  println!("relayed_bytes_each_direction={PAYLOAD_BYTES}");
  Ok(())
}
