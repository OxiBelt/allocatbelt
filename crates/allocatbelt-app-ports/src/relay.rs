//! A single-use, caller-owned TCP relay over charged scratch buffers.
//!
//! `relay_io` is the generic borrowed kernel. [`RelaySession`] adapts two
//! registered TCP streams and two unique [`ManagedBuf`] values to that kernel
//! while holding a single atomic two-endpoint network permit. Dropping a
//! borrowed `run` future keeps the session, its buffers and its last reported
//! progress with the caller. The session is not resumable or restartable:
//! cancellation may have consumed source bytes or completed half-close work.
//!
//! Supplied buffers retain their existing ledger charges. The resource scope
//! passed to [`RelaySession::new`] accounts for the two session endpoints, but
//! does not retroactively move buffer charges into that scope. An output
//! buffer remains charged until its final clone is dropped. This charge tracks
//! retained managed storage, not RSS, socket memory, or arbitrary allocation.

use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::ops::Range;
use std::pin::pin;

use allocatbelt::runtime::io::{AsyncRead, AsyncWrite, copy_bidirectional_with_buffers};
use allocatbelt::runtime::managed::{
  ManagedBuf, OperationPermit, OperationRequest, ResourceError, ResourceScope,
};
use allocatbelt::runtime::net::TcpStream;

/// The last successfully returned poll's transfer counts and scratch suffixes.
///
/// Transfer counts mean bytes accepted by the destination. Each nonempty
/// range identifies initialized bytes read from one source but not yet
/// accepted by its destination. They are not proof that a peer acknowledged
/// data. A panic inside an endpoint poll may mutate endpoint state before the
/// helper regains control, so the last recorded progress cannot recover from
/// such a panic. On a fresh helper invocation, initialize this to
/// [`RelayProgress::default`]; validation errors before the copy starts leave
/// the caller's previous record unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayProgress {
  /// Bytes accepted A-to-B and B-to-A, respectively.
  pub transferred: (u64, u64),
  /// Unwritten source bytes in the A-to-B and B-to-A scratch buffers.
  pub unwritten: (Range<usize>, Range<usize>),
}

impl Default for RelayProgress {
  fn default() -> Self {
    Self {
      transferred: (0, 0),
      unwritten: (0..0, 0..0),
    }
  }
}

/// Copies in both directions using unique, nonempty managed buffers.
///
/// This is an adapter over the runtime's bounded copy state machine; it does
/// not allocate, resize buffers or duplicate the flush, half-close, fairness
/// or partial-write logic. `progress` is refreshed after every normal poll,
/// including a poll returning `Pending` or an error, before this future
/// returns that outcome. Dropping this future preserves the bytes and the
/// supplied progress record, but does not undo bytes already accepted by an
/// endpoint. Inspect retained suffixes explicitly; calling the helper again
/// does not continue the previous copy state.
pub async fn relay_io<A, B>(
  a: &mut A,
  b: &mut B,
  a_to_b: &mut ManagedBuf,
  b_to_a: &mut ManagedBuf,
  progress: &mut RelayProgress,
) -> io::Result<(u64, u64)>
where
  A: AsyncRead + AsyncWrite + Unpin,
  B: AsyncRead + AsyncWrite + Unpin,
{
  validate_buffer(a_to_b)?;
  validate_buffer(b_to_a)?;
  let (Some(a_to_b_slice), Some(b_to_a_slice)) = (a_to_b.get_mut(), b_to_a.get_mut()) else {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "relay scratch buffers must be uniquely owned",
    ));
  };

  let mut copy = pin!(copy_bidirectional_with_buffers(
    a,
    b,
    a_to_b_slice,
    b_to_a_slice,
  ));
  poll_fn(|cx| {
    let result = copy.as_mut().poll(cx);
    progress.transferred = copy.as_ref().transferred();
    progress.unwritten = copy.as_ref().unwritten();
    result
  })
  .await
}

/// Endpoints and caller-owned scratch storage offered to a relay session.
pub struct RelayInputs {
  /// First TCP endpoint.
  pub a: TcpStream,
  /// Second TCP endpoint.
  pub b: TcpStream,
  /// Initialized scratch storage for A-to-B bytes.
  pub a_to_b: ManagedBuf,
  /// Initialized scratch storage for B-to-A bytes.
  pub b_to_a: ManagedBuf,
}

/// The direction of a rejected scratch buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayBufferDirection {
  /// A-to-B scratch buffer.
  AToB,
  /// B-to-A scratch buffer.
  BToA,
}

/// Why relay construction was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum RelayInitErrorKind {
  /// The named scratch buffer has no writable capacity.
  Empty(RelayBufferDirection),
  /// The named scratch buffer has another live clone.
  Shared(RelayBufferDirection),
  /// Atomic admission of both endpoint slots failed.
  Resource(ResourceError),
}

/// A failed constructor that returns every original input unchanged.
pub struct RelayInitError {
  /// Construction refusal reason.
  pub kind: RelayInitErrorKind,
  /// Both original streams and buffers.
  pub inputs: RelayInputs,
}

impl fmt::Debug for RelayInitError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RelayInitError")
      .field("kind", &self.kind)
      .field("inputs", &"<owned inputs retained>")
      .finish()
  }
}

impl fmt::Display for RelayInitError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &self.kind {
      RelayInitErrorKind::Empty(direction) => {
        write!(f, "{direction:?} relay scratch buffer is empty")
      }
      RelayInitErrorKind::Shared(direction) => {
        write!(f, "{direction:?} relay scratch buffer is shared")
      }
      RelayInitErrorKind::Resource(error) => write!(f, "relay resources refused: {error}"),
    }
  }
}

impl std::error::Error for RelayInitError {}

/// A single-use owner of two endpoints, buffers, progress and endpoint charge.
///
/// Endpoint fields precede the permit so ordinary drop closes both sockets
/// before releasing their declared network slots. The scratch buffers are
/// independent caller-supplied storage and keep their original ledger charge.
pub struct RelaySession {
  a: TcpStream,
  b: TcpStream,
  a_to_b: ManagedBuf,
  b_to_a: ManagedBuf,
  progress: RelayProgress,
  started: bool,
  permit: OperationPermit,
}

impl RelaySession {
  /// Validates unique nonempty buffers and atomically admits both endpoints.
  ///
  /// On any refusal, both streams and both original buffer handles are
  /// returned in [`RelayInitError`]. Buffer uniqueness is checked before the
  /// endpoint permit is acquired, and acquisition is all-or-nothing.
  pub fn new(mut inputs: RelayInputs, resources: &ResourceScope) -> Result<Self, RelayInitError> {
    if let Err(kind) = validate_inputs(&mut inputs) {
      return Err(RelayInitError { kind, inputs });
    }
    let permit = match resources.try_acquire(OperationRequest {
      disk: 0,
      network: 2,
    }) {
      Ok(permit) => permit,
      Err(error) => {
        return Err(RelayInitError {
          kind: RelayInitErrorKind::Resource(error),
          inputs,
        });
      }
    };
    let RelayInputs {
      a,
      b,
      a_to_b,
      b_to_a,
    } = inputs;
    Ok(Self {
      a,
      b,
      a_to_b,
      b_to_a,
      progress: RelayProgress::default(),
      started: false,
      permit,
    })
  }

  /// Runs the bidirectional relay once.
  ///
  /// The single-use flag changes on the first poll, not merely when the
  /// future is constructed. After that poll, even cancellation or an I/O
  /// error forbids silent replay. `finish` returns buffers and progress but
  /// closes both endpoints; create another session only with separately
  /// obtained endpoints and an explicit caller decision about retained suffix
  /// bytes.
  pub async fn run(&mut self) -> io::Result<(u64, u64)> {
    if self.started {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "relay session has already been polled",
      ));
    }
    self.started = true;
    relay_io(
      &mut self.a,
      &mut self.b,
      &mut self.a_to_b,
      &mut self.b_to_a,
      &mut self.progress,
    )
    .await
  }

  /// Returns the most recently recorded poll progress.
  #[must_use]
  pub fn progress(&self) -> &RelayProgress {
    &self.progress
  }

  /// Closes both endpoints before releasing their permit, then returns the
  /// original scratch buffers and last progress. Drop the returned buffers
  /// (and all clones) before expecting their memory charges to be released.
  pub fn finish(mut self) -> RelayOutput {
    self.a.cancel_io_waits();
    self.b.cancel_io_waits();
    let RelaySession {
      a,
      b,
      a_to_b,
      b_to_a,
      progress,
      started: _,
      permit,
    } = self;
    drop(a);
    drop(b);
    drop(permit);
    RelayOutput {
      a_to_b,
      b_to_a,
      progress,
    }
  }
}

/// Recovered scratch storage and progress after explicitly finishing a session.
pub struct RelayOutput {
  /// A-to-B scratch buffer; `progress.unwritten.0` identifies pending bytes.
  pub a_to_b: ManagedBuf,
  /// B-to-A scratch buffer; `progress.unwritten.1` identifies pending bytes.
  pub b_to_a: ManagedBuf,
  /// Last progress reported by a normally returned helper poll.
  pub progress: RelayProgress,
}

fn validate_inputs(inputs: &mut RelayInputs) -> Result<(), RelayInitErrorKind> {
  validate_buffer_ref(&mut inputs.a_to_b, RelayBufferDirection::AToB)?;
  validate_buffer_ref(&mut inputs.b_to_a, RelayBufferDirection::BToA)
}

fn validate_buffer_ref(
  buffer: &mut ManagedBuf,
  direction: RelayBufferDirection,
) -> Result<(), RelayInitErrorKind> {
  if buffer.is_empty() {
    return Err(RelayInitErrorKind::Empty(direction));
  }
  if buffer.get_mut().is_none() {
    return Err(RelayInitErrorKind::Shared(direction));
  }
  Ok(())
}

fn validate_buffer(buffer: &mut ManagedBuf) -> io::Result<()> {
  if buffer.is_empty() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "relay scratch buffers must be nonempty",
    ));
  }
  if buffer.get_mut().is_none() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "relay scratch buffers must be uniquely owned",
    ));
  }
  Ok(())
}
