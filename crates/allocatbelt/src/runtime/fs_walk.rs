//! Bounded recursive directory traversal layered on [`super::FsHandle`].

use super::{FsHandle, FsSubmissionError, FsSubmissionErrorKind};
use crate::runtime::job::{CancellationToken, Job};
use crate::runtime::managed::{ManagedBuf, ResourceError, ResourceKind};
use std::ffi::OsStr;
use std::fs::{self, ReadDir};
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

const MAX_WALK_ENTRIES: usize = 1_000_000;
const MAX_WALK_DEPTH: usize = 256;
const MAX_WALK_PATH_BYTES: usize = 1024 * 1024;
const MAX_WALK_INTERNAL_STEPS: usize = 64;

#[cfg(all(test, not(loom)))]
#[path = "fs_walk_tests.rs"]
mod tests;

/// Explicit ceilings for a recursive filesystem walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
  /// Maximum number of emitted paths, including the root.
  pub max_entries: usize,
  /// Maximum emitted path depth. The root is depth zero.
  pub max_depth: usize,
  /// Maximum raw path bytes, including the root and each emitted entry.
  pub max_path_bytes: usize,
}

/// The kind of one emitted path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEntryKind {
  /// A regular file.
  File,
  /// A directory.
  Directory,
  /// A symbolic link. The walk never descends through it.
  Symlink,
  /// Another filesystem object.
  Other,
}

/// One bounded step from a [`TreeWalk`].
#[derive(Debug)]
#[non_exhaustive]
pub enum WalkStep {
  /// One path was written to the beginning of the returned managed buffer.
  Entry {
    /// Number of raw path bytes written.
    path_bytes: usize,
    /// Root is zero; direct children have depth one.
    depth: usize,
    /// Filesystem type, determined without following symbolic links.
    kind: WalkEntryKind,
    /// This entry used the final allowed entry slot. No child directory is
    /// opened after this point; the next call returns `EntryLimitReached`.
    entry_limit_reached: bool,
  },
  /// No entries remain within the configured depth.
  Complete {
    /// True when a directory at the depth ceiling was left unopened. That
    /// subtree may have been empty.
    depth_limited: bool,
  },
  /// The entry ceiling stopped the walk before another directory read.
  EntryLimitReached,
  /// This job reached its internal frame/iterator work ceiling without
  /// producing an entry. Submit the returned cursor again to continue.
  Yielded,
  /// Cancellation was observed before another filesystem call. No output
  /// entry was written by this result; prior frame progress remains in the
  /// returned cursor, which may be submitted again.
  Interrupted,
  /// An error occurred after the iterator advanced. `path_bytes` is present
  /// when the current path was already written to the output buffer. The
  /// cursor is terminal after this result and cannot resume past the error.
  Error {
    /// Number of path bytes written before the error, if known.
    path_bytes: Option<usize>,
    /// The filesystem or path error.
    error: io::Error,
  },
  /// The cursor was already terminal after completion, an entry limit, or an
  /// earlier error.
  Terminated,
}

struct WalkFrame {
  path: PathBuf,
  entries: ReadDir,
  depth: usize,
}

/// A depth-first traversal cursor retaining only its bounded directory stack.
pub struct TreeWalk {
  stack: Vec<WalkFrame>,
  limits: WalkLimits,
  emitted: usize,
  root: PathBuf,
  root_pending: bool,
  depth_limited: bool,
  terminal: bool,
  limit_pending: bool,
}

impl std::fmt::Debug for TreeWalk {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("TreeWalk")
      .field("stack_depth", &self.stack.len())
      .field("limits", &self.limits)
      .field("emitted", &self.emitted)
      .field("terminal", &self.terminal)
      .finish_non_exhaustive()
  }
}

/// One walk result with the cursor and charged output storage returned.
#[derive(Debug)]
pub struct WalkNextOutcome {
  /// Cursor for the next one-entry operation.
  pub walk: TreeWalk,
  /// Caller-owned charged storage containing the path bytes, when a step
  /// reports an entry or a post-advance error with `path_bytes`.
  pub path: ManagedBuf,
  /// One entry, completion, limit, or terminal error.
  pub step: WalkStep,
}

impl FsHandle {
  /// Opens a bounded depth-first traversal rooted at `root`.
  ///
  /// The root is emitted as the first path at depth zero. Each later
  /// [`FsHandle::walk_next`] call emits at most one raw Unix path into a
  /// caller-owned [`ManagedBuf`]. Symbolic links are emitted but never
  /// descended. This uses ordinary path-based filesystem operations and does
  /// not provide descriptor-relative confinement; path replacement races can
  /// change what a later `read_dir` opens. A final root symlink is rejected
  /// even when the supplied path ends in `/`. An earlier path component
  /// (such as `link/.`) can still resolve through a symlink and is outside this
  /// check.
  ///
  /// `max_entries` is capped at 1,000,000, `max_depth` at 256, and
  /// `max_path_bytes` at 1 MiB. A zero entry limit returns a cursor which
  /// immediately reports [`WalkStep::EntryLimitReached`] without inspecting
  /// the filesystem. One `walk_next` performs at most 64 frame/iterator steps,
  /// then returns `Yielded` for caller-driven continuation. The cursor retains
  /// at most `max_depth + 1` directory frames. Terminal error/limit cleanup
  /// may drop that bounded stack in one call. Its logical path lengths and
  /// frame count obey those ceilings, but standard-library allocation
  /// rounding, iterator state, and temporary entry names are not
  /// managed-memory-accounted. Emitted path bytes are written only into the
  /// charged buffer supplied to `walk_next`.
  pub fn walk_dir(
    &self,
    root: PathBuf,
    limits: WalkLimits,
  ) -> Result<Job<io::Result<TreeWalk>>, FsSubmissionError<(PathBuf, WalkLimits)>> {
    self.submit((root, limits), |(root, limits), token| {
      validate_walk_limits(limits)?;
      let root_bytes = root.as_os_str().as_bytes();
      if root_bytes.len() > limits.max_path_bytes {
        return Err(invalid_walk_input("root path exceeds max_path_bytes"));
      }
      let frame_count = limits
        .max_depth
        .checked_add(1)
        .ok_or_else(|| invalid_walk_input("max_depth overflows frame count"))?;
      std::alloc::Layout::array::<WalkFrame>(frame_count)
        .map_err(|_| invalid_walk_input("walk frame capacity is not representable"))?;

      let mut walk = TreeWalk {
        stack: Vec::new(),
        limits,
        emitted: 0,
        root,
        root_pending: limits.max_entries != 0,
        depth_limited: false,
        terminal: false,
        limit_pending: limits.max_entries == 0,
      };
      if limits.max_entries == 0 {
        return Ok(walk);
      }
      walk
        .stack
        .try_reserve_exact(frame_count)
        .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
      if token.is_cancelled() {
        return Err(io::Error::new(
          io::ErrorKind::Interrupted,
          "filesystem traversal cancelled",
        ));
      }
      let metadata = fs::symlink_metadata(root_metadata_path(&walk.root))?;
      if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_walk_input("walk root is not a directory"));
      }
      if token.is_cancelled() {
        return Err(io::Error::new(
          io::ErrorKind::Interrupted,
          "filesystem traversal cancelled",
        ));
      }
      let entries = fs::read_dir(&walk.root)?;
      walk.stack.push(WalkFrame {
        path: walk.root.clone(),
        entries,
        depth: 0,
      });
      Ok(walk)
    })
  }

  /// Emits one path from a recursive walk into caller-owned managed storage.
  ///
  /// `path` must be uniquely owned and at least `max_path_bytes` long; these
  /// conditions are checked before disk admission and rejection returns both
  /// original inputs. Bytes beyond `path_bytes` in an entry result are left
  /// unchanged. Iterator and metadata work is performed on the blocking pool
  /// under one disk permit. Cancellation is checked between filesystem calls;
  /// an in-flight call cannot be preempted.
  pub fn walk_next(
    &self,
    walk: TreeWalk,
    mut path: ManagedBuf,
  ) -> Result<Job<WalkNextOutcome>, FsSubmissionError<(TreeWalk, ManagedBuf)>> {
    if path.get_mut().is_none() {
      return Err(FsSubmissionError {
        kind: FsSubmissionErrorKind::Resource(ResourceError::Shared),
        input: (walk, path),
      });
    }
    if path.len() < walk.limits.max_path_bytes {
      return Err(FsSubmissionError {
        kind: FsSubmissionErrorKind::Resource(ResourceError::Invalid(ResourceKind::Memory)),
        input: (walk, path),
      });
    }
    self.submit((walk, path), |(mut walk, mut path), token| {
      let step = walk_next_step(&mut walk, &mut path, &token);
      WalkNextOutcome { walk, path, step }
    })
  }
}

fn root_metadata_path(root: &Path) -> PathBuf {
  let bytes = root.as_os_str().as_bytes();
  if !bytes.ends_with(b"/") {
    return root.to_path_buf();
  }
  let mut end = bytes.len();
  while end > 1 && bytes[end - 1] == b'/' {
    end -= 1;
  }
  PathBuf::from(OsStr::from_bytes(&bytes[..end]))
}

fn validate_walk_limits(limits: WalkLimits) -> io::Result<()> {
  if limits.max_entries > MAX_WALK_ENTRIES {
    return Err(invalid_walk_input("max_entries exceeds the walk ceiling"));
  }
  if limits.max_depth > MAX_WALK_DEPTH {
    return Err(invalid_walk_input("max_depth exceeds the walk ceiling"));
  }
  if limits.max_path_bytes == 0 || limits.max_path_bytes > MAX_WALK_PATH_BYTES {
    return Err(invalid_walk_input(
      "max_path_bytes is outside the walk ceiling",
    ));
  }
  Ok(())
}

fn invalid_walk_input(message: &'static str) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn walk_next_step(
  walk: &mut TreeWalk,
  path: &mut ManagedBuf,
  token: &CancellationToken,
) -> WalkStep {
  if walk.terminal {
    return WalkStep::Terminated;
  }
  if walk.limit_pending {
    walk.limit_pending = false;
    walk.terminal = true;
    walk.stack.clear();
    return WalkStep::EntryLimitReached;
  }
  if token.is_cancelled() {
    return WalkStep::Interrupted;
  }

  if walk.root_pending {
    let root_bytes = walk.root.as_os_str().as_bytes();
    let Some(output) = path.get_mut() else {
      return fail_walk(
        walk,
        None,
        io::Error::other("managed path buffer became shared"),
      );
    };
    output[..root_bytes.len()].copy_from_slice(root_bytes);
    walk.root_pending = false;
    walk.emitted = 1;
    let entry_limit_reached = walk.emitted == walk.limits.max_entries;
    if entry_limit_reached {
      walk.limit_pending = true;
      walk.stack.clear();
    } else if walk.limits.max_depth == 0 {
      walk.depth_limited = true;
      walk.stack.clear();
    }
    return WalkStep::Entry {
      path_bytes: root_bytes.len(),
      depth: 0,
      kind: WalkEntryKind::Directory,
      entry_limit_reached,
    };
  }

  let mut internal_steps = 0;
  loop {
    if internal_steps == MAX_WALK_INTERNAL_STEPS {
      return WalkStep::Yielded;
    }
    if token.is_cancelled() {
      return WalkStep::Interrupted;
    }
    let Some(frame) = walk.stack.last_mut() else {
      walk.terminal = true;
      return WalkStep::Complete {
        depth_limited: walk.depth_limited,
      };
    };
    if frame.depth >= walk.limits.max_depth {
      walk.depth_limited = true;
      walk.stack.pop();
      internal_steps += 1;
      continue;
    }

    let (parent, parent_depth, next) = {
      let frame = match walk.stack.last_mut() {
        Some(frame) => frame,
        None => unreachable!("walk stack was checked above"),
      };
      (frame.path.clone(), frame.depth, frame.entries.next())
    };
    internal_steps += 1;
    let entry = match next {
      Some(Ok(entry)) => entry,
      Some(Err(error)) => {
        return fail_walk(walk, None, error);
      }
      None => {
        walk.stack.pop();
        continue;
      }
    };
    let file_name = entry.file_name();
    let child_path = match joined_walk_path(&parent, &file_name, walk.limits.max_path_bytes) {
      Ok(path) => path,
      Err(error) => {
        return fail_walk(walk, None, error);
      }
    };
    let child_bytes = child_path.as_os_str().as_bytes();
    let child_len = child_bytes.len();
    let Some(output) = path.get_mut() else {
      return fail_walk(
        walk,
        None,
        io::Error::other("managed path buffer became shared"),
      );
    };
    output[..child_bytes.len()].copy_from_slice(child_bytes);

    if token.is_cancelled() {
      return fail_walk(
        walk,
        Some(child_len),
        io::Error::new(
          io::ErrorKind::Interrupted,
          "filesystem traversal cancelled after reading an entry",
        ),
      );
    }
    let file_type = match entry.file_type() {
      Ok(file_type) => file_type,
      Err(error) => {
        return fail_walk(walk, Some(child_len), error);
      }
    };
    let kind = if file_type.is_symlink() {
      WalkEntryKind::Symlink
    } else if file_type.is_dir() {
      WalkEntryKind::Directory
    } else if file_type.is_file() {
      WalkEntryKind::File
    } else {
      WalkEntryKind::Other
    };
    let child_depth = match parent_depth.checked_add(1) {
      Some(depth) => depth,
      None => {
        return fail_walk(
          walk,
          Some(child_len),
          invalid_walk_input("walk depth overflowed"),
        );
      }
    };
    let next_emitted = match walk.emitted.checked_add(1) {
      Some(count) => count,
      None => {
        return fail_walk(
          walk,
          Some(child_len),
          invalid_walk_input("walk entry count overflowed"),
        );
      }
    };
    walk.emitted = next_emitted;
    let entry_limit_reached = next_emitted == walk.limits.max_entries;
    if entry_limit_reached {
      walk.limit_pending = true;
      walk.stack.clear();
    } else if kind == WalkEntryKind::Directory {
      if child_depth >= walk.limits.max_depth {
        walk.depth_limited = true;
      } else {
        if token.is_cancelled() {
          return fail_walk(
            walk,
            Some(child_len),
            io::Error::new(
              io::ErrorKind::Interrupted,
              "filesystem traversal cancelled before opening a directory",
            ),
          );
        }
        match fs::read_dir(&child_path) {
          Ok(entries) => walk.stack.push(WalkFrame {
            path: child_path,
            entries,
            depth: child_depth,
          }),
          Err(error) => {
            return fail_walk(walk, Some(child_len), error);
          }
        }
      }
    }
    return WalkStep::Entry {
      path_bytes: child_len,
      depth: child_depth,
      kind,
      entry_limit_reached,
    };
  }
}

fn fail_walk(walk: &mut TreeWalk, path_bytes: Option<usize>, error: io::Error) -> WalkStep {
  walk.terminal = true;
  walk.stack.clear();
  WalkStep::Error { path_bytes, error }
}

fn joined_walk_path(parent: &Path, name: &std::ffi::OsStr, ceiling: usize) -> io::Result<PathBuf> {
  let parent_bytes = parent.as_os_str().as_bytes();
  let name_bytes = name.as_bytes();
  let separator = usize::from(!parent_bytes.is_empty() && !parent_bytes.ends_with(b"/"));
  let length = parent_bytes
    .len()
    .checked_add(separator)
    .and_then(|length| length.checked_add(name_bytes.len()))
    .ok_or_else(|| invalid_walk_input("walk path length overflowed"))?;
  if length > ceiling {
    return Err(invalid_walk_input("walk path exceeds max_path_bytes"));
  }
  let mut path = parent.to_path_buf();
  let additional = separator
    .checked_add(name_bytes.len())
    .ok_or_else(|| invalid_walk_input("walk path capacity overflowed"))?;
  path
    .try_reserve(additional)
    .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
  path.push(name);
  debug_assert_eq!(path.as_os_str().as_bytes().len(), length);
  Ok(path)
}
