//! Readers of Linux `/proc` for the resource profiler (`resource-profile`)
//! and the benchmark binaries.
//!
//! Nothing here is linked into the allocator. The readers parse the text
//! the kernel exposes for a process and its threads; a field the kernel does
//! not report (an older kernel, or a process that has exited) reads as zero.
//! See `docs/research/profiling.md` for what each figure covers.

use std::path::Path;

/// Clock ticks per second of the `/proc/<pid>/stat` CPU times.
///
/// The kernel reports these in `USER_HZ`, which is fixed at 100 on every
/// architecture allocatbelt supports (x86_64, aarch64, riscv64), whatever the
/// kernel's own `HZ`.
pub const USER_HZ: f64 = 100.0;

/// Fields of `/proc/<pid>/stat` or `/proc/<pid>/task/<tid>/stat`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stat {
  /// Command or thread name (at most 15 bytes, as the kernel keeps it).
  pub comm: String,
  /// Parent process.
  pub ppid: u32,
  /// Minor page faults (no disk read).
  pub minflt: u64,
  /// Minor page faults of waited-for children.
  pub cminflt: u64,
  /// Major page faults (the page was read from disk).
  pub majflt: u64,
  /// Major page faults of waited-for children.
  pub cmajflt: u64,
  /// User CPU time, in clock ticks.
  pub utime: u64,
  /// System CPU time, in clock ticks.
  pub stime: u64,
  /// User CPU time of waited-for children, in clock ticks.
  pub cutime: u64,
  /// System CPU time of waited-for children, in clock ticks.
  pub cstime: u64,
  /// Threads in the process.
  pub threads: u64,
}

impl Stat {
  /// Parses the one line of a `stat` file.
  pub fn parse(s: &str) -> Option<Self> {
    // The name is in parentheses and may itself contain spaces and
    // parentheses, so the fields start after the last `)`.
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_owned();
    // `f[0]` is field 3 (`state`) of proc(5).
    let f: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
    let n = |field: usize| -> Option<u64> { f.get(field - 3)?.parse().ok() };
    Some(Self {
      comm,
      ppid: u32::try_from(n(4)?).ok()?,
      minflt: n(10)?,
      cminflt: n(11)?,
      majflt: n(12)?,
      cmajflt: n(13)?,
      utime: n(14)?,
      stime: n(15)?,
      cutime: n(16)?,
      cstime: n(17)?,
      threads: n(20)?,
    })
  }

  /// User plus system CPU time, in seconds.
  pub fn cpu_s(&self) -> f64 {
    (self.utime + self.stime) as f64 / USER_HZ
  }
}

/// Fields of `/proc/<pid>/status` (sizes in KiB).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
  /// Resident set size.
  pub vm_rss: u64,
  /// Peak resident set size.
  pub vm_hwm: u64,
  /// Virtual address space, reserved address space included.
  pub vm_size: u64,
  /// Resident anonymous memory (the heap lives here).
  pub rss_anon: u64,
  /// Resident file-backed memory (code, mapped files).
  pub rss_file: u64,
  /// Resident shared memory.
  pub rss_shmem: u64,
  /// Context switches where the thread gave up the CPU (it blocked).
  pub voluntary_ctxt_switches: u64,
  /// Context switches where the scheduler took the CPU away.
  pub nonvoluntary_ctxt_switches: u64,
}

impl Status {
  /// Parses the `key: value` lines of a `status` file.
  pub fn parse(s: &str) -> Self {
    let mut st = Self::default();
    for line in s.lines() {
      let Some((key, rest)) = line.split_once(':') else {
        continue;
      };
      let Some(v) = rest.split_whitespace().next().and_then(|v| v.parse().ok()) else {
        continue;
      };
      match key {
        "VmRSS" => st.vm_rss = v,
        "VmHWM" => st.vm_hwm = v,
        "VmSize" => st.vm_size = v,
        "RssAnon" => st.rss_anon = v,
        "RssFile" => st.rss_file = v,
        "RssShmem" => st.rss_shmem = v,
        "voluntary_ctxt_switches" => st.voluntary_ctxt_switches = v,
        "nonvoluntary_ctxt_switches" => st.nonvoluntary_ctxt_switches = v,
        _ => {}
      }
    }
    st
  }
}

/// Fields of `/proc/<pid>/io` (bytes and calls).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Io {
  /// Bytes passed to `read`-like calls, from any file, socket or pipe.
  pub rchar: u64,
  /// Bytes passed to `write`-like calls, to any file, socket or pipe.
  pub wchar: u64,
  /// `read`-like calls.
  pub syscr: u64,
  /// `write`-like calls.
  pub syscw: u64,
  /// Bytes the process caused to be fetched from storage.
  pub read_bytes: u64,
  /// Bytes the process caused to be sent to storage.
  pub write_bytes: u64,
  /// Bytes of `write_bytes` that were truncated away before reaching storage.
  pub cancelled_write_bytes: u64,
}

impl Io {
  /// Parses the `key: value` lines of an `io` file.
  pub fn parse(s: &str) -> Self {
    let mut io = Self::default();
    for line in s.lines() {
      let Some((key, rest)) = line.split_once(':') else {
        continue;
      };
      let Ok(v) = rest.trim().parse() else {
        continue;
      };
      match key {
        "rchar" => io.rchar = v,
        "wchar" => io.wchar = v,
        "syscr" => io.syscr = v,
        "syscw" => io.syscw = v,
        "read_bytes" => io.read_bytes = v,
        "write_bytes" => io.write_bytes = v,
        "cancelled_write_bytes" => io.cancelled_write_bytes = v,
        _ => {}
      }
    }
    io
  }

  /// Storage bytes written that reached storage.
  pub fn net_write_bytes(&self) -> u64 {
    self.write_bytes.saturating_sub(self.cancelled_write_bytes)
  }
}

/// Totals of `/proc/<pid>/net/dev`.
///
/// The file describes the network namespace, not the process: every process
/// in the namespace adds to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetDev {
  /// Received bytes over every interface but loopback.
  pub rx_bytes: u64,
  /// Received packets over every interface but loopback.
  pub rx_packets: u64,
  /// Sent bytes over every interface but loopback.
  pub tx_bytes: u64,
  /// Sent packets over every interface but loopback.
  pub tx_packets: u64,
  /// Bytes over loopback (counted once, as received).
  pub lo_bytes: u64,
}

impl NetDev {
  /// Parses the table of a `net/dev` file.
  pub fn parse(s: &str) -> Self {
    let mut n = Self::default();
    // Two header lines, then `iface: rx_bytes rx_packets ... (8 receive
    // columns) tx_bytes tx_packets ...`.
    for line in s.lines().skip(2) {
      let Some((iface, rest)) = line.split_once(':') else {
        continue;
      };
      let f: Vec<u64> = rest
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
      if f.len() < 10 {
        continue;
      }
      if iface.trim() == "lo" {
        n.lo_bytes += f[0];
      } else {
        n.rx_bytes += f[0];
        n.rx_packets += f[1];
        n.tx_bytes += f[8];
        n.tx_packets += f[9];
      }
    }
    n
  }

  /// Counters accumulated since `earlier`.
  pub fn since(&self, earlier: &Self) -> Self {
    Self {
      rx_bytes: self.rx_bytes.saturating_sub(earlier.rx_bytes),
      rx_packets: self.rx_packets.saturating_sub(earlier.rx_packets),
      tx_bytes: self.tx_bytes.saturating_sub(earlier.tx_bytes),
      tx_packets: self.tx_packets.saturating_sub(earlier.tx_packets),
      lo_bytes: self.lo_bytes.saturating_sub(earlier.lo_bytes),
    }
  }
}

/// Open file descriptors of a process, and how many of them are sockets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fds {
  /// All open descriptors.
  pub open: u64,
  /// Descriptors that are sockets.
  pub sockets: u64,
}

fn read(path: &Path) -> Option<String> {
  std::fs::read_to_string(path).ok()
}

/// Reads `<dir>/stat`, where `dir` is `/proc/<pid>` or a task directory.
pub fn read_stat(dir: &Path) -> Option<Stat> {
  Stat::parse(&read(&dir.join("stat"))?)
}

/// Reads `<dir>/status`.
pub fn read_status(dir: &Path) -> Option<Status> {
  read(&dir.join("status")).map(|s| Status::parse(&s))
}

/// Reads `<dir>/io`. Needs the same user as the process (or `CAP_SYS_PTRACE`).
pub fn read_io(dir: &Path) -> Option<Io> {
  read(&dir.join("io")).map(|s| Io::parse(&s))
}

/// Reads `<dir>/net/dev`.
pub fn read_net_dev(dir: &Path) -> Option<NetDev> {
  read(&dir.join("net/dev")).map(|s| NetDev::parse(&s))
}

/// Counts `<dir>/fd`.
pub fn read_fds(dir: &Path) -> Option<Fds> {
  let mut fds = Fds::default();
  for entry in std::fs::read_dir(dir.join("fd")).ok()?.flatten() {
    fds.open += 1;
    if std::fs::read_link(entry.path()).is_ok_and(|l| l.to_string_lossy().starts_with("socket:")) {
      fds.sockets += 1;
    }
  }
  Some(fds)
}

/// The numeric entries of a directory: process ids under `/proc`, thread ids
/// under `/proc/<pid>/task`.
pub fn ids(dir: &Path) -> Vec<u32> {
  std::fs::read_dir(dir)
    .map(|d| {
      d.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect()
    })
    .unwrap_or_default()
}

/// Resource use of the calling process so far, for a before and after
/// around one benchmark workload.
///
/// CPU time, page faults and storage bytes cover every thread the process
/// has had, the exited ones included. Context switches are not here: the
/// kernel keeps them per thread and drops them when a thread exits.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Usage {
  /// User CPU time, in seconds.
  pub user_s: f64,
  /// System CPU time, in seconds.
  pub sys_s: f64,
  /// Minor page faults.
  pub minflt: u64,
  /// Major page faults.
  pub majflt: u64,
  /// Bytes read from storage.
  pub read_bytes: u64,
  /// Bytes written to storage.
  pub write_bytes: u64,
}

impl Usage {
  /// Reads the calling process's usage; fields that cannot be read are zero.
  pub fn of_self() -> Self {
    let dir = Path::new("/proc/self");
    let stat = read_stat(dir).unwrap_or_default();
    let io = read_io(dir).unwrap_or_default();
    Self {
      user_s: stat.utime as f64 / USER_HZ,
      sys_s: stat.stime as f64 / USER_HZ,
      minflt: stat.minflt,
      majflt: stat.majflt,
      read_bytes: io.read_bytes,
      write_bytes: io.net_write_bytes(),
    }
  }

  /// Usage accumulated since `earlier`.
  pub fn since(&self, earlier: &Self) -> Self {
    Self {
      user_s: (self.user_s - earlier.user_s).max(0.0),
      sys_s: (self.sys_s - earlier.sys_s).max(0.0),
      minflt: self.minflt.saturating_sub(earlier.minflt),
      majflt: self.majflt.saturating_sub(earlier.majflt),
      read_bytes: self.read_bytes.saturating_sub(earlier.read_bytes),
      write_bytes: self.write_bytes.saturating_sub(earlier.write_bytes),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn stat_with_spaces_and_parentheses_in_the_name() {
    let line =
      "4242 (a (b) c) S 1 4242 4242 0 -1 4194560 120 7 3 1 250 40 2 5 20 0 3 0 9999 1000 200";
    let s = Stat::parse(line).expect("parse");
    assert_eq!(s.comm, "a (b) c");
    assert_eq!(s.ppid, 1);
    assert_eq!((s.minflt, s.cminflt, s.majflt, s.cmajflt), (120, 7, 3, 1));
    assert_eq!((s.utime, s.stime, s.cutime, s.cstime), (250, 40, 2, 5));
    assert_eq!(s.threads, 3);
    assert!((s.cpu_s() - 2.9).abs() < 1e-9);
  }

  #[test]
  fn truncated_stat_is_rejected() {
    assert_eq!(Stat::parse("1 (init) S 0 1"), None);
    assert_eq!(Stat::parse("no parentheses"), None);
  }

  #[test]
  fn status_fields() {
    let s = Status::parse(
      "Name:\tx\nVmHWM:\t  2048 kB\nVmRSS:\t  1024 kB\nVmSize:\t 99999 kB\nRssAnon:\t 600 kB\n\
       RssFile:\t 400 kB\nRssShmem:\t 24 kB\nvoluntary_ctxt_switches:\t5\nnonvoluntary_ctxt_switches:\t2\n",
    );
    assert_eq!(
      s,
      Status {
        vm_rss: 1024,
        vm_hwm: 2048,
        vm_size: 99999,
        rss_anon: 600,
        rss_file: 400,
        rss_shmem: 24,
        voluntary_ctxt_switches: 5,
        nonvoluntary_ctxt_switches: 2,
      }
    );
  }

  #[test]
  fn io_fields() {
    let io = Io::parse(
      "rchar: 10\nwchar: 20\nsyscr: 3\nsyscw: 4\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 4096\n",
    );
    assert_eq!((io.rchar, io.wchar, io.syscr, io.syscw), (10, 20, 3, 4));
    assert_eq!((io.read_bytes, io.write_bytes), (4096, 8192));
    assert_eq!(io.net_write_bytes(), 4096);
  }

  #[test]
  fn net_dev_skips_loopback() {
    let s = "Inter-|   Receive                                                |  Transmit\n \
       face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
       lo:  500 5 0 0 0 0 0 0  500 5 0 0 0 0 0 0\n  \
       eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n  \
       eth1:  100 1 0 0 0 0 0 0  200 2 0 0 0 0 0 0\n";
    let n = NetDev::parse(s);
    assert_eq!(
      n,
      NetDev {
        rx_bytes: 1100,
        rx_packets: 11,
        tx_bytes: 2200,
        tx_packets: 22,
        lo_bytes: 500
      }
    );
    assert_eq!(n.since(&n), NetDev::default());
  }

  #[test]
  fn own_process_is_readable() {
    let dir = Path::new("/proc/self");
    let stat = read_stat(dir).expect("stat");
    assert!(stat.threads >= 1);
    assert!(read_status(dir).expect("status").vm_rss > 0);
    assert!(read_fds(dir).expect("fds").open >= 1);
    assert!(ids(Path::new("/proc/self/task")).contains(&std::process::id()));
    let a = Usage::of_self();
    let b = Usage::of_self();
    assert!(b.since(&a).user_s >= 0.0);
  }
}
