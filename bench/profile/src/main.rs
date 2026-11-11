//! `resource-profile`: runs a command and samples the CPU, memory, disk,
//! network and per-thread use of it and its child processes from `/proc`.
//!
//! ```text
//! resource-profile [--interval-ms N] [--out DIR] [--root-only] [--] COMMAND [ARGS...]
//! ```
//!
//! Writes `samples.csv` (one row per sample), `threads.csv` (per thread),
//! `threads-by-name.csv` (per thread name) and `summary.tsv` to `DIR`
//! (default `resource-profile`), prints the summary to standard error and
//! exits with the command's exit code. See `docs/research/profiling.md`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use allocatbelt_profile::{
  Fds, Io, NetDev, Stat, USER_HZ, ids, read_fds, read_io, read_net_dev, read_stat, read_status,
};

struct Args {
  interval: Duration,
  out: PathBuf,
  root_only: bool,
  command: Vec<String>,
}

const USAGE: &str =
  "usage: resource-profile [--interval-ms N] [--out DIR] [--root-only] [--] COMMAND [ARGS...]";

fn parse_args() -> Result<Args, String> {
  let mut args = Args {
    interval: Duration::from_millis(100),
    out: PathBuf::from("resource-profile"),
    root_only: false,
    command: Vec::new(),
  };
  let mut it = std::env::args().skip(1);
  while let Some(a) = it.next() {
    match a.as_str() {
      "--interval-ms" => {
        let ms: u64 = it
          .next()
          .and_then(|v| v.parse().ok())
          .filter(|&ms| ms > 0)
          .ok_or("--interval-ms needs a positive number")?;
        args.interval = Duration::from_millis(ms);
      }
      "--out" => args.out = it.next().ok_or("--out needs a directory")?.into(),
      "--root-only" => args.root_only = true,
      "-h" | "--help" => return Err(USAGE.to_owned()),
      "--" => {
        args.command.extend(it.by_ref());
      }
      _ => {
        args.command.push(a);
        args.command.extend(it.by_ref());
      }
    }
  }
  if args.command.is_empty() {
    return Err(USAGE.to_owned());
  }
  Ok(args)
}

/// What was last read for one process.
#[derive(Default)]
struct ProcLast {
  stat: Stat,
  io: Io,
}

/// What was last read for one thread.
struct ThreadLast {
  pid: u32,
  tid: u32,
  comm: String,
  utime: u64,
  stime: u64,
  vcs: u64,
  nvcs: u64,
}

/// Counters summed over every process and thread seen so far, exited ones
/// at their last reading, plus the gauges of the processes alive now.
#[derive(Default)]
struct Sample {
  t_s: f64,
  cpu_pct: f64,
  user_ticks: u64,
  sys_ticks: u64,
  rss: u64,
  rss_anon: u64,
  rss_file: u64,
  vm_size: u64,
  root_hwm: u64,
  minflt: u64,
  majflt: u64,
  processes: u64,
  threads: u64,
  vcs: u64,
  nvcs: u64,
  io: Io,
  fds: Fds,
  net: NetDev,
}

const SAMPLE_HEADER: &str = "t_s,cpu_pct,cpu_user_s,cpu_sys_s,rss_kib,rss_anon_kib,rss_file_kib,vm_kib,\
minflt,majflt,processes,threads,ctx_voluntary,ctx_involuntary,rchar,wchar,syscr,syscw,\
read_bytes,write_bytes,fds,sockets,net_rx_bytes,net_tx_bytes,net_rx_packets,net_tx_packets,lo_bytes";

impl Sample {
  fn csv_row(&self) -> String {
    format!(
      "{:.3},{:.1},{:.2},{:.2},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
      self.t_s,
      self.cpu_pct,
      self.user_ticks as f64 / USER_HZ,
      self.sys_ticks as f64 / USER_HZ,
      self.rss,
      self.rss_anon,
      self.rss_file,
      self.vm_size,
      self.minflt,
      self.majflt,
      self.processes,
      self.threads,
      self.vcs,
      self.nvcs,
      self.io.rchar,
      self.io.wchar,
      self.io.syscr,
      self.io.syscw,
      self.io.read_bytes,
      self.io.net_write_bytes(),
      self.fds.open,
      self.fds.sockets,
      self.net.rx_bytes,
      self.net.tx_bytes,
      self.net.rx_packets,
      self.net.tx_packets,
      self.net.lo_bytes,
    )
  }
}

struct Sampler {
  root: u32,
  root_only: bool,
  procs: HashMap<u32, ProcLast>,
  threads: HashMap<(u32, u32), ThreadLast>,
  net_base: NetDev,
}

impl Sampler {
  /// The root and, unless `root_only`, every process descended from it.
  fn tree(&self) -> Vec<u32> {
    if self.root_only {
      return vec![self.root];
    }
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for pid in ids(Path::new("/proc")) {
      if let Some(stat) = read_stat(&proc_dir(pid)) {
        children.entry(stat.ppid).or_default().push(pid);
      }
    }
    let mut seen = HashSet::from([self.root]);
    let mut out = vec![self.root];
    let mut i = 0;
    while i < out.len() {
      for &c in children.get(&out[i]).into_iter().flatten() {
        if seen.insert(c) {
          out.push(c);
        }
      }
      i += 1;
    }
    out
  }

  fn sample(&mut self, t_s: f64) -> Sample {
    let mut s = Sample {
      t_s,
      ..Sample::default()
    };
    for pid in self.tree() {
      let dir = proc_dir(pid);
      let Some(stat) = read_stat(&dir) else {
        continue;
      };
      let status = read_status(&dir).unwrap_or_default();
      let fds = read_fds(&dir).unwrap_or_default();
      s.processes += 1;
      s.threads += stat.threads;
      s.rss += status.vm_rss;
      s.rss_anon += status.rss_anon;
      s.rss_file += status.rss_file;
      s.vm_size += status.vm_size;
      s.fds.open += fds.open;
      s.fds.sockets += fds.sockets;
      if pid == self.root {
        s.root_hwm = status.vm_hwm;
      }
      let last = self.procs.entry(pid).or_default();
      last.stat = stat;
      if let Some(io) = read_io(&dir) {
        last.io = io;
      }
      for tid in ids(&dir.join("task")) {
        let tdir = dir.join("task").join(tid.to_string());
        let Some(tstat) = read_stat(&tdir) else {
          continue;
        };
        let tstatus = read_status(&tdir).unwrap_or_default();
        self.threads.insert(
          (pid, tid),
          ThreadLast {
            pid,
            tid,
            comm: tstat.comm,
            utime: tstat.utime,
            stime: tstat.stime,
            vcs: tstatus.voluntary_ctxt_switches,
            nvcs: tstatus.nonvoluntary_ctxt_switches,
          },
        );
      }
    }
    for p in self.procs.values() {
      s.user_ticks += p.stat.utime;
      s.sys_ticks += p.stat.stime;
      s.minflt += p.stat.minflt;
      s.majflt += p.stat.majflt;
      s.io.rchar += p.io.rchar;
      s.io.wchar += p.io.wchar;
      s.io.syscr += p.io.syscr;
      s.io.syscw += p.io.syscw;
      s.io.read_bytes += p.io.read_bytes;
      s.io.write_bytes += p.io.write_bytes;
      s.io.cancelled_write_bytes += p.io.cancelled_write_bytes;
    }
    for t in self.threads.values() {
      s.vcs += t.vcs;
      s.nvcs += t.nvcs;
    }
    s.net = self_net().since(&self.net_base);
    s
  }
}

fn proc_dir(pid: u32) -> PathBuf {
  PathBuf::from(format!("/proc/{pid}"))
}

/// The profiler shares the command's network namespace unless the command
/// creates its own, and its `net/dev` stays readable after the command exits.
fn self_net() -> NetDev {
  read_net_dev(Path::new("/proc/self")).unwrap_or_default()
}

fn self_stat_io() -> (Stat, Io) {
  let dir = Path::new("/proc/self");
  (
    read_stat(dir).unwrap_or_default(),
    read_io(dir).unwrap_or_default(),
  )
}

fn write_file(dir: &Path, name: &str, body: &str) -> std::io::Result<()> {
  std::fs::write(dir.join(name), body)
}

fn main() -> ExitCode {
  let args = match parse_args() {
    Ok(a) => a,
    Err(msg) => {
      eprintln!("{msg}");
      return ExitCode::from(2);
    }
  };
  if let Err(e) = std::fs::create_dir_all(&args.out) {
    eprintln!(
      "resource-profile: cannot create {}: {e}",
      args.out.display()
    );
    return ExitCode::from(2);
  }

  let (self_stat0, self_io0) = self_stat_io();
  let net_base = self_net();
  let start = Instant::now();
  let mut child = match Command::new(&args.command[0])
    .args(&args.command[1..])
    .spawn()
  {
    Ok(c) => c,
    Err(e) => {
      eprintln!("resource-profile: cannot run {}: {e}", args.command[0]);
      return ExitCode::from(127);
    }
  };
  let mut sampler = Sampler {
    root: child.id(),
    root_only: args.root_only,
    procs: HashMap::new(),
    threads: HashMap::new(),
    net_base,
  };

  let mut csv = String::from(SAMPLE_HEADER);
  csv.push('\n');
  let mut last_ticks = 0u64;
  let mut last_t = 0.0f64;
  let mut peak = Sample::default();
  let mut samples = 0u64;
  let status = loop {
    let t = start.elapsed().as_secs_f64();
    let mut s = sampler.sample(t);
    let ticks = s.user_ticks + s.sys_ticks;
    if t > last_t {
      s.cpu_pct = (ticks.saturating_sub(last_ticks)) as f64 / USER_HZ / (t - last_t) * 100.0;
    }
    (last_ticks, last_t) = (ticks, t);
    peak.cpu_pct = peak.cpu_pct.max(s.cpu_pct);
    peak.rss = peak.rss.max(s.rss);
    peak.root_hwm = peak.root_hwm.max(s.root_hwm);
    peak.threads = peak.threads.max(s.threads);
    peak.processes = peak.processes.max(s.processes);
    peak.fds.open = peak.fds.open.max(s.fds.open);
    peak.fds.sockets = peak.fds.sockets.max(s.fds.sockets);
    let _ = writeln!(csv, "{}", s.csv_row());
    samples += 1;
    match child.try_wait() {
      Ok(Some(status)) => break Some((status, s)),
      Ok(None) => std::thread::sleep(args.interval),
      Err(e) => {
        eprintln!("resource-profile: waiting for the command failed: {e}");
        break None;
      }
    }
  };
  let Some((status, last)) = status else {
    return ExitCode::from(2);
  };
  let wall = start.elapsed().as_secs_f64();

  // The command and the descendants it waited for are now added to the
  // profiler's "children" counters, which are exact where the samples
  // miss what happened after the last one. The profiler's own reads of
  // `/proc` touch no storage, so its `read_bytes` and `write_bytes` deltas
  // are the command's.
  let (self_stat1, self_io1) = self_stat_io();
  let user_s = (self_stat1.cutime.saturating_sub(self_stat0.cutime)) as f64 / USER_HZ;
  let sys_s = (self_stat1.cstime.saturating_sub(self_stat0.cstime)) as f64 / USER_HZ;
  let minflt = self_stat1.cminflt.saturating_sub(self_stat0.cminflt);
  let majflt = self_stat1.cmajflt.saturating_sub(self_stat0.cmajflt);
  let read_bytes = self_io1.read_bytes.saturating_sub(self_io0.read_bytes);
  let write_bytes = self_io1
    .net_write_bytes()
    .saturating_sub(self_io0.net_write_bytes());
  let net = self_net().since(&sampler.net_base);

  let mut threads: Vec<&ThreadLast> = sampler.threads.values().collect();
  threads.sort_by_key(|t| std::cmp::Reverse(t.utime + t.stime));
  let mut tcsv = String::from("pid,tid,comm,cpu_user_s,cpu_sys_s,ctx_voluntary,ctx_involuntary\n");
  let mut by_name: HashMap<&str, (u64, u64, u64, u64, u64)> = HashMap::new();
  for t in &threads {
    let e = by_name.entry(t.comm.as_str()).or_default();
    *e = (
      e.0 + 1,
      e.1 + t.utime,
      e.2 + t.stime,
      e.3 + t.vcs,
      e.4 + t.nvcs,
    );
    let _ = writeln!(
      tcsv,
      "{},{},{},{:.2},{:.2},{},{}",
      t.pid,
      t.tid,
      csv_field(&t.comm),
      t.utime as f64 / USER_HZ,
      t.stime as f64 / USER_HZ,
      t.vcs,
      t.nvcs
    );
  }
  let mut names: Vec<_> = by_name.into_iter().collect();
  names.sort_by_key(|(_, v)| std::cmp::Reverse(v.1 + v.2));
  let mut ncsv = String::from("comm,threads,cpu_user_s,cpu_sys_s,ctx_voluntary,ctx_involuntary\n");
  for (name, (n, u, s, v, nv)) in &names {
    let _ = writeln!(
      ncsv,
      "{},{n},{:.2},{:.2},{v},{nv}",
      csv_field(name),
      *u as f64 / USER_HZ,
      *s as f64 / USER_HZ
    );
  }

  let exit = status.code().map_or_else(
    || format!("signal {}", status.signal().unwrap_or(0)),
    |c| c.to_string(),
  );
  let cpu = user_s + sys_s;
  let mut summary = String::new();
  let mut row = |k: &str, v: String| {
    let _ = writeln!(summary, "{k}\t{v}");
  };
  row("command", args.command.join(" "));
  row("exit", exit);
  row("wall_s", format!("{wall:.3}"));
  row(
    "samples",
    format!("{samples} every {} ms", args.interval.as_millis()),
  );
  row("cpu_user_s", format!("{user_s:.2}"));
  row("cpu_sys_s", format!("{sys_s:.2}"));
  row(
    "cpu_avg_pct",
    format!("{:.1}", if wall > 0.0 { cpu / wall * 100.0 } else { 0.0 }),
  );
  row("cpu_peak_pct_sampled", format!("{:.1}", peak.cpu_pct));
  row("rss_peak_kib_sampled", peak.rss.to_string());
  row("root_vmhwm_kib", peak.root_hwm.to_string());
  row("minflt", minflt.to_string());
  row("majflt", majflt.to_string());
  row("ctx_voluntary_sampled", last.vcs.to_string());
  row("ctx_involuntary_sampled", last.nvcs.to_string());
  row("disk_read_bytes", read_bytes.to_string());
  row("disk_write_bytes", write_bytes.to_string());
  row("io_rchar_sampled", last.io.rchar.to_string());
  row("io_wchar_sampled", last.io.wchar.to_string());
  row("io_syscr_sampled", last.io.syscr.to_string());
  row("io_syscw_sampled", last.io.syscw.to_string());
  row("net_rx_bytes_netns", net.rx_bytes.to_string());
  row("net_tx_bytes_netns", net.tx_bytes.to_string());
  row("net_rx_packets_netns", net.rx_packets.to_string());
  row("net_tx_packets_netns", net.tx_packets.to_string());
  row("net_lo_bytes_netns", net.lo_bytes.to_string());
  row("processes_peak", peak.processes.to_string());
  row("threads_peak", peak.threads.to_string());
  row("threads_seen", sampler.threads.len().to_string());
  row("fds_peak", peak.fds.open.to_string());
  row("sockets_peak", peak.fds.sockets.to_string());

  for (name, body) in [
    ("samples.csv", csv.as_str()),
    ("threads.csv", tcsv.as_str()),
    ("threads-by-name.csv", ncsv.as_str()),
    ("summary.tsv", summary.as_str()),
  ] {
    if let Err(e) = write_file(&args.out, name, body) {
      eprintln!("resource-profile: cannot write {name}: {e}");
    }
  }
  let mut err = std::io::stderr().lock();
  let _ = writeln!(err, "== resource-profile: {}", args.out.display());
  let _ = err.write_all(summary.as_bytes());

  match status.code() {
    Some(c) => ExitCode::from(u8::try_from(c).unwrap_or(1)),
    None => {
      ExitCode::from(128u8.wrapping_add(u8::try_from(status.signal().unwrap_or(0)).unwrap_or(0)))
    }
  }
}

/// Quotes a CSV field when it holds a comma, quote or newline.
fn csv_field(s: &str) -> String {
  if s.contains([',', '"', '\n']) {
    format!("\"{}\"", s.replace('"', "\"\""))
  } else {
    s.to_owned()
  }
}
