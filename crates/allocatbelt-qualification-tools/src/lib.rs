//! Deterministic, bounded-memory analysis for paired application traces.
//!
//! The wire format is deliberately small and versioned. The Python
//! orchestrator validates manifests and raw rows; this crate validates the
//! compact trace stream, computes exact block-resampled p99 endpoints, and
//! returns simultaneous intervals without expanding resampled traces.

use std::io::{Read, Write};
use std::mem::size_of;

const INPUT_MAGIC: &[u8; 8] = b"ABQST01\0";
const OUTPUT_MAGIC: &[u8; 8] = b"ABQSO01\0";
const MAX_FRAME_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_RESIDENT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DRAWS: u32 = 50_000;
const MAX_PAIRS: u16 = 36;
const MAX_GROUPS: u16 = 512;
const MAX_ENDPOINTS: u16 = 1024;
const MAX_GROUPS_BLOCKS: u32 = 10_000;
const MAX_BLOCK_VALUES: u32 = 1000;
const FRAME_HEADER: u8 = 1;
const FRAME_ENDPOINT: u8 = 2;
const FRAME_SUITE: u8 = 3;
const FRAME_GROUP: u8 = 4;
const FRAME_END: u8 = 5;

#[derive(Debug)]
struct Input<R> {
  reader: R,
  consumed: u64,
  maximum: u64,
}

impl<R: Read> Input<R> {
  fn new(reader: R) -> Self {
    Self {
      reader,
      consumed: 0,
      maximum: MAX_INPUT_BYTES,
    }
  }

  fn exact(&mut self, buffer: &mut [u8]) -> Result<(), String> {
    let next = self
      .consumed
      .checked_add(buffer.len() as u64)
      .ok_or_else(|| "input byte counter overflow".to_owned())?;
    if next > self.maximum {
      return Err("analysis input exceeds its finite byte budget".into());
    }
    self
      .reader
      .read_exact(buffer)
      .map_err(|error| format!("truncated analysis input: {error}"))?;
    self.consumed = next;
    Ok(())
  }

  fn u64(&mut self) -> Result<u64, String> {
    let mut value = [0; 8];
    self.exact(&mut value)?;
    Ok(u64::from_le_bytes(value))
  }

  fn frame(&mut self) -> Result<Frame<'_, R>, String> {
    let length = self.u64()?;
    if length == 0 || length > MAX_FRAME_BYTES {
      return Err("analysis frame length is outside its finite bound".into());
    }
    Ok(Frame {
      input: self,
      remaining: length,
    })
  }
}

struct Frame<'a, R> {
  input: &'a mut Input<R>,
  remaining: u64,
}

impl<R: Read> Frame<'_, R> {
  fn exact(&mut self, buffer: &mut [u8]) -> Result<(), String> {
    if buffer.len() as u64 > self.remaining {
      return Err("analysis frame is shorter than its declared fields".into());
    }
    self.input.exact(buffer)?;
    self.remaining -= buffer.len() as u64;
    Ok(())
  }

  fn u8(&mut self) -> Result<u8, String> {
    let mut value = [0; 1];
    self.exact(&mut value)?;
    Ok(value[0])
  }

  fn u16(&mut self) -> Result<u16, String> {
    let mut value = [0; 2];
    self.exact(&mut value)?;
    Ok(u16::from_le_bytes(value))
  }

  fn u32(&mut self) -> Result<u32, String> {
    let mut value = [0; 4];
    self.exact(&mut value)?;
    Ok(u32::from_le_bytes(value))
  }

  fn u64(&mut self) -> Result<u64, String> {
    let mut value = [0; 8];
    self.exact(&mut value)?;
    Ok(u64::from_le_bytes(value))
  }

  fn f64(&mut self) -> Result<f64, String> {
    let value = f64::from_bits(self.u64()?);
    if !value.is_finite() {
      return Err("analysis input contains a non-finite float".into());
    }
    Ok(value)
  }

  fn string(&mut self, maximum: u16) -> Result<String, String> {
    let length = self.u16()?;
    if length == 0 || length > maximum {
      return Err("analysis string length is outside its finite bound".into());
    }
    let mut bytes = Vec::new();
    bytes
      .try_reserve_exact(length as usize)
      .map_err(|_| "could not reserve bounded analysis string".to_owned())?;
    bytes.resize(length as usize, 0);
    self.exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| "analysis string is not UTF-8".to_owned())
  }

  fn finish(self) -> Result<(), String> {
    if self.remaining != 0 {
      return Err("analysis frame contains trailing or unknown fields".into());
    }
    Ok(())
  }
}

#[derive(Clone, Copy, Debug)]
struct Budget {
  limit: u64,
  used: u64,
  peak: u64,
}

impl Budget {
  fn add(&mut self, bytes: usize) -> Result<(), String> {
    self.used = self
      .used
      .checked_add(bytes as u64)
      .ok_or_else(|| "analysis resident-byte counter overflow".to_owned())?;
    if self.used > self.limit {
      return Err("analysis exceeds its declared resident-memory budget".into());
    }
    self.peak = self.peak.max(self.used);
    Ok(())
  }

  fn vector<T>(&mut self, vector: &Vec<T>) -> Result<(), String> {
    let bytes = vector
      .capacity()
      .checked_mul(size_of::<T>())
      .ok_or_else(|| "analysis vector capacity overflow".to_owned())?;
    self.add(bytes)
  }
}

fn reserved<T>(capacity: usize) -> Result<Vec<T>, String> {
  let mut vector = Vec::new();
  vector
    .try_reserve_exact(capacity)
    .map_err(|_| "could not reserve bounded analysis vector".to_owned())?;
  Ok(vector)
}

#[derive(Clone, Debug)]
struct Endpoint {
  id: u16,
  name: String,
  group: u16,
  family: Option<String>,
  observed_candidate: Vec<u64>,
  observed_control: Vec<u64>,
  log_ratios: Vec<f64>,
}

#[derive(Clone, Debug)]
struct Component {
  index: u16,
  numerator: u32,
  denominator: u32,
}

#[derive(Clone, Debug)]
struct Suite {
  id: u16,
  name: String,
  components: Vec<Component>,
}

#[derive(Clone, Debug)]
struct Block {
  values: Vec<u64>,
  counts: Vec<u32>,
  successes: u64,
}

#[derive(Clone, Debug)]
struct Trace {
  blocks: Vec<Block>,
  values_descending: Vec<GlobalValue>,
  successes: u64,
  regular_block_successes: u64,
  final_block_delta: i64,
}

#[derive(Clone, Copy, Debug)]
struct GlobalValue {
  latency: u64,
  block: u32,
  frequency: u32,
}

#[derive(Clone, Debug)]
struct FamilyPair {
  candidate: Trace,
  control: Trace,
}

#[derive(Clone, Debug)]
struct PairSlot {
  families: Vec<FamilyPair>,
}

#[derive(Clone, Debug)]
struct Group {
  id: u16,
  name: String,
  families: Vec<String>,
  slots: Vec<PairSlot>,
}

#[derive(Debug)]
struct Header {
  draws: u32,
  pairs: u16,
  groups: u16,
  endpoints: u16,
  suites: u16,
  seed: u64,
  confidence: f64,
  block_size: u32,
  input_budget: u64,
  resident_budget: u64,
}

fn read_header<R: Read>(input: &mut Input<R>) -> Result<Header, String> {
  let frame = input.frame()?;
  let mut frame = frame;
  if frame.u8()? != FRAME_HEADER {
    return Err("first analyzer frame is not the header".into());
  }
  let draws = frame.u32()?;
  let pairs = frame.u16()?;
  let groups = frame.u16()?;
  let endpoints = frame.u16()?;
  let suites = frame.u16()?;
  let seed = frame.u64()?;
  let confidence = frame.f64()?;
  let block_size = frame.u32()?;
  let input_budget = frame.u64()?;
  let resident_budget = frame.u64()?;
  frame.finish()?;
  if !(1..=MAX_DRAWS).contains(&draws)
    || !(1..=MAX_PAIRS).contains(&pairs)
    || !(1..=MAX_GROUPS).contains(&groups)
    || endpoints == 0
    || endpoints > MAX_ENDPOINTS
    || suites > MAX_ENDPOINTS
    || !(confidence > 0.0 && confidence < 1.0)
    || block_size == 0
    || block_size > MAX_BLOCK_VALUES
    || input_budget == 0
    || input_budget > MAX_INPUT_BYTES
    || resident_budget == 0
    || resident_budget > MAX_RESIDENT_BYTES
  {
    return Err("analysis header exceeds a frozen finite bound".into());
  }
  Ok(Header {
    draws,
    pairs,
    groups,
    endpoints,
    suites,
    seed,
    confidence,
    block_size,
    input_budget,
    resident_budget,
  })
}

fn read_endpoint<R: Read>(
  frame: &mut Frame<'_, R>,
  id: u16,
  header: &Header,
  budget: &mut Budget,
) -> Result<Endpoint, String> {
  let kind = frame.u8()?;
  let group = frame.u16()?;
  if group >= header.groups {
    return Err("endpoint references an unknown independent pair group".into());
  }
  let name = frame.string(256)?;
  budget.add(name.capacity())?;
  let family = match kind {
    0 => None,
    1 => Some(frame.string(16)?),
    _ => return Err("unknown primary endpoint kind".into()),
  };
  if let Some(family) = &family {
    budget.add(family.capacity())?;
  }
  let mut observed_candidate = Vec::new();
  let mut observed_control = Vec::new();
  let mut log_ratios = Vec::new();
  if family.is_some() {
    observed_candidate = reserved(header.pairs as usize)?;
    observed_control = reserved(header.pairs as usize)?;
    for _ in 0..header.pairs {
      let candidate = frame.u64()?;
      let control = frame.u64()?;
      if candidate == 0 || control == 0 {
        return Err("p99 endpoint has a zero observed percentile".into());
      }
      observed_candidate.push(candidate);
      observed_control.push(control);
    }
  } else {
    log_ratios = reserved(header.pairs as usize)?;
    for _ in 0..header.pairs {
      let ratio = frame.f64()?;
      if ratio <= 0.0 {
        return Err("counter endpoint contains a zero or negative ratio".into());
      }
      log_ratios.push(ratio.ln());
    }
  }
  Ok(Endpoint {
    id,
    name,
    group,
    family,
    observed_candidate,
    observed_control,
    log_ratios,
  })
}

fn read_suite<R: Read>(
  frame: &mut Frame<'_, R>,
  id: u16,
  primary_count: u16,
  budget: &mut Budget,
) -> Result<Suite, String> {
  let name = frame.string(256)?;
  budget.add(name.capacity())?;
  let count = frame.u16()?;
  if count == 0 || count > primary_count {
    return Err("suite component count is outside its finite bound".into());
  }
  let mut components = reserved(count as usize)?;
  budget.vector(&components)?;
  let mut weight_sum = 0.0;
  for _ in 0..count {
    let index = frame.u16()?;
    let numerator = frame.u32()?;
    let denominator = frame.u32()?;
    if index >= primary_count || numerator == 0 || denominator == 0 {
      return Err("suite component reference or rational weight is invalid".into());
    }
    weight_sum += f64::from(numerator) / f64::from(denominator);
    components.push(Component {
      index,
      numerator,
      denominator,
    });
  }
  if (weight_sum - 1.0).abs() > 1e-12 {
    return Err("suite component rational weights do not sum to one".into());
  }
  Ok(Suite {
    id,
    name,
    components,
  })
}

fn read_block<R: Read>(
  frame: &mut Frame<'_, R>,
  block_size: u32,
  budget: &mut Budget,
) -> Result<Block, String> {
  let successes = u64::from(frame.u32()?);
  let unique = frame.u32()?;
  if successes > u64::from(block_size) || unique > block_size || (successes == 0) != (unique == 0) {
    return Err("block cardinality is inconsistent with its frozen size".into());
  }
  let mut values = reserved(unique as usize)?;
  let mut counts = reserved(unique as usize)?;
  budget.vector(&values)?;
  budget.vector(&counts)?;
  let mut count_sum = 0u64;
  let mut previous = None;
  for _ in 0..unique {
    let value = frame.u64()?;
    let count = frame.u32()?;
    if count == 0 || previous.is_some_and(|prior| prior <= value) {
      return Err("block values are not unique, positive-count, descending entries".into());
    }
    previous = Some(value);
    count_sum = count_sum
      .checked_add(u64::from(count))
      .ok_or_else(|| "block frequency count overflow".to_owned())?;
    values.push(value);
    counts.push(count);
  }
  if count_sum != successes {
    return Err("block value frequencies do not reconcile to its successful IDs".into());
  }
  Ok(Block {
    values,
    counts,
    successes,
  })
}

fn read_trace<R: Read>(
  frame: &mut Frame<'_, R>,
  pairs: u16,
  block_size: u32,
  budget: &mut Budget,
) -> Result<Trace, String> {
  let block_count = frame.u32()?;
  if block_count == 0 || block_count > MAX_GROUPS_BLOCKS {
    return Err("trace block count is outside its finite bound".into());
  }
  let mut blocks = reserved(block_count as usize)?;
  budget.vector(&blocks)?;
  let mut total = 0u64;
  for _ in 0..block_count {
    let block = read_block(frame, block_size, budget)?;
    total = total
      .checked_add(block.successes)
      .ok_or_else(|| "trace success count overflow".to_owned())?;
    blocks.push(block);
  }
  if total == 0 || total > 1_000_000 {
    return Err("trace has no successful IDs or exceeds the frozen one-million bound".into());
  }
  let regular = blocks[0].successes;
  if blocks[..blocks.len().saturating_sub(1)]
    .iter()
    .any(|block| block.successes != regular)
    || blocks.last().is_some_and(|block| block.successes > regular)
  {
    return Err(
      "trace blocks must have the frozen full-block cardinality and one final partial block".into(),
    );
  }
  let final_successes = blocks.last().map_or(0, |block| block.successes);
  let final_delta = i64::try_from(final_successes)
    .ok()
    .and_then(|last| {
      i64::try_from(regular)
        .ok()
        .and_then(|base| last.checked_sub(base))
    })
    .ok_or_else(|| "trace final-block cardinality delta overflow".to_owned())?;
  let unique_count = blocks.iter().try_fold(0usize, |sum, block| {
    sum
      .checked_add(block.values.len())
      .ok_or_else(|| "trace unique-latency count overflow".to_owned())
  })?;
  let mut values_descending = reserved(unique_count)?;
  budget.vector(&values_descending)?;
  for (block_id, block) in blocks.iter().enumerate() {
    let block_id = u32::try_from(block_id).map_err(|_| "trace block ID exceeds its wire bound")?;
    for (&latency, &frequency) in block.values.iter().zip(&block.counts) {
      values_descending.push(GlobalValue {
        latency,
        block: block_id,
        frequency,
      });
    }
  }
  values_descending.sort_unstable_by(|left, right| {
    right
      .latency
      .cmp(&left.latency)
      .then_with(|| left.block.cmp(&right.block))
  });
  // The flattened compact index replaces the per-block value/count arrays.
  // Keep only per-block success cardinalities for exact weighted ranks.
  let freed_raw_bytes = blocks.iter().try_fold(0usize, |sum, block| {
    let values = block
      .values
      .capacity()
      .checked_mul(size_of::<u64>())
      .ok_or_else(|| "trace latency-array capacity overflow".to_owned())?;
    let counts = block
      .counts
      .capacity()
      .checked_mul(size_of::<u32>())
      .ok_or_else(|| "trace frequency-array capacity overflow".to_owned())?;
    sum
      .checked_add(values)
      .and_then(|total| total.checked_add(counts))
      .ok_or_else(|| "trace raw-array capacity overflow".to_owned())
  })?;
  for block in &mut blocks {
    block.values = Vec::new();
    block.counts = Vec::new();
  }
  budget.used = budget
    .used
    .checked_sub(freed_raw_bytes as u64)
    .ok_or_else(|| "trace resident accounting underflow after flattening".to_owned())?;
  let _ = pairs;
  Ok(Trace {
    blocks,
    values_descending,
    successes: total,
    regular_block_successes: regular,
    final_block_delta: final_delta,
  })
}

fn read_group<R: Read>(
  frame: &mut Frame<'_, R>,
  id: u16,
  previous_name: Option<&str>,
  endpoints: &[Endpoint],
  header: &Header,
  budget: &mut Budget,
) -> Result<Group, String> {
  if frame.u16()? != id {
    return Err("pair-group frame ID is missing, duplicated, or reordered".into());
  }
  let name = frame.string(512)?;
  budget.add(name.capacity())?;
  if previous_name.is_some_and(|previous| previous >= name.as_str()) {
    return Err("pair groups are not in stable strict lexical order".into());
  }
  let family_count = frame.u16()?;
  if family_count > 4 {
    return Err("pair group exceeds the four source-family bound".into());
  }
  let mut families = reserved(family_count as usize)?;
  budget.vector(&families)?;
  for _ in 0..family_count {
    let family = frame.string(16)?;
    if families.last().is_some_and(|previous| previous >= &family) {
      return Err("trace family labels are not uniquely sorted".into());
    }
    budget.add(family.capacity())?;
    families.push(family);
  }
  let mut expected_families = reserved(endpoints.len())?;
  for endpoint in endpoints.iter().filter(|endpoint| endpoint.group == id) {
    if let Some(family) = endpoint.family.as_deref() {
      expected_families.push(family);
    }
  }
  budget.vector(&expected_families)?;
  expected_families.sort_unstable();
  expected_families.dedup();
  if families.len() != expected_families.len()
    || families
      .iter()
      .map(String::as_str)
      .zip(&expected_families)
      .any(|(actual, expected)| actual != *expected)
  {
    return Err("trace group family labels differ from the frozen endpoint map".into());
  }
  if frame.u16()? != header.pairs {
    return Err("trace group pair-slot count differs from the frozen process horizon".into());
  }
  let mut slots: Vec<PairSlot> = reserved(header.pairs as usize)?;
  budget.vector(&slots)?;
  for _ in 0..header.pairs {
    let mut slot_families: Vec<FamilyPair> = reserved(families.len())?;
    budget.vector(&slot_families)?;
    for _family in &families {
      let candidate = read_trace(frame, header.pairs, header.block_size, budget)?;
      let control = read_trace(frame, header.pairs, header.block_size, budget)?;
      if candidate.blocks.len() != control.blocks.len() {
        return Err("matched candidate/control trace block horizons differ".into());
      }
      for (candidate_block, control_block) in candidate.blocks.iter().zip(&control.blocks) {
        if candidate_block.successes != control_block.successes {
          return Err("matched candidate/control successful-ID membership differs".into());
        }
      }
      let expected_block_count = slot_families.first().map_or_else(
        || {
          slots
            .first()
            .and_then(|slot| slot.families.first())
            .map(|family| family.candidate.blocks.len())
        },
        |family| Some(family.candidate.blocks.len()),
      );
      if expected_block_count.is_some_and(|count| candidate.blocks.len() != count) {
        return Err("paired family trace block horizons differ".into());
      }
      slot_families.push(FamilyPair { candidate, control });
    }
    slots.push(PairSlot {
      families: slot_families,
    });
  }
  Ok(Group {
    id,
    name,
    families,
    slots,
  })
}

fn nearest_rank_p99(count: u64) -> Result<u64, String> {
  if count == 0 {
    return Err("nearest-rank p99 has no observations".into());
  }
  let ascending = (count / 100)
    .checked_mul(99)
    .and_then(|base| base.checked_add((count % 100 * 99).div_ceil(100)))
    .ok_or_else(|| "nearest-rank p99 count overflow".to_owned())?;
  Ok(count - ascending + 1)
}

fn exact_weighted_p99(trace: &Trace, multiplicities: &[u32], count: u64) -> Result<u64, String> {
  if multiplicities.len() != trace.blocks.len() || count == 0 {
    return Err("weighted p99 block membership is inconsistent".into());
  }
  if let (Some(first), Some(last)) = (
    trace.values_descending.first(),
    trace.values_descending.last(),
  ) && first.latency == last.latency
  {
    return Ok(first.latency);
  }
  let target = nearest_rank_p99(count)?;
  let mut observed = 0u64;
  for entry in &trace.values_descending {
    observed = observed
      .checked_add(u64::from(multiplicities[entry.block as usize]) * u64::from(entry.frequency))
      .ok_or_else(|| "weighted p99 cumulative count overflow".to_owned())?;
    if observed >= target {
      return Ok(entry.latency);
    }
  }
  Err("weighted p99 heap merge fell short of the exact nearest rank".into())
}

fn unweighted_p99(trace: &Trace) -> Result<u64, String> {
  if let (Some(first), Some(last)) = (
    trace.values_descending.first(),
    trace.values_descending.last(),
  ) && first.latency == last.latency
  {
    return Ok(first.latency);
  }
  let target = nearest_rank_p99(trace.successes)?;
  let mut observed = 0u64;
  for entry in &trace.values_descending {
    observed = observed
      .checked_add(u64::from(entry.frequency))
      .ok_or_else(|| "unweighted p99 cumulative count overflow".to_owned())?;
    if observed >= target {
      return Ok(entry.latency);
    }
  }
  Err("unweighted p99 index fell short of the exact nearest rank".into())
}

fn sampled_success_count(
  trace: &Trace,
  selected_blocks: usize,
  last_block_multiplicity: u32,
) -> Result<u64, String> {
  let regular = trace
    .regular_block_successes
    .checked_mul(selected_blocks as u64)
    .ok_or_else(|| "sampled regular-block success count overflow".to_owned())?;
  let delta = trace
    .final_block_delta
    .checked_mul(i64::from(last_block_multiplicity))
    .ok_or_else(|| "sampled final-block success count overflow".to_owned())?;
  let total = i128::from(regular) + i128::from(delta);
  u64::try_from(total).map_err(|_| "sampled family trace has an invalid success count".to_owned())
}

#[derive(Clone, Copy, Debug)]
struct SplitMix64 {
  state: u64,
}

impl SplitMix64 {
  fn next(&mut self) -> u64 {
    self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = self.state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
  }

  #[cfg(test)]
  fn below(&mut self, upper: u64) -> Result<u64, String> {
    if upper == 0 {
      return Err("bootstrap sampled an empty range".into());
    }
    let threshold = upper.wrapping_neg() % upper;
    self.below_with_threshold(upper, threshold)
  }

  fn below_with_threshold(&mut self, upper: u64, threshold: u64) -> Result<u64, String> {
    if upper == 0 || threshold >= upper {
      return Err("bootstrap uniform sampler parameters are invalid".into());
    }
    loop {
      let value = self.next();
      if value >= threshold {
        return Ok(value % upper);
      }
    }
  }
}

fn group_seed(seed: u64, name: &str, id: u16) -> u64 {
  let mut hash = 0xcbf2_9ce4_8422_2325u64;
  for byte in name.bytes() {
    hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
  }
  seed ^ hash ^ (u64::from(id).wrapping_mul(0xd6e8_feb8_6659_fd93))
}

fn f64_order_stat(mut values: Vec<f64>, rank: usize) -> Result<f64, String> {
  if values.is_empty() || rank >= values.len() {
    return Err("bootstrap critical-value order statistic rank is invalid".into());
  }
  values.sort_by(f64::total_cmp);
  Ok(values[rank])
}

/// Consume one complete `ABQST01` stream and emit one `ABQSO01` response.
pub fn analyze<R: Read, W: Write>(reader: R, mut writer: W) -> Result<(), String> {
  let mut input = Input::new(reader);
  let mut magic = [0; 8];
  input.exact(&mut magic)?;
  if &magic != INPUT_MAGIC {
    return Err("analysis input magic/version mismatch".into());
  }
  let header = read_header(&mut input)?;
  input.maximum = header.input_budget;
  if input.consumed > input.maximum {
    return Err("analysis header exceeds the declared stream byte budget".into());
  }
  let mut budget = Budget {
    limit: header.resident_budget,
    used: 0,
    peak: 0,
  };

  let mut endpoints = reserved(header.endpoints as usize)?;
  budget.vector(&endpoints)?;
  for expected_id in 0..header.endpoints {
    let mut frame = input.frame()?;
    if frame.u8()? != FRAME_ENDPOINT {
      return Err("primary endpoint descriptor frame is missing or reordered".into());
    }
    let endpoint = read_endpoint(&mut frame, expected_id, &header, &mut budget)?;
    frame.finish()?;
    if endpoints
      .iter()
      .any(|existing: &Endpoint| existing.name == endpoint.name)
    {
      return Err("analysis endpoint names must be unique".into());
    }
    budget.vector(&endpoint.observed_candidate)?;
    budget.vector(&endpoint.observed_control)?;
    budget.vector(&endpoint.log_ratios)?;
    endpoints.push(endpoint);
  }

  let mut suites = reserved(header.suites as usize)?;
  budget.vector(&suites)?;
  for suite_index in 0..header.suites {
    let mut frame = input.frame()?;
    if frame.u8()? != FRAME_SUITE {
      return Err("suite descriptor frame is missing or reordered".into());
    }
    let suite_id = header.endpoints + suite_index;
    let suite = read_suite(&mut frame, suite_id, header.endpoints, &mut budget)?;
    frame.finish()?;
    if endpoints.iter().any(|endpoint| endpoint.name == suite.name)
      || suites
        .iter()
        .any(|existing: &Suite| existing.name == suite.name)
    {
      return Err("analysis endpoint and suite names must be unique".into());
    }
    suites.push(suite);
  }

  let endpoint_count = usize::from(header.endpoints + header.suites);
  let matrix_items = (header.draws as usize)
    .checked_mul(endpoint_count)
    .ok_or_else(|| "bootstrap draw matrix size overflow".to_owned())?;
  let mut matrix = reserved(matrix_items)?;
  matrix.resize(matrix_items, 0.0);
  budget.vector(&matrix)?;
  let mut centers = reserved(endpoint_count)?;
  let mut populated_endpoints = reserved(header.endpoints as usize)?;
  centers.resize(endpoint_count, 0.0);
  populated_endpoints.resize(header.endpoints as usize, 0u8);
  budget.vector(&centers)?;
  budget.vector(&populated_endpoints)?;
  let base_budget = budget.used;
  if base_budget > header.resident_budget {
    return Err("endpoint and packed draw matrix exceed the resident budget".into());
  }

  for endpoint in &endpoints {
    let center = if endpoint.family.is_some() {
      endpoint
        .observed_candidate
        .iter()
        .zip(&endpoint.observed_control)
        .map(|(candidate, control)| (*candidate as f64 / *control as f64).ln())
        .sum::<f64>()
        / f64::from(header.pairs)
    } else {
      endpoint.log_ratios.iter().sum::<f64>() / f64::from(header.pairs)
    };
    centers[endpoint.id as usize] = center;
  }

  let mut previous_group_name: Option<String> = None;
  for expected_id in 0..header.groups {
    let mut frame = input.frame()?;
    if frame.u8()? != FRAME_GROUP {
      return Err("pair-group frame is missing or reordered".into());
    }
    let group = read_group(
      &mut frame,
      expected_id,
      previous_group_name.as_deref(),
      &endpoints,
      &header,
      &mut budget,
    )?;
    frame.finish()?;
    let current_group_name = group.name.clone();
    budget.add(current_group_name.capacity())?;
    previous_group_name = Some(current_group_name);
    let mut group_endpoint_ids = reserved(endpoints.len())?;
    for endpoint in endpoints
      .iter()
      .filter(|endpoint| endpoint.group == group.id)
    {
      group_endpoint_ids.push(endpoint.id as usize);
    }
    budget.vector(&group_endpoint_ids)?;
    if group_endpoint_ids.is_empty() {
      return Err("pair group has no primary endpoint".into());
    }
    let max_blocks = group
      .slots
      .first()
      .and_then(|slot| slot.families.first())
      .map_or(0, |family| family.candidate.blocks.len());
    let mut multiplicities = reserved(max_blocks)?;
    multiplicities.resize(max_blocks, 0u32);
    budget.vector(&multiplicities)?;
    let mut log_accumulators = reserved(group_endpoint_ids.len())?;
    log_accumulators.resize(group_endpoint_ids.len(), 0.0);
    budget.vector(&log_accumulators)?;
    let mut sampled_counts = reserved(group.families.len())?;
    sampled_counts.resize(group.families.len(), 0u64);
    budget.vector(&sampled_counts)?;
    let mut endpoint_family_indices = reserved(group_endpoint_ids.len())?;
    for endpoint_id in &group_endpoint_ids {
      endpoint_family_indices.push(endpoints[*endpoint_id].family.as_ref().and_then(|family| {
        group
          .families
          .iter()
          .position(|candidate| candidate == family)
      }));
    }
    budget.vector(&endpoint_family_indices)?;

    // Verify every supplied per-process p99 against a recomputation over its
    // exact, original contiguous trace before sampling any pseudotraces.
    for endpoint in endpoints
      .iter()
      .filter(|endpoint| endpoint.group == group.id && endpoint.family.is_some())
    {
      let family_index = group
        .families
        .iter()
        .position(|family| Some(family.as_str()) == endpoint.family.as_deref())
        .ok_or_else(|| "p99 endpoint family is absent from its paired trace group".to_owned())?;
      for slot_index in 0..header.pairs as usize {
        let traces = &group.slots[slot_index].families[family_index];
        let candidate = unweighted_p99(&traces.candidate)?;
        let control = unweighted_p99(&traces.control)?;
        if candidate != endpoint.observed_candidate[slot_index]
          || control != endpoint.observed_control[slot_index]
        {
          return Err(format!(
            "observed p99 differs from exact source trace for {} pair slot {slot_index}",
            endpoint.name
          ));
        }
      }
    }

    let mut rng = SplitMix64 {
      state: group_seed(header.seed, &group.name, group.id),
    };
    let pair_upper = u64::from(header.pairs);
    let pair_threshold = pair_upper.wrapping_neg() % pair_upper;
    for draw_index in 0..header.draws as usize {
      log_accumulators.fill(0.0);
      for _sample_slot in 0..header.pairs {
        let selected_slot = rng.below_with_threshold(pair_upper, pair_threshold)? as usize;
        for (endpoint_offset, endpoint_id) in group_endpoint_ids.iter().enumerate() {
          let endpoint = &endpoints[*endpoint_id];
          if endpoint.family.is_none() {
            log_accumulators[endpoint_offset] += endpoint.log_ratios[selected_slot];
          }
        }
        if group.families.is_empty() {
          continue;
        }
        let block_count = group.slots[selected_slot].families[0]
          .candidate
          .blocks
          .len();
        let block_upper = block_count as u64;
        let block_threshold = block_upper.wrapping_neg() % block_upper;
        multiplicities.fill(0);
        sampled_counts.fill(0);
        for _ in 0..block_count {
          let block_id = rng.below_with_threshold(block_upper, block_threshold)? as usize;
          multiplicities[block_id] += 1;
        }
        let last_block_multiplicity = multiplicities[block_count - 1];
        for (family_index, family) in group.slots[selected_slot].families.iter().enumerate() {
          sampled_counts[family_index] =
            sampled_success_count(&family.candidate, block_count, last_block_multiplicity)?;
        }
        for endpoint_offset in 0..group_endpoint_ids.len() {
          let Some(family_index) = endpoint_family_indices[endpoint_offset] else {
            continue;
          };
          let traces = &group.slots[selected_slot].families[family_index];
          let candidate = exact_weighted_p99(
            &traces.candidate,
            &multiplicities,
            sampled_counts[family_index],
          )?;
          let control = exact_weighted_p99(
            &traces.control,
            &multiplicities,
            sampled_counts[family_index],
          )?;
          log_accumulators[endpoint_offset] += (candidate as f64 / control as f64).ln();
        }
      }
      for (offset, endpoint_id) in group_endpoint_ids.iter().enumerate() {
        let matrix_index = draw_index * endpoint_count + *endpoint_id;
        matrix[matrix_index] = log_accumulators[offset] / f64::from(header.pairs);
      }
    }
    for endpoint_id in &group_endpoint_ids {
      populated_endpoints[*endpoint_id] = 1;
    }
    drop(group);
    budget.used = base_budget
      .checked_add(
        previous_group_name
          .as_ref()
          .map_or(0, |name| name.capacity() as u64),
      )
      .ok_or_else(|| "persistent analyzer group-name budget overflow".to_owned())?;
    let _ = base_budget;
  }

  let mut end_frame = input.frame()?;
  if end_frame.u8()? != FRAME_END {
    return Err("analysis stream lacks its end frame".into());
  }
  end_frame.finish()?;
  let mut trailing = [0; 1];
  if input
    .reader
    .read(&mut trailing)
    .map_err(|error| format!("could not check analyzer stream EOF: {error}"))?
    != 0
  {
    return Err("analysis stream has bytes after its end frame".into());
  }

  if populated_endpoints.iter().any(|populated| *populated != 1) {
    return Err("one or more analyzer endpoint columns were not populated".into());
  }
  for suite in &suites {
    let mut center = 0.0;
    for component in &suite.components {
      center += (f64::from(component.numerator) / f64::from(component.denominator))
        * centers[component.index as usize];
    }
    centers[suite.id as usize] = center;
    for draw in 0..header.draws as usize {
      let mut value = 0.0;
      for component in &suite.components {
        value += (f64::from(component.numerator) / f64::from(component.denominator))
          * matrix[draw * endpoint_count + component.index as usize];
      }
      matrix[draw * endpoint_count + suite.id as usize] = value;
    }
  }

  let draws = header.draws as usize;
  let mut scales = reserved(endpoint_count)?;
  scales.resize(endpoint_count, 0.0);
  budget.vector(&scales)?;
  let mut max_statistics = reserved(draws)?;
  budget.vector(&max_statistics)?;
  for endpoint in 0..endpoint_count {
    let mut mean = 0.0;
    let mut m2 = 0.0;
    for draw in 0..draws {
      let value = matrix[draw * endpoint_count + endpoint];
      let delta = value - mean;
      mean += delta / (draw + 1) as f64;
      m2 += delta * (value - mean);
    }
    let scale = if draws > 1 {
      (m2 / (draws - 1) as f64).sqrt()
    } else {
      0.0
    };
    if !scale.is_finite() {
      return Err("bootstrap endpoint scale is non-finite".into());
    }
    if scale == 0.0 {
      for draw in 0..draws {
        if matrix[draw * endpoint_count + endpoint] != centers[endpoint] {
          return Err("constant bootstrap endpoint differs from its exact point center".into());
        }
      }
    }
    scales[endpoint] = scale;
  }
  for draw in 0..draws {
    let mut maximum = 0.0f64;
    for endpoint in 0..endpoint_count {
      let scale = scales[endpoint];
      let deviation = (matrix[draw * endpoint_count + endpoint] - centers[endpoint]).abs();
      if scale == 0.0 {
        if deviation != 0.0 {
          return Err("zero-scale endpoint replicate differs from its exact center".into());
        }
      } else {
        maximum = maximum.max(deviation / scale);
      }
    }
    max_statistics.push(maximum);
  }
  let critical_rank = ((header.confidence * draws as f64).ceil() as usize)
    .saturating_sub(1)
    .min(draws - 1);
  let critical = f64_order_stat(max_statistics, critical_rank)?;

  writer
    .write_all(OUTPUT_MAGIC)
    .map_err(|error| error.to_string())?;
  writer
    .write_all(&header.draws.to_le_bytes())
    .map_err(|error| error.to_string())?;
  writer
    .write_all(&(endpoint_count as u16).to_le_bytes())
    .map_err(|error| error.to_string())?;
  writer
    .write_all(&header.groups.to_le_bytes())
    .map_err(|error| error.to_string())?;
  writer
    .write_all(&header.seed.to_le_bytes())
    .map_err(|error| error.to_string())?;
  writer
    .write_all(&input.consumed.to_le_bytes())
    .map_err(|error| error.to_string())?;
  writer
    .write_all(&budget.peak.to_le_bytes())
    .map_err(|error| error.to_string())?;
  writer
    .write_all(&critical.to_bits().to_le_bytes())
    .map_err(|error| error.to_string())?;
  for index in 0..endpoint_count {
    let (name, id) = if index < endpoints.len() {
      (&endpoints[index].name, endpoints[index].id)
    } else {
      let suite = &suites[index - endpoints.len()];
      (&suite.name, suite.id)
    };
    let point = centers[index].exp();
    let scale = scales[index];
    let lower = (centers[index] - critical * scale).exp();
    let upper = (centers[index] + critical * scale).exp();
    if ![point, lower, upper]
      .iter()
      .all(|value| value.is_finite() && *value > 0.0)
    {
      return Err("bootstrap interval endpoint is non-finite or non-positive".into());
    }
    writer
      .write_all(&id.to_le_bytes())
      .map_err(|error| error.to_string())?;
    writer
      .write_all(&(name.len() as u16).to_le_bytes())
      .map_err(|error| error.to_string())?;
    writer
      .write_all(name.as_bytes())
      .map_err(|error| error.to_string())?;
    for value in [point, centers[index], scale, lower, upper] {
      writer
        .write_all(&value.to_bits().to_le_bytes())
        .map_err(|error| error.to_string())?;
    }
  }
  writer.flush().map_err(|error| error.to_string())?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Cursor;

  fn frame(kind: u8, fields: &[u8]) -> Vec<u8> {
    let length = (fields.len() + 1) as u64;
    let mut bytes = length.to_le_bytes().to_vec();
    bytes.push(kind);
    bytes.extend_from_slice(fields);
    bytes
  }

  fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
  }

  fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
  }

  fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
  }

  fn put_f64(bytes: &mut Vec<u8>, value: f64) {
    put_u64(bytes, value.to_bits());
  }

  fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u16(bytes, value.len() as u16);
    bytes.extend_from_slice(value.as_bytes());
  }

  fn header(draws: u32, pairs: u16, groups: u16, endpoints: u16, suites: u16) -> Vec<u8> {
    let mut fields = Vec::new();
    put_u32(&mut fields, draws);
    put_u16(&mut fields, pairs);
    put_u16(&mut fields, groups);
    put_u16(&mut fields, endpoints);
    put_u16(&mut fields, suites);
    put_u64(&mut fields, 20261012);
    put_f64(&mut fields, 0.95);
    put_u32(&mut fields, 1000);
    put_u64(&mut fields, 1 << 30);
    put_u64(&mut fields, 1 << 30);
    frame(FRAME_HEADER, &fields)
  }

  fn output_point(bytes: &[u8]) -> f64 {
    assert_eq!(&bytes[..8], OUTPUT_MAGIC);
    let name_len = u16::from_le_bytes([bytes[50], bytes[51]]) as usize;
    let point_offset = 52 + name_len;
    f64::from_bits(u64::from_le_bytes(
      bytes[point_offset..point_offset + 8].try_into().unwrap(),
    ))
  }

  #[test]
  fn splitmix_below_is_repeatable_and_rejects_empty_ranges() {
    let mut left = SplitMix64 { state: 20261012 };
    let mut right = left;
    for _ in 0..100 {
      assert_eq!(left.below(37).unwrap(), right.below(37).unwrap());
    }
    assert!(left.below(0).is_err());
  }

  #[test]
  fn nearest_rank_matches_exact_small_and_large_cardinalities() {
    assert_eq!(nearest_rank_p99(1).unwrap(), 1);
    assert_eq!(nearest_rank_p99(100).unwrap(), 2);
    assert_eq!(nearest_rank_p99(1000).unwrap(), 11);
    assert_eq!(nearest_rank_p99(100_000).unwrap(), 1001);
  }

  #[test]
  fn header_rejects_resident_budget_above_frozen_bound() {
    let mut wire = header(1, 1, 1, 1, 0);
    let resident_budget_offset = 8 + 1 + 4 + 2 * 4 + 8 + 8 + 4 + 8;
    wire[resident_budget_offset..resident_budget_offset + 8]
      .copy_from_slice(&(MAX_RESIDENT_BYTES + 1).to_le_bytes());
    let mut input = Input::new(std::io::Cursor::new(wire));
    assert!(read_header(&mut input).is_err());
  }

  #[test]
  fn exact_weighted_order_statistic_uses_all_blocks_and_empty_family_slots() {
    let trace = Trace {
      blocks: vec![
        Block {
          values: vec![],
          counts: vec![],
          successes: 3,
        },
        Block {
          values: vec![],
          counts: vec![],
          successes: 3,
        },
        Block {
          values: vec![],
          counts: vec![],
          successes: 0,
        },
      ],
      values_descending: vec![
        GlobalValue {
          latency: 100,
          block: 0,
          frequency: 1,
        },
        GlobalValue {
          latency: 50,
          block: 1,
          frequency: 1,
        },
        GlobalValue {
          latency: 20,
          block: 1,
          frequency: 1,
        },
        GlobalValue {
          latency: 10,
          block: 0,
          frequency: 1,
        },
        GlobalValue {
          latency: 5,
          block: 1,
          frequency: 1,
        },
        GlobalValue {
          latency: 1,
          block: 0,
          frequency: 1,
        },
      ],
      successes: 6,
      regular_block_successes: 3,
      final_block_delta: -3,
    };
    let repeated_full_blocks = sampled_success_count(&trace, 3, 0).unwrap();
    assert_eq!(repeated_full_blocks, 9);
    assert_eq!(
      exact_weighted_p99(&trace, &[2, 1, 0], repeated_full_blocks).unwrap(),
      100
    );
    let one_full_and_two_empty = sampled_success_count(&trace, 3, 2).unwrap();
    assert_eq!(one_full_and_two_empty, 3);
    assert_eq!(
      exact_weighted_p99(&trace, &[0, 1, 2], one_full_and_two_empty).unwrap(),
      50
    );
    assert!(exact_weighted_p99(&trace, &[0, 0, 3], 0).is_err());
  }

  #[test]
  fn exact_weighted_p99_regression_matches_full_pseudotrace_not_block_p99_mean() {
    let candidate = Trace {
      blocks: vec![
        Block {
          values: vec![],
          counts: vec![],
          successes: 1000,
        },
        Block {
          values: vec![],
          counts: vec![],
          successes: 1000,
        },
      ],
      values_descending: vec![
        GlobalValue {
          latency: 100,
          block: 1,
          frequency: 1000,
        },
        GlobalValue {
          latency: 1,
          block: 0,
          frequency: 1000,
        },
      ],
      successes: 2000,
      regular_block_successes: 1000,
      final_block_delta: 0,
    };
    let control = Trace {
      blocks: vec![
        Block {
          values: vec![],
          counts: vec![],
          successes: 1000,
        },
        Block {
          values: vec![],
          counts: vec![],
          successes: 1000,
        },
      ],
      values_descending: vec![
        GlobalValue {
          latency: 100,
          block: 1,
          frequency: 1000,
        },
        GlobalValue {
          latency: 2,
          block: 0,
          frequency: 1000,
        },
      ],
      successes: 2000,
      regular_block_successes: 1000,
      final_block_delta: 0,
    };
    assert_eq!(exact_weighted_p99(&candidate, &[1, 1], 2000).unwrap(), 100);
    assert_eq!(exact_weighted_p99(&control, &[1, 1], 2000).unwrap(), 100);
    assert_eq!(100.0 / 100.0, 1.0);
    assert_eq!(((1.0 / 2.0) + (100.0 / 100.0)) / 2.0, 0.75);
  }

  #[test]
  fn analyzer_decodes_counter_and_suite_endpoints_repeatably() {
    let mut input = INPUT_MAGIC.to_vec();
    input.extend(header(32, 3, 1, 1, 1));
    let mut endpoint = vec![0];
    put_u16(&mut endpoint, 0);
    put_string(&mut endpoint, "capacity:cpu:steady");
    for ratio in [1.1, 1.2, 1.3] {
      put_f64(&mut endpoint, ratio);
    }
    input.extend(frame(FRAME_ENDPOINT, &endpoint));
    let mut suite = Vec::new();
    put_string(&mut suite, "capacity-suite");
    put_u16(&mut suite, 1);
    put_u16(&mut suite, 0);
    put_u32(&mut suite, 1);
    put_u32(&mut suite, 1);
    input.extend(frame(FRAME_SUITE, &suite));
    let mut group = Vec::new();
    put_u16(&mut group, 0);
    put_string(&mut group, "capacity-cpu");
    put_u16(&mut group, 0);
    put_u16(&mut group, 3);
    input.extend(frame(FRAME_GROUP, &group));
    input.extend(frame(FRAME_END, &[]));

    let mut first = Vec::new();
    analyze(Cursor::new(input.clone()), &mut first).unwrap();
    let mut second = Vec::new();
    analyze(Cursor::new(input), &mut second).unwrap();
    assert_eq!(
      first, second,
      "fixed seed must produce byte-identical output"
    );
    let expected = ((1.1f64.ln() + 1.2f64.ln() + 1.3f64.ln()) / 3.0).exp();
    assert!((output_point(&first) - expected).abs() < 1e-12);
  }

  #[test]
  fn reciprocal_counter_ratios_may_sum_to_zero_across_nonconstant_draws() {
    let group_name = (0..10_000)
      .map(|candidate| format!("reciprocal-counter-{candidate}"))
      .find(|name| {
        let mut rng = SplitMix64 {
          state: group_seed(20261012, name, 0),
        };
        let mut selected = [0usize; 2];
        let mut has_nonconstant_draw = false;
        for _ in 0..2 {
          let first = rng.below(2).unwrap() as usize;
          let second = rng.below(2).unwrap() as usize;
          selected[first] += 1;
          selected[second] += 1;
          has_nonconstant_draw |= first == second;
        }
        selected[0] == selected[1] && has_nonconstant_draw
      })
      .expect("fixed-seed fixture should contain reciprocal nonconstant draws");

    let mut input = INPUT_MAGIC.to_vec();
    input.extend(header(2, 2, 1, 1, 0));
    let mut endpoint = vec![0];
    put_u16(&mut endpoint, 0);
    put_string(&mut endpoint, "reciprocal-counter");
    put_f64(&mut endpoint, 2.0);
    put_f64(&mut endpoint, 0.5);
    input.extend(frame(FRAME_ENDPOINT, &endpoint));
    let mut group = Vec::new();
    put_u16(&mut group, 0);
    put_string(&mut group, &group_name);
    put_u16(&mut group, 0);
    put_u16(&mut group, 2);
    input.extend(frame(FRAME_GROUP, &group));
    input.extend(frame(FRAME_END, &[]));

    let mut output = Vec::new();
    analyze(Cursor::new(input), &mut output).unwrap();
    assert!((output_point(&output) - 1.0).abs() < 1e-12);
    let name_len = u16::from_le_bytes([output[50], output[51]]) as usize;
    let scale_offset = 52 + name_len + 2 * 8;
    let scale = f64::from_bits(u64::from_le_bytes(
      output[scale_offset..scale_offset + 8].try_into().unwrap(),
    ));
    assert!(scale > 0.0, "opposing homogeneous draws must have variance");
  }

  #[test]
  fn analyzer_recomputes_full_trace_p99_before_resampling() {
    let mut input = INPUT_MAGIC.to_vec();
    input.extend(header(64, 1, 1, 1, 0));
    let mut endpoint = vec![1];
    put_u16(&mut endpoint, 0);
    put_string(&mut endpoint, "p99:cpu:steady");
    put_string(&mut endpoint, "cpu");
    put_u64(&mut endpoint, 100);
    put_u64(&mut endpoint, 50);
    input.extend(frame(FRAME_ENDPOINT, &endpoint));

    let mut group = Vec::new();
    put_u16(&mut group, 0);
    put_string(&mut group, "openloop-cpu");
    put_u16(&mut group, 1);
    put_string(&mut group, "cpu");
    put_u16(&mut group, 1);
    for values in [[100u64, 1u64], [50u64, 1u64]] {
      put_u32(&mut group, 2);
      for value in values {
        put_u32(&mut group, 1);
        put_u32(&mut group, 1);
        put_u64(&mut group, value);
        put_u32(&mut group, 1);
      }
    }
    input.extend(frame(FRAME_GROUP, &group));
    input.extend(frame(FRAME_END, &[]));
    let mut output = Vec::new();
    analyze(Cursor::new(input.clone()), &mut output).unwrap();
    assert!((output_point(&output) - 2.0).abs() < 1e-12);
    let mut replay = Vec::new();
    analyze(Cursor::new(input), &mut replay).unwrap();
    assert_eq!(output, replay);
  }

  #[test]
  fn analyzer_rejects_observed_p99_mismatch_and_trailing_bytes() {
    let mut input = INPUT_MAGIC.to_vec();
    input.extend(header(8, 1, 1, 1, 0));
    let mut endpoint = vec![1];
    put_u16(&mut endpoint, 0);
    put_string(&mut endpoint, "p99:cpu");
    put_string(&mut endpoint, "cpu");
    put_u64(&mut endpoint, 200);
    put_u64(&mut endpoint, 50);
    input.extend(frame(FRAME_ENDPOINT, &endpoint));
    let mut group = Vec::new();
    put_u16(&mut group, 0);
    put_string(&mut group, "group");
    put_u16(&mut group, 1);
    put_string(&mut group, "cpu");
    put_u16(&mut group, 1);
    for value in [100u64, 50u64] {
      put_u32(&mut group, 1);
      put_u32(&mut group, 1);
      put_u32(&mut group, 1);
      put_u64(&mut group, value);
      put_u32(&mut group, 1);
    }
    input.extend(frame(FRAME_GROUP, &group));
    input.extend(frame(FRAME_END, &[]));
    assert!(
      analyze(Cursor::new(input.clone()), Vec::new())
        .unwrap_err()
        .contains("observed p99 differs")
    );
    let mut valid = INPUT_MAGIC.to_vec();
    valid.extend(header(8, 1, 1, 1, 0));
    let mut raw_endpoint = vec![0];
    put_u16(&mut raw_endpoint, 0);
    put_string(&mut raw_endpoint, "capacity:cpu");
    put_f64(&mut raw_endpoint, 1.0);
    valid.extend(frame(FRAME_ENDPOINT, &raw_endpoint));
    let mut raw_group = Vec::new();
    put_u16(&mut raw_group, 0);
    put_string(&mut raw_group, "capacity-cpu");
    put_u16(&mut raw_group, 0);
    put_u16(&mut raw_group, 1);
    valid.extend(frame(FRAME_GROUP, &raw_group));
    valid.extend(frame(FRAME_END, &[]));
    valid.push(0);
    let trailing_error = analyze(Cursor::new(valid), Vec::new()).unwrap_err();
    assert!(
      trailing_error.contains("bytes after its end"),
      "unexpected trailing-data result: {trailing_error}"
    );
  }

  #[test]
  fn input_decoder_rejects_magic_and_truncated_frames() {
    assert!(analyze(Cursor::new(b"badmagic"), Vec::new()).is_err());
    let mut input = INPUT_MAGIC.to_vec();
    input.extend_from_slice(&100u64.to_le_bytes());
    input.extend_from_slice(&[FRAME_HEADER]);
    assert!(analyze(Cursor::new(input), Vec::new()).is_err());
  }
}
