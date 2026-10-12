use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

fn run() -> Result<(), String> {
  let arguments: Vec<String> = std::env::args().collect();
  if arguments.len() != 3 {
    return Err("usage: application-analyze INPUT_STREAM OUTPUT_STREAM".into());
  }
  let input_path = Path::new(&arguments[1]);
  let output_path = Path::new(&arguments[2]);
  let input =
    File::open(input_path).map_err(|error| format!("cannot open analyzer input: {error}"))?;
  let output = OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(output_path)
    .map_err(|error| format!("cannot create analyzer output: {error}"))?;
  let result =
    allocatbelt_qualification_tools::analyze(BufReader::new(input), BufWriter::new(output));
  if result.is_err() {
    let _ = std::fs::remove_file(output_path);
  }
  result
}

fn main() -> ExitCode {
  match run() {
    Ok(()) => ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("application analyzer refused: {error}");
      ExitCode::FAILURE
    }
  }
}
