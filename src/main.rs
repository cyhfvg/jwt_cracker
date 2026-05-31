use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use jwt_cracker::{
    CrackStats, EncodeMethod, InputSource, Match, crack_reporting, crack_with_key_reader_reporting,
    load_secret_keys, load_token_values,
};

#[derive(Debug, Parser)]
#[command(
    name = "jwt_cracker",
    version,
    about = "Brute-force HMAC-signed JWT tokens with candidate secret keys.",
    long_about = "Brute-force HS256, HS384, and HS512 JWT tokens with candidate secret keys.\n\nValues for --jwt-token and --secret-key can be direct strings, line-oriented files, or '-' for stdin."
)]
struct Cli {
    #[arg(
        short = 't',
        long = "jwt-token",
        value_name = "JWT_OR_FILE_OR_STDIN",
        help = "JWT token, path to a line-oriented token file, or '-' to read tokens from stdin"
    )]
    jwt_token: String,

    #[arg(
        short = 'k',
        long = "secret-key",
        value_name = "KEY_OR_FILE_OR_STDIN",
        help = "Secret key, path to a line-oriented key file, or '-' to read keys from stdin"
    )]
    secret_key: String,

    #[arg(
        short = 'e',
        long = "encode-method",
        value_name = "METHOD",
        value_enum,
        default_value_t = CliEncodeMethod::None,
        help = "Encode each candidate secret before cracking"
    )]
    encode_method: CliEncodeMethod,

    #[arg(
        short = 'w',
        long = "workers",
        value_name = "N",
        default_value_t = num_cpus::get(),
        help = "Number of worker threads to split the total attempt space across"
    )]
    workers: usize,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
enum CliEncodeMethod {
    None,
    Base64,
    Md5,
    Md5Len16,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let started = Instant::now();

    if cli.jwt_token == "-" && cli.secret_key == "-" {
        bail!("--jwt-token and --secret-key cannot both read from stdin");
    }

    let stdin = if cli.jwt_token == "-" {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        Some(buffer)
    } else {
        None
    };
    let stdin = stdin.as_deref();

    let tokens = load_token_values(&cli.jwt_token, stdin, "JWT token")?;
    let token_count = tokens.values.len();
    let token_source = source_label(&tokens.source);
    let key_source = secret_key_source(&cli.secret_key);
    let key_source_label = source_label(&key_source);
    let encode_method = cli.encode_method.into();
    let stdout = Mutex::new(std::io::stdout());
    let print_match = |found: Match| {
        let mut stdout = stdout.lock().expect("stdout lock should not be poisoned");
        writeln!(
            stdout,
            "MATCH token={} key={}",
            yellow(&found.token),
            green(&found.key)
        )
        .expect("match result should be written");
        stdout.flush().expect("match result should be flushed");
    };
    let CrackStats {
        key_count,
        match_count,
        attempt_count,
    } = match &key_source {
        InputSource::Direct => {
            let keys = load_secret_keys(&cli.secret_key, None, "secret key", encode_method)?;
            let key_count = keys.values.len();
            let stats = crack_reporting(tokens.values, keys.values, cli.workers, print_match)?;
            CrackStats {
                key_count,
                match_count: stats.match_count,
                attempt_count: stats.attempt_count,
            }
        }
        InputSource::File(path) => {
            let file = File::open(path)
                .with_context(|| format!("failed to open secret key file `{path}`"))?;
            crack_with_key_reader_reporting(
                tokens.values,
                BufReader::new(file),
                encode_method,
                cli.workers,
                print_match,
            )?
        }
        InputSource::Stdin => {
            let stdin = std::io::stdin();
            crack_with_key_reader_reporting(
                tokens.values,
                stdin.lock(),
                encode_method,
                cli.workers,
                print_match,
            )?
        }
    };
    let effective_workers = cli.workers.max(1).min(key_count);
    let elapsed = started.elapsed();

    eprintln!(
        "Loaded {} token(s) from {} and {} key(s) from {}.",
        token_count, token_source, key_count, key_source_label,
    );
    eprintln!(
        "Tested {} total attempt(s) across {} worker(s) in {}.",
        attempt_count,
        effective_workers,
        format_duration(elapsed),
    );

    if match_count == 0 {
        println!("No matching secret keys found.");
    }

    Ok(())
}

fn source_label(source: &InputSource) -> &str {
    match source {
        InputSource::Direct => "direct input",
        InputSource::File(_) => "file",
        InputSource::Stdin => "stdin",
    }
}

fn secret_key_source(argument: &str) -> InputSource {
    if argument == "-" {
        InputSource::Stdin
    } else if Path::new(argument).is_file() {
        InputSource::File(argument.to_owned())
    } else {
        InputSource::Direct
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let millis = duration.subsec_millis();
    if seconds == 0 {
        format!("{millis}ms")
    } else {
        format!("{seconds}.{millis:03}s")
    }
}

fn yellow(value: &str) -> String {
    format!("\x1b[33m{value}\x1b[0m")
}

fn green(value: &str) -> String {
    format!("\x1b[32m{value}\x1b[0m")
}

impl From<CliEncodeMethod> for EncodeMethod {
    fn from(value: CliEncodeMethod) -> Self {
        match value {
            CliEncodeMethod::None => Self::None,
            CliEncodeMethod::Base64 => Self::Base64,
            CliEncodeMethod::Md5 => Self::Md5,
            CliEncodeMethod::Md5Len16 => Self::Md5Len16,
        }
    }
}
