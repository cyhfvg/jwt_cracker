use std::fmt;
use std::io::BufRead;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::{Engine, encoded_len};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Sha256, Sha384, Sha512};

const SECRET_KEY_BATCH_SIZE: usize = 262_144;
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputList<T> {
    pub values: T,
    pub source: InputSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputSource {
    Direct,
    File(String),
    Stdin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Match {
    pub token: String,
    pub key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrackResult {
    pub matches: Vec<Match>,
    pub key_count: usize,
    pub attempt_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrackStats {
    pub key_count: usize,
    pub match_count: usize,
    pub attempt_count: usize,
}

struct BatchResult {
    matches: Vec<Match>,
    attempt_count: usize,
}

struct BatchStats {
    match_count: usize,
    attempt_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeySpan {
    start: usize,
    end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretKeyRef<'a> {
    bytes: &'a [u8],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretKeyBatch {
    bytes: Vec<u8>,
    spans: Vec<KeySpan>,
}

impl SecretKeyBatch {
    #[must_use]
    pub fn with_capacity(key_capacity: usize) -> Self {
        Self {
            bytes: Vec::new(),
            spans: Vec::with_capacity(key_capacity),
        }
    }

    #[must_use]
    pub fn from_keys<I, B>(keys: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let keys = keys.into_iter();
        let mut batch = Self::with_capacity(keys.size_hint().0);
        for key in keys {
            batch.push(key);
        }
        batch
    }

    pub fn push(&mut self, bytes: impl AsRef<[u8]>) {
        let bytes = bytes.as_ref();
        let start = self.bytes.len();
        self.bytes.extend_from_slice(bytes);
        self.spans.push(KeySpan {
            start,
            end: self.bytes.len(),
        });
    }

    pub fn push_encoded(&mut self, input: &[u8], encode_method: EncodeMethod) {
        match encode_method {
            EncodeMethod::None => self.push(input),
            EncodeMethod::Base64 => {
                self.push_base64(input);
            }
            EncodeMethod::Md5 => {
                let digest = md5::compute(input);
                self.push_hex(&digest.0);
            }
            EncodeMethod::Md5Len16 => {
                let digest = md5::compute(input);
                self.push_hex(&digest.0[4..12]);
            }
        }
    }

    fn push_hex(&mut self, bytes: &[u8]) {
        let start = self.bytes.len();
        self.bytes.reserve(bytes.len() * 2);
        for byte in bytes {
            self.bytes.push(HEX_LOWER[(byte >> 4) as usize]);
            self.bytes.push(HEX_LOWER[(byte & 0x0f) as usize]);
        }
        self.spans.push(KeySpan {
            start,
            end: self.bytes.len(),
        });
    }

    fn push_base64(&mut self, bytes: &[u8]) {
        let encoded_len =
            encoded_len(bytes.len(), true).expect("base64 encoded length should fit in usize");
        let start = self.bytes.len();
        self.bytes.resize(start + encoded_len, 0);
        let bytes_written = STANDARD
            .encode_slice(bytes, &mut self.bytes[start..])
            .expect("base64 output buffer was sized from encoded_len");
        debug_assert_eq!(bytes_written, encoded_len);
        self.spans.push(KeySpan {
            start,
            end: start + bytes_written,
        });
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
        self.spans.clear();
    }

    #[inline]
    #[must_use]
    pub fn key(&self, index: usize) -> SecretKeyRef<'_> {
        let span = self.spans[index];
        SecretKeyRef {
            bytes: &self.bytes[span.start..span.end],
        }
    }
}

impl<'a> SecretKeyRef<'a> {
    #[inline]
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub fn display_lossy(self) -> String {
        String::from_utf8_lossy(self.bytes).into_owned()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeMethod {
    None,
    Base64,
    Md5,
    Md5Len16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JwtCandidate {
    original: String,
    signing_input: String,
    signature: Vec<u8>,
    alg: Algorithm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Hs256,
    Hs384,
    Hs512,
}

impl Algorithm {
    fn from_name(name: &str) -> Result<Self> {
        match name {
            "HS256" => Ok(Self::Hs256),
            "HS384" => Ok(Self::Hs384),
            "HS512" => Ok(Self::Hs512),
            other => {
                bail!("unsupported JWT alg `{other}`; supported values are HS256, HS384, and HS512")
            }
        }
    }
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
}

pub fn load_token_values(
    argument: &str,
    stdin: Option<&[u8]>,
    label: &str,
) -> Result<InputList<Vec<String>>> {
    if argument == "-" {
        let stdin =
            stdin.ok_or_else(|| anyhow!("{label} requested stdin, but stdin was not provided"))?;
        let stdin = std::str::from_utf8(stdin)
            .with_context(|| format!("{label} stdin was not valid UTF-8"))?;
        return Ok(InputList {
            values: parse_text_lines(stdin),
            source: InputSource::Stdin,
        });
    }

    if std::path::Path::new(argument).is_file() {
        let contents = std::fs::read_to_string(argument)
            .with_context(|| format!("failed to read {label} file `{argument}`"))?;
        return Ok(InputList {
            values: parse_text_lines(&contents),
            source: InputSource::File(argument.to_owned()),
        });
    }

    Ok(InputList {
        values: vec![argument.to_owned()],
        source: InputSource::Direct,
    })
}

pub fn load_secret_keys(
    argument: &str,
    stdin: Option<&[u8]>,
    label: &str,
    encode_method: EncodeMethod,
) -> Result<InputList<SecretKeyBatch>> {
    if argument == "-" {
        let stdin =
            stdin.ok_or_else(|| anyhow!("{label} requested stdin, but stdin was not provided"))?;
        return Ok(InputList {
            values: parse_secret_key_lines(stdin, encode_method),
            source: InputSource::Stdin,
        });
    }

    if std::path::Path::new(argument).is_file() {
        let contents = std::fs::read(argument)
            .with_context(|| format!("failed to read {label} file `{argument}`"))?;
        return Ok(InputList {
            values: parse_secret_key_lines(&contents, encode_method),
            source: InputSource::File(argument.to_owned()),
        });
    }

    let mut values = SecretKeyBatch::with_capacity(1);
    values.push_encoded(argument.as_bytes(), encode_method);
    Ok(InputList {
        values,
        source: InputSource::Direct,
    })
}

pub fn crack(tokens: Vec<String>, keys: SecretKeyBatch, workers: usize) -> Result<Vec<Match>> {
    if tokens.is_empty() {
        bail!("no JWT tokens were provided");
    }
    if keys.is_empty() {
        bail!("no secret keys were provided");
    }

    let candidates = parse_candidates(tokens)?;
    let matched_tokens = match_flags(candidates.len());
    let matched_count = AtomicUsize::new(0);

    crack_candidates(&candidates, &keys, workers, &matched_tokens, &matched_count)
        .map(|result| result.matches)
}

pub fn crack_reporting<F>(
    tokens: Vec<String>,
    keys: SecretKeyBatch,
    workers: usize,
    on_match: F,
) -> Result<CrackStats>
where
    F: Fn(Match) + Sync,
{
    if tokens.is_empty() {
        bail!("no JWT tokens were provided");
    }
    if keys.is_empty() {
        bail!("no secret keys were provided");
    }

    let candidates = parse_candidates(tokens)?;
    let matched_tokens = match_flags(candidates.len());
    let matched_count = AtomicUsize::new(0);
    let key_count = keys.len();
    let stats = crack_candidates_reporting(
        &candidates,
        &keys,
        workers,
        &matched_tokens,
        &matched_count,
        &on_match,
    )?;

    Ok(CrackStats {
        key_count,
        match_count: stats.match_count,
        attempt_count: stats.attempt_count,
    })
}

pub fn crack_with_key_reader<R>(
    tokens: Vec<String>,
    mut reader: R,
    encode_method: EncodeMethod,
    workers: usize,
) -> Result<CrackResult>
where
    R: BufRead,
{
    if tokens.is_empty() {
        bail!("no JWT tokens were provided");
    }

    let candidates = parse_candidates(tokens)?;
    let matched_tokens = match_flags(candidates.len());
    let matched_count = AtomicUsize::new(0);
    let mut line = Vec::new();
    let mut batch = SecretKeyBatch::with_capacity(SECRET_KEY_BATCH_SIZE);
    let mut matches = Vec::new();
    let mut key_count = 0;
    let mut attempt_count = 0;

    loop {
        line.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line)
            .context("failed to read secret key input")?;
        if bytes_read == 0 {
            break;
        }

        if let Some(line) = normalize_secret_key_line(&line) {
            batch.push_encoded(line, encode_method);
        }

        if batch.len() == SECRET_KEY_BATCH_SIZE {
            key_count += batch.len();
            let result = crack_candidates(
                &candidates,
                &batch,
                workers,
                &matched_tokens,
                &matched_count,
            )?;
            attempt_count += result.attempt_count;
            matches.extend(result.matches);
            batch.clear();
            if all_tokens_matched(&matched_count, candidates.len()) {
                break;
            }
        }
    }

    if !batch.is_empty() && !all_tokens_matched(&matched_count, candidates.len()) {
        key_count += batch.len();
        let result = crack_candidates(
            &candidates,
            &batch,
            workers,
            &matched_tokens,
            &matched_count,
        )?;
        attempt_count += result.attempt_count;
        matches.extend(result.matches);
    }

    if key_count == 0 {
        bail!("no secret keys were provided");
    }

    Ok(CrackResult {
        matches,
        key_count,
        attempt_count,
    })
}

pub fn crack_with_key_reader_reporting<R, F>(
    tokens: Vec<String>,
    mut reader: R,
    encode_method: EncodeMethod,
    workers: usize,
    on_match: F,
) -> Result<CrackStats>
where
    R: BufRead,
    F: Fn(Match) + Sync,
{
    if tokens.is_empty() {
        bail!("no JWT tokens were provided");
    }

    let candidates = parse_candidates(tokens)?;
    let matched_tokens = match_flags(candidates.len());
    let matched_count = AtomicUsize::new(0);
    let mut line = Vec::new();
    let mut batch = SecretKeyBatch::with_capacity(SECRET_KEY_BATCH_SIZE);
    let mut key_count = 0;
    let mut match_count = 0;
    let mut attempt_count = 0;

    loop {
        line.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line)
            .context("failed to read secret key input")?;
        if bytes_read == 0 {
            break;
        }

        if let Some(line) = normalize_secret_key_line(&line) {
            batch.push_encoded(line, encode_method);
        }

        if batch.len() == SECRET_KEY_BATCH_SIZE {
            key_count += batch.len();
            let stats = crack_candidates_reporting(
                &candidates,
                &batch,
                workers,
                &matched_tokens,
                &matched_count,
                &on_match,
            )?;
            match_count += stats.match_count;
            attempt_count += stats.attempt_count;
            batch.clear();
            if all_tokens_matched(&matched_count, candidates.len()) {
                break;
            }
        }
    }

    if !batch.is_empty() && !all_tokens_matched(&matched_count, candidates.len()) {
        key_count += batch.len();
        let stats = crack_candidates_reporting(
            &candidates,
            &batch,
            workers,
            &matched_tokens,
            &matched_count,
            &on_match,
        )?;
        match_count += stats.match_count;
        attempt_count += stats.attempt_count;
    }

    if key_count == 0 {
        bail!("no secret keys were provided");
    }

    Ok(CrackStats {
        key_count,
        match_count,
        attempt_count,
    })
}

fn parse_candidates(tokens: Vec<String>) -> Result<Vec<JwtCandidate>> {
    tokens
        .into_iter()
        .map(parse_jwt)
        .collect::<Result<Vec<_>>>()
}

fn match_flags(token_count: usize) -> Vec<AtomicBool> {
    (0..token_count).map(|_| AtomicBool::new(false)).collect()
}

fn all_tokens_matched(matched_count: &AtomicUsize, token_count: usize) -> bool {
    matched_count.load(Ordering::Relaxed) >= token_count
}

fn crack_candidates(
    candidates: &[JwtCandidate],
    keys: &SecretKeyBatch,
    workers: usize,
    matched_tokens: &[AtomicBool],
    matched_count: &AtomicUsize,
) -> Result<BatchResult> {
    if keys.is_empty() {
        bail!("no secret keys were provided");
    }

    let workers = workers.max(1).min(keys.len());
    if workers == 1 {
        return Ok(crack_key_range(
            candidates,
            keys,
            matched_tokens,
            matched_count,
            0,
            keys.len(),
        ));
    }

    let chunk_size = keys.len().div_ceil(workers);

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);

        for worker_index in 0..workers {
            let start = worker_index * chunk_size;
            let end = ((worker_index + 1) * chunk_size).min(keys.len());
            if start >= end {
                continue;
            }

            let candidates = &candidates;
            let keys = &keys;
            let matched_tokens = &matched_tokens;
            let matched_count = &matched_count;
            handles.push(scope.spawn(move || {
                crack_key_range(candidates, keys, matched_tokens, matched_count, start, end)
            }));
        }

        let mut matches = Vec::new();
        let mut attempt_count = 0;
        for handle in handles {
            let result = handle
                .join()
                .map_err(|panic| anyhow!("worker thread failed: {}", PanicMessage(panic)))?;
            attempt_count += result.attempt_count;
            matches.extend(result.matches);
        }

        Ok(BatchResult {
            matches,
            attempt_count,
        })
    })
}

fn crack_candidates_reporting<F>(
    candidates: &[JwtCandidate],
    keys: &SecretKeyBatch,
    workers: usize,
    matched_tokens: &[AtomicBool],
    matched_count: &AtomicUsize,
    on_match: &F,
) -> Result<BatchStats>
where
    F: Fn(Match) + Sync,
{
    if keys.is_empty() {
        bail!("no secret keys were provided");
    }

    let workers = workers.max(1).min(keys.len());
    if workers == 1 {
        return Ok(crack_key_range_reporting(
            candidates,
            keys,
            matched_tokens,
            matched_count,
            0,
            keys.len(),
            on_match,
        ));
    }

    let chunk_size = keys.len().div_ceil(workers);

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);

        for worker_index in 0..workers {
            let start = worker_index * chunk_size;
            let end = ((worker_index + 1) * chunk_size).min(keys.len());
            if start >= end {
                continue;
            }

            let candidates = &candidates;
            let keys = &keys;
            let matched_tokens = &matched_tokens;
            let matched_count = &matched_count;
            handles.push(scope.spawn(move || {
                crack_key_range_reporting(
                    candidates,
                    keys,
                    matched_tokens,
                    matched_count,
                    start,
                    end,
                    on_match,
                )
            }));
        }

        let mut match_count = 0;
        let mut attempt_count = 0;
        for handle in handles {
            let stats = handle
                .join()
                .map_err(|panic| anyhow!("worker thread failed: {}", PanicMessage(panic)))?;
            match_count += stats.match_count;
            attempt_count += stats.attempt_count;
        }

        Ok(BatchStats {
            match_count,
            attempt_count,
        })
    })
}

fn crack_key_range(
    candidates: &[JwtCandidate],
    keys: &SecretKeyBatch,
    matched_tokens: &[AtomicBool],
    matched_count: &AtomicUsize,
    start: usize,
    end: usize,
) -> BatchResult {
    let mut matches = Vec::new();
    let mut attempt_count = 0;

    for key_index in start..end {
        if all_tokens_matched(matched_count, candidates.len()) {
            break;
        }
        let key = keys.key(key_index);
        attempt_count +=
            crack_key_candidates(key, candidates, matched_tokens, matched_count, &mut matches);
    }

    BatchResult {
        matches,
        attempt_count,
    }
}

fn crack_key_range_reporting<F>(
    candidates: &[JwtCandidate],
    keys: &SecretKeyBatch,
    matched_tokens: &[AtomicBool],
    matched_count: &AtomicUsize,
    start: usize,
    end: usize,
    on_match: &F,
) -> BatchStats
where
    F: Fn(Match) + Sync,
{
    let mut match_count = 0;
    let mut attempt_count = 0;

    for key_index in start..end {
        if all_tokens_matched(matched_count, candidates.len()) {
            break;
        }
        let key = keys.key(key_index);
        let stats = crack_key_candidates_reporting(
            key,
            candidates,
            matched_tokens,
            matched_count,
            on_match,
        );
        match_count += stats.match_count;
        attempt_count += stats.attempt_count;
    }

    BatchStats {
        match_count,
        attempt_count,
    }
}

fn crack_key_candidates(
    key: SecretKeyRef<'_>,
    candidates: &[JwtCandidate],
    matched_tokens: &[AtomicBool],
    matched_count: &AtomicUsize,
    matches: &mut Vec<Match>,
) -> usize {
    let mut attempt_count = 0;

    let mut hs256 = None;
    let mut hs384 = None;
    let mut hs512 = None;

    for (token_index, candidate) in candidates.iter().enumerate() {
        let matched_token = &matched_tokens[token_index];
        if matched_token.load(Ordering::Relaxed) {
            continue;
        }

        let verified = match candidate.alg {
            Algorithm::Hs256 => {
                let mac = hs256.get_or_insert_with(|| {
                    Hmac::<Sha256>::new_from_slice(key.as_bytes())
                        .expect("HMAC accepts keys of any length")
                });
                verify_hmac_sha256(candidate, mac.clone())
            }
            Algorithm::Hs384 => {
                let mac = hs384.get_or_insert_with(|| {
                    Hmac::<Sha384>::new_from_slice(key.as_bytes())
                        .expect("HMAC accepts keys of any length")
                });
                verify_hmac_sha384(candidate, mac.clone())
            }
            Algorithm::Hs512 => {
                let mac = hs512.get_or_insert_with(|| {
                    Hmac::<Sha512>::new_from_slice(key.as_bytes())
                        .expect("HMAC accepts keys of any length")
                });
                verify_hmac_sha512(candidate, mac.clone())
            }
        };
        attempt_count += 1;

        if verified
            && matched_token
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let new_match_count = matched_count.fetch_add(1, Ordering::Relaxed) + 1;
            matches.push(Match {
                token: candidate.original.clone(),
                key: key.display_lossy(),
            });
            if new_match_count >= candidates.len() {
                break;
            }
        }
    }

    attempt_count
}

fn crack_key_candidates_reporting<F>(
    key: SecretKeyRef<'_>,
    candidates: &[JwtCandidate],
    matched_tokens: &[AtomicBool],
    matched_count: &AtomicUsize,
    on_match: &F,
) -> BatchStats
where
    F: Fn(Match) + Sync,
{
    let mut match_count = 0;
    let mut attempt_count = 0;

    let mut hs256 = None;
    let mut hs384 = None;
    let mut hs512 = None;

    for (token_index, candidate) in candidates.iter().enumerate() {
        let matched_token = &matched_tokens[token_index];
        if matched_token.load(Ordering::Relaxed) {
            continue;
        }

        let verified = match candidate.alg {
            Algorithm::Hs256 => {
                let mac = hs256.get_or_insert_with(|| {
                    Hmac::<Sha256>::new_from_slice(key.as_bytes())
                        .expect("HMAC accepts keys of any length")
                });
                verify_hmac_sha256(candidate, mac.clone())
            }
            Algorithm::Hs384 => {
                let mac = hs384.get_or_insert_with(|| {
                    Hmac::<Sha384>::new_from_slice(key.as_bytes())
                        .expect("HMAC accepts keys of any length")
                });
                verify_hmac_sha384(candidate, mac.clone())
            }
            Algorithm::Hs512 => {
                let mac = hs512.get_or_insert_with(|| {
                    Hmac::<Sha512>::new_from_slice(key.as_bytes())
                        .expect("HMAC accepts keys of any length")
                });
                verify_hmac_sha512(candidate, mac.clone())
            }
        };
        attempt_count += 1;

        if verified
            && matched_token
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let new_match_count = matched_count.fetch_add(1, Ordering::Relaxed) + 1;
            match_count += 1;
            on_match(Match {
                token: candidate.original.clone(),
                key: key.display_lossy(),
            });
            if new_match_count >= candidates.len() {
                break;
            }
        }
    }

    BatchStats {
        match_count,
        attempt_count,
    }
}

fn parse_text_lines(input: &str) -> Vec<String> {
    let mut values = Vec::with_capacity(input.lines().count());
    values.extend(
        input
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned),
    );
    values
}

fn parse_secret_key_lines(input: &[u8], encode_method: EncodeMethod) -> SecretKeyBatch {
    let line_count =
        input.iter().filter(|byte| **byte == b'\n').count() + usize::from(!input.is_empty());
    let mut keys = SecretKeyBatch::with_capacity(line_count);
    for line in input
        .split(|byte| *byte == b'\n')
        .filter_map(normalize_secret_key_line)
    {
        keys.push_encoded(line, encode_method);
    }
    keys
}

fn normalize_secret_key_line(line: &[u8]) -> Option<&[u8]> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    (!line.is_empty()).then_some(line)
}

fn parse_jwt(token: String) -> Result<JwtCandidate> {
    let mut parts = token.split('.');
    let header = parts
        .next()
        .ok_or_else(|| anyhow!("invalid JWT `{token}`: missing header"))?;
    let payload = parts
        .next()
        .ok_or_else(|| anyhow!("invalid JWT `{token}`: missing payload"))?;
    let signature = parts
        .next()
        .ok_or_else(|| anyhow!("invalid JWT `{token}`: missing signature"))?;

    if parts.next().is_some() {
        bail!("invalid JWT `{token}`: too many segments");
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header)
        .with_context(|| format!("invalid JWT `{token}`: header is not base64url"))?;
    let header_json: JwtHeader = serde_json::from_slice(&header_bytes)
        .with_context(|| format!("invalid JWT `{token}`: header is not valid JSON"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .with_context(|| format!("invalid JWT `{token}`: signature is not base64url"))?;
    let signing_input = format!("{header}.{payload}");

    Ok(JwtCandidate {
        original: token,
        signing_input,
        signature,
        alg: Algorithm::from_name(&header_json.alg)?,
    })
}

fn verify_hmac_sha256(candidate: &JwtCandidate, mut mac: Hmac<Sha256>) -> bool {
    mac.update(candidate.signing_input.as_bytes());
    mac.verify_slice(&candidate.signature).is_ok()
}

fn verify_hmac_sha384(candidate: &JwtCandidate, mut mac: Hmac<Sha384>) -> bool {
    mac.update(candidate.signing_input.as_bytes());
    mac.verify_slice(&candidate.signature).is_ok()
}

fn verify_hmac_sha512(candidate: &JwtCandidate, mut mac: Hmac<Sha512>) -> bool {
    mac.update(candidate.signing_input.as_bytes());
    mac.verify_slice(&candidate.signature).is_ok()
}

struct PanicMessage(Box<dyn std::any::Any + Send>);

impl fmt::Display for PanicMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(message) = self.0.downcast_ref::<&str>() {
            formatter.write_str(message)
        } else if let Some(message) = self.0.downcast_ref::<String>() {
            formatter.write_str(message)
        } else {
            formatter.write_str("unknown panic")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
        SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn direct_argument_is_loaded_as_single_value() {
        let list = load_token_values("token", None, "JWT token").expect("direct input should load");
        assert_eq!(list.values, vec!["token"]);
        assert_eq!(list.source, InputSource::Direct);
    }

    #[test]
    fn stdin_lines_are_trimmed_and_empty_lines_are_ignored() {
        let list = load_token_values("-", Some(b" first\n\n second \n"), "JWT token")
            .expect("stdin input should load");
        assert_eq!(list.values, vec!["first", "second"]);
        assert_eq!(list.source, InputSource::Stdin);
    }

    #[test]
    fn existing_file_argument_is_loaded_line_by_line() {
        let path = std::env::temp_dir().join(format!(
            "jwt_cracker_keys_{}_{}.txt",
            std::process::id(),
            "line_input"
        ));
        std::fs::write(&path, "alpha\n\n beta \n").expect("fixture file should be written");

        let list = load_token_values(
            path.to_str().expect("temp path should be valid UTF-8"),
            None,
            "JWT token",
        )
        .expect("file input should load");

        std::fs::remove_file(path).expect("fixture file should be removed");
        assert_eq!(list.values, vec!["alpha", "beta"]);
        assert!(matches!(list.source, InputSource::File(_)));
    }

    #[test]
    fn secret_key_file_allows_non_utf8_lines() {
        let path = std::env::temp_dir().join(format!(
            "jwt_cracker_keys_{}_{}.txt",
            std::process::id(),
            "bytes_input"
        ));
        std::fs::write(&path, b"alpha\n\xffbeta\r\n").expect("fixture file should be written");

        let list = load_secret_keys(
            path.to_str().expect("temp path should be valid UTF-8"),
            None,
            "secret key",
            EncodeMethod::None,
        )
        .expect("byte-oriented file input should load");

        std::fs::remove_file(path).expect("fixture file should be removed");
        assert_eq!(list.values.key(0).as_bytes(), b"alpha");
        assert_eq!(list.values.key(1).as_bytes(), b"\xffbeta");
        assert!(matches!(list.source, InputSource::File(_)));
    }

    #[test]
    fn secret_keys_can_be_encoded_before_cracking() {
        let base64 = load_secret_keys("hello", None, "secret key", EncodeMethod::Base64)
            .expect("base64 key should load");
        assert_eq!(base64.values.key(0).as_bytes(), b"aGVsbG8=");

        let md5 = load_secret_keys("hello", None, "secret key", EncodeMethod::Md5)
            .expect("md5 key should load");
        assert_eq!(
            md5.values.key(0).as_bytes(),
            b"5d41402abc4b2a76b9719d911017c592"
        );

        let md5_len16 = load_secret_keys("hello", None, "secret key", EncodeMethod::Md5Len16)
            .expect("md5_len16 key should load");
        assert_eq!(md5_len16.values.key(0).as_bytes(), b"bc4b2a76b9719d91");
    }

    #[test]
    fn hs256_token_is_cracked_across_key_ranges() {
        let tokens = vec![HS256_TOKEN.replace(['\n', ' '], "")];
        let keys = SecretKeyBatch::from_keys(["wrong", "your-256-bit-secret"]);

        let matches = crack(tokens.clone(), keys, 2).expect("cracking should complete");

        assert_eq!(
            matches,
            vec![Match {
                token: tokens[0].clone(),
                key: "your-256-bit-secret".to_owned()
            }]
        );
    }

    #[test]
    fn cracking_handles_key_ranges_with_multiple_tokens() {
        let token = HS256_TOKEN.replace(['\n', ' '], "");
        let tokens = vec![token.clone(), token.clone()];
        let keys = SecretKeyBatch::from_keys(["wrong-1", "your-256-bit-secret", "wrong-2"]);

        let matches = crack(tokens, keys, 4).expect("cracking should complete");

        assert_eq!(
            matches,
            vec![
                Match {
                    token: token.clone(),
                    key: "your-256-bit-secret".to_owned()
                },
                Match {
                    token,
                    key: "your-256-bit-secret".to_owned()
                }
            ]
        );
    }

    #[test]
    fn streaming_key_reader_cracks_without_loading_all_keys_at_once() {
        let token = HS256_TOKEN.replace(['\n', ' '], "");
        let keys = std::io::Cursor::new(b"wrong\nanother-wrong\nyour-256-bit-secret\n");

        let result = crack_with_key_reader(vec![token.clone()], keys, EncodeMethod::None, 1)
            .expect("streaming cracking should complete");

        assert_eq!(result.key_count, 3);
        assert_eq!(result.attempt_count, 3);
        assert_eq!(
            result.matches,
            vec![Match {
                token,
                key: "your-256-bit-secret".to_owned()
            }]
        );
    }

    #[test]
    fn streaming_key_reader_stops_after_all_tokens_match() {
        let token = HS256_TOKEN.replace(['\n', ' '], "");
        let mut keys = Vec::new();
        keys.extend_from_slice(b"your-256-bit-secret\n");
        for _ in 1..SECRET_KEY_BATCH_SIZE {
            keys.extend_from_slice(b"wrong\n");
        }
        keys.extend_from_slice(b"unread-after-match\n");

        let result = crack_with_key_reader(
            vec![token.clone()],
            std::io::Cursor::new(keys),
            EncodeMethod::None,
            1,
        )
        .expect("streaming cracking should complete");

        assert_eq!(result.key_count, SECRET_KEY_BATCH_SIZE);
        assert_eq!(result.attempt_count, 1);
        assert_eq!(
            result.matches,
            vec![Match {
                token,
                key: "your-256-bit-secret".to_owned()
            }]
        );
    }

    #[test]
    fn reporting_cracker_emits_matches_during_cracking() {
        let token = HS256_TOKEN.replace(['\n', ' '], "");
        let keys = SecretKeyBatch::from_keys(["wrong", "your-256-bit-secret"]);
        let reported = std::sync::Mutex::new(Vec::new());

        let stats = crack_reporting(vec![token.clone()], keys, 1, |found| {
            reported
                .lock()
                .expect("reported matches lock should not be poisoned")
                .push(found);
        })
        .expect("reporting cracking should complete");

        assert_eq!(
            stats,
            CrackStats {
                key_count: 2,
                match_count: 1,
                attempt_count: 2
            }
        );
        assert_eq!(
            *reported
                .lock()
                .expect("reported matches lock should not be poisoned"),
            vec![Match {
                token,
                key: "your-256-bit-secret".to_owned()
            }]
        );
    }

    #[test]
    fn cracking_stops_trying_keys_for_a_token_after_match() {
        let token = HS256_TOKEN.replace(['\n', ' '], "");
        let keys =
            SecretKeyBatch::from_keys(["wrong", "your-256-bit-secret", "your-256-bit-secret"]);

        let stats = crack_reporting(vec![token.clone()], keys, 1, |_| {})
            .expect("reporting cracking should complete");

        assert_eq!(
            stats,
            CrackStats {
                key_count: 3,
                match_count: 1,
                attempt_count: 2
            }
        );
    }
}
