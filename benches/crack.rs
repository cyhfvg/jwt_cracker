use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use hmac::{Hmac, Mac};
use jwt_cracker::{
    EncodeMethod, SecretKeyBatch, crack, crack_reporting, crack_with_key_reader_reporting,
};
use sha2::Sha256;

const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.\
    mFiqJLxnKmlH9RNt-xVzKeZeIIHsxbsMf4Gveo1FV7w";
const SECRET_KEY: &str = "hello_world,hello,rust!";
const ENCODE_SOURCE: &str = "hello";
const KEY_COUNT: usize = 10_000;
const TOKEN_COUNT: usize = 10;
const WORKERS: usize = 4;

fn bench_crack(c: &mut Criterion) {
    c.bench_function("crack_hs256_in_memory_10k_keys", |b| {
        let token = token();
        let keys = keys(KEY_COUNT);

        b.iter_batched(
            || (vec![token.clone()], keys.clone()),
            |(tokens, keys)| black_box(crack(tokens, keys, WORKERS).expect("cracking should run")),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_reporting_10k_keys", |b| {
        let token = token();
        let keys = keys(KEY_COUNT);

        b.iter_batched(
            || (vec![token.clone()], keys.clone()),
            |(tokens, keys)| {
                black_box(
                    crack_reporting(tokens, keys, WORKERS, |_| {}).expect("cracking should run"),
                )
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_streaming_10k_keys", |b| {
        let token = token();
        let wordlist = wordlist(KEY_COUNT);

        b.iter_batched(
            || (vec![token.clone()], Cursor::new(wordlist.clone())),
            |(tokens, reader)| {
                black_box(
                    crack_with_key_reader_reporting(
                        tokens,
                        reader,
                        EncodeMethod::None,
                        WORKERS,
                        |_| {},
                    )
                    .expect("streaming cracking should run"),
                )
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_streaming_base64_10k_keys", |b| {
        let token = sign_hs256_token(b"aGVsbG8=");
        let wordlist = encoded_wordlist(KEY_COUNT);

        b.iter_batched(
            || (vec![token.clone()], Cursor::new(wordlist.clone())),
            |(tokens, reader)| {
                black_box(
                    crack_with_key_reader_reporting(
                        tokens,
                        reader,
                        EncodeMethod::Base64,
                        WORKERS,
                        |_| {},
                    )
                    .expect("streaming cracking should run"),
                )
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_streaming_md5_10k_keys", |b| {
        let token = sign_hs256_token(b"5d41402abc4b2a76b9719d911017c592");
        let wordlist = encoded_wordlist(KEY_COUNT);

        b.iter_batched(
            || (vec![token.clone()], Cursor::new(wordlist.clone())),
            |(tokens, reader)| {
                black_box(
                    crack_with_key_reader_reporting(
                        tokens,
                        reader,
                        EncodeMethod::Md5,
                        WORKERS,
                        |_| {},
                    )
                    .expect("streaming cracking should run"),
                )
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_streaming_md5_len16_10k_keys", |b| {
        let token = sign_hs256_token(b"bc4b2a76b9719d91");
        let wordlist = encoded_wordlist(KEY_COUNT);

        b.iter_batched(
            || (vec![token.clone()], Cursor::new(wordlist.clone())),
            |(tokens, reader)| {
                black_box(
                    crack_with_key_reader_reporting(
                        tokens,
                        reader,
                        EncodeMethod::Md5Len16,
                        WORKERS,
                        |_| {},
                    )
                    .expect("streaming cracking should run"),
                )
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_in_memory_10_tokens_10k_keys", |b| {
        let tokens = tokens(TOKEN_COUNT);
        let keys = keys(KEY_COUNT);

        b.iter_batched(
            || (tokens.clone(), keys.clone()),
            |(tokens, keys)| black_box(crack(tokens, keys, WORKERS).expect("cracking should run")),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_in_memory_match_at_10_percent", |b| {
        let token = token();
        let keys = keys_with_secret_at(KEY_COUNT, KEY_COUNT / 10);

        b.iter_batched(
            || (vec![token.clone()], keys.clone()),
            |(tokens, keys)| black_box(crack(tokens, keys, WORKERS).expect("cracking should run")),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_in_memory_match_at_50_percent", |b| {
        let token = token();
        let keys = keys_with_secret_at(KEY_COUNT, KEY_COUNT / 2);

        b.iter_batched(
            || (vec![token.clone()], keys.clone()),
            |(tokens, keys)| black_box(crack(tokens, keys, WORKERS).expect("cracking should run")),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("crack_hs256_in_memory_match_at_90_percent", |b| {
        let token = token();
        let keys = keys_with_secret_at(KEY_COUNT, KEY_COUNT * 9 / 10);

        b.iter_batched(
            || (vec![token.clone()], keys.clone()),
            |(tokens, keys)| black_box(crack(tokens, keys, WORKERS).expect("cracking should run")),
            BatchSize::SmallInput,
        );
    });
}

fn token() -> String {
    HS256_TOKEN.replace(['\n', ' '], "")
}

fn tokens(count: usize) -> Vec<String> {
    vec![token(); count]
}

fn keys(count: usize) -> SecretKeyBatch {
    keys_with_secret_at(count, count.saturating_sub(1))
}

fn keys_with_secret_at(count: usize, secret_index: usize) -> SecretKeyBatch {
    let mut keys = SecretKeyBatch::with_capacity(count);
    for index in 0..count {
        if index == secret_index {
            keys.push(SECRET_KEY);
        } else {
            keys.push(format!("wrong-key-{index}"));
        }
    }
    keys
}

fn wordlist(count: usize) -> Vec<u8> {
    let mut wordlist = Vec::new();
    for index in 0..count.saturating_sub(1) {
        wordlist.extend_from_slice(format!("wrong-key-{index}\n").as_bytes());
    }
    wordlist.extend_from_slice(SECRET_KEY.as_bytes());
    wordlist.push(b'\n');
    wordlist
}

fn encoded_wordlist(count: usize) -> Vec<u8> {
    let mut wordlist = Vec::new();
    for index in 0..count.saturating_sub(1) {
        wordlist.extend_from_slice(format!("wrong-key-{index}\n").as_bytes());
    }
    wordlist.extend_from_slice(ENCODE_SOURCE.as_bytes());
    wordlist.push(b'\n');
    wordlist
}

fn sign_hs256_token(secret: &[u8]) -> String {
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}"#;
    let header = URL_SAFE_NO_PAD.encode(header);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{signature}")
}

criterion_group!(benches, bench_crack);
criterion_main!(benches);
