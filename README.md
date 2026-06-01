# jwt_cracker

[中文文档](README.zh-CN.md)

`jwt_cracker` is a command-line tool for auditing weak secrets in HMAC-signed JWTs. It can test one or many JWT tokens against one or many candidate secrets from direct input, files, or stdin.

## Hashcat Alternative

The same weak-secret audit can also be performed directly with `hashcat`. Save the JWT token to `jwt.hash`, put candidate secrets in `jwt-secrets.txt`, then run:

```bash
hashcat -m 16500 -a 0 jwt.hash jwt-secrets.txt --status --status-timer=10
```

Show cracked results:

```bash
hashcat -m 16500 jwt.hash --show
```

## Authorized Use Only

Use this tool only on systems, applications, and tokens that you own or have explicit permission to test. Do not use `jwt_cracker` against third-party services, production systems, or user data without written authorization. You are responsible for complying with all applicable laws, policies, and engagement rules.

## Features

- Supports `HS256`, `HS384`, and `HS512`.
- Accepts JWT tokens from a direct string, a line-oriented file, or stdin.
- Accepts secret candidates from a direct string, a line-oriented file, or stdin.
- Streams large secret dictionaries instead of loading the full file into memory.
- Uses multiple worker threads for faster cracking.
- Emits successful matches as soon as they are found.
- Supports optional candidate transforms: `none`, `base64`, `md5`, and `md5_len16`.
- Handles non-UTF-8 dictionary entries.

## Installation

Download a prebuilt binary from the GitHub Releases page when available.

To build from source:

```bash
git clone <repo-url>
cd jwt_cracker
cargo build --release
```

The binary will be available at:

```bash
target/release/jwt_cracker
```

## Quick Start

Test one token with one secret:

```bash
jwt_cracker -t '<jwt-token>' -k 'secret'
```

Test tokens from a file against a dictionary:

```bash
jwt_cracker -t ./tokens.txt -k ./wordlist.txt -w 8
```

Read secret candidates from stdin:

```bash
cat ./wordlist.txt | jwt_cracker -t ./tokens.txt -k - -w 8
```

Apply a candidate transform before testing:

```bash
jwt_cracker -t ./tokens.txt -k ./wordlist.txt -e md5_len16 -w 8
```

## Usage

```text
Usage: jwt_cracker [OPTIONS] --jwt-token <JWT_OR_FILE_OR_STDIN> --secret-key <KEY_OR_FILE_OR_STDIN>

Options:
  -t, --jwt-token <JWT_OR_FILE_OR_STDIN>
          JWT token, path to a line-oriented token file, or '-' to read tokens from stdin

  -k, --secret-key <KEY_OR_FILE_OR_STDIN>
          Secret key, path to a line-oriented key file, or '-' to read keys from stdin

  -e, --encode-method <METHOD>
          Encode each candidate secret before cracking

          [default: none]
          [possible values: none, base64, md5, md5_len16]

  -w, --workers <N>
          Number of worker threads to split the total attempt space across

  -h, --help
          Print help

  -V, --version
          Print version
```

## Input Formats

Token files should contain one JWT per line:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9...
```

Secret files should contain one candidate per line:

```text
secret
password
hello_world,hello,rust!
```

`-` can be used for either tokens or secrets, but not both at the same time.

## Output

Successful matches are printed immediately:

```text
MATCH token=<jwt> key=<secret>
```

When no match is found:

```text
No matching secret keys found.
```

Progress and final attempt statistics are printed to stderr:

```text
Loaded 1 token(s) from file and 14344400 key(s) from file.
Tested 14344400 total attempt(s) across 8 worker(s) in 3.421s.
```

## Supported Algorithms

`jwt_cracker` currently supports HMAC-signed JWTs:

- `HS256`
- `HS384`
- `HS512`

Asymmetric algorithms such as `RS256` and `ES256` are not supported.

## Development

Run the test suite:

```bash
cargo test
```

Run formatting and lint checks:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Run benchmarks:

```bash
cargo bench
```

## Contributing

Issues and pull requests are welcome. Please keep changes focused, include tests for user-facing behavior, and avoid committing large wordlists or private tokens.

## Acknowledgements

Thanks to [alwaystest18/jwtCracker](https://github.com/alwaystest18/jwtCracker) for inspiration.

## License

This project is licensed under the terms in [LICENSE](LICENSE).
