# JWT Cracker Implementation Process

## Scope

The tool is a command-line JWT secret brute-forcer for HMAC signed tokens.

Supported inputs:

- `-t, --jwt-token JWT_OR_FILE_OR_STDIN`: direct JWT string, line-oriented token file, or `-` for stdin.
- `-k, --secret-key KEY_OR_FILE_OR_STDIN`: direct secret key, line-oriented key file, or `-` for stdin.
- `-e, --encode-method METHOD`: encode each candidate secret before cracking.
- `-w, --workers N`: worker thread count.

`-w` is used for workers because `-t` is already assigned to `--jwt-token`.

## Input Handling

Each token/key argument is resolved in this order:

1. `-` reads newline-delimited values from stdin.
2. An existing file path reads newline-delimited values from disk.
3. Any other value is treated as a literal token or key string.

Token input is decoded as UTF-8 text. Blank token lines are ignored and surrounding whitespace is trimmed.

Secret key files and stdin are streamed as raw bytes, split on `\n`, and have a trailing `\r` removed for CRLF files. This allows common password dictionaries to contain non-UTF-8 byte sequences without failing before cracking starts, and avoids loading the full dictionary into memory.

Secret key candidates can be transformed before cracking with `--encode-method`:

- `none`: use the original candidate bytes.
- `base64`: use standard base64 with padding.
- `md5`: use lowercase 32-character MD5 hex.
- `md5_len16`: use characters 8 through 23 of the lowercase MD5 hex digest.

Both token and key cannot read from stdin at the same time, because stdin is a single stream and the tool would not know where token input ends and key input begins.

## JWT Verification

The cracker parses each JWT into:

- header
- payload
- signature
- signing input: `base64url(header).base64url(payload)`

The `alg` field is read from the decoded JWT header. Supported algorithms:

- `HS256`
- `HS384`
- `HS512`

Unsupported algorithms fail fast with an explanatory error.

## Parallelization Model

For an in-memory key set, the implementation treats all attempts as one flat search space:

```text
total_attempts = token_count * key_count
attempt_index -> token_index = attempt_index / key_count
attempt_index -> key_index   = attempt_index % key_count
```

Workers receive contiguous ranges of that total attempt space. This avoids assigning one thread per token and keeps work balanced when token counts and key counts are uneven. Once a token has a successful match, later candidate secrets are skipped for that token.

For streamed dictionaries, keys are read in fixed-size batches. Each batch is still split across the full `token_count * batch_key_count` attempt space and all workers participate in every batch. Token match state is preserved across batches.

## Output

The tool prints progress metadata to stderr and match results to stdout. Successful matches are emitted immediately when workers find them; the final attempt summary is printed after all work completes and includes elapsed runtime for input loading and cracking.

Successful matches use this format:

```text
MATCH token=<jwt> key=<secret>
```

In terminal output, matched JWT tokens are rendered in yellow and matched secret keys are rendered in green.

When no key matches, stdout contains:

```text
No matching secret keys found.
```

## Verification

Implemented checks:

- `cargo test`
- unit test for direct input loading
- unit test for stdin line parsing
- unit test for non-UTF-8 secret key file input
- unit test for base64, md5, and md5_len16 secret key transforms
- unit test for HS256 cracking across multiple workers
- unit test for streaming secret key reader cracking
- unit test for stopping additional key attempts after a token match
- manual `--help` run to confirm English CLI help text
