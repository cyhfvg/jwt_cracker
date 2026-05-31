# TODO

## Completed

- [x] Implement CLI for JWT token input with `-t, --jwt-token`.
- [x] Implement CLI for secret key input with `-k, --secret-key`.
- [x] Support direct string input for tokens and keys.
- [x] Support line-oriented file input for tokens and keys.
- [x] Support `-` stdin input for either tokens or keys.
- [x] Read secret key dictionaries as raw bytes to tolerate non-UTF-8 wordlist entries.
- [x] Stream secret key dictionaries in batches instead of loading the full file into memory.
- [x] Add `-e, --encode-method` for `none`, `base64`, `md5`, and `md5_len16`.
- [x] Add worker control with `-w, --workers`.
- [x] Split work across the total `token_count * key_count` attempt space.
- [x] Show elapsed runtime in the attempt summary.
- [x] Render matched JWT tokens in yellow and matched secret keys in green.
- [x] Stop trying additional secret keys for a token after it has matched.
- [x] Verify HMAC JWT algorithms `HS256`, `HS384`, and `HS512`.
- [x] Keep CLI help text in English.
- [x] Add implementation process documentation in `docs/PROCESS.md`.
- [x] Add integration tests for file input and stdin input through the binary.
- [x] Add release artifacts to the existing release workflow.
- [x] Add benchmark coverage for large token/key dictionaries.
- [x] Add release profile optimizations.

## Follow-Up Ideas

- [ ] Add optional global early-exit mode after the first match.
- [ ] Add JSON output for easier scripting.
