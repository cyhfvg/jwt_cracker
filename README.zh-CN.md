# jwt_cracker

[English README](README.md)

`jwt_cracker` 是一个命令行工具，用于审计 HMAC 签名 JWT 是否使用了弱 secret。它可以将一个或多个 JWT token 与一个或多个候选 secret 进行检测，输入来源可以是直接字符串、文件或 stdin。

## 仅限授权测试使用

请仅在你拥有或被明确授权测试的系统、应用和 token 上使用本工具。不要在未获得书面授权的情况下，对第三方服务、生产系统或用户数据使用 `jwt_cracker`。使用者需要自行确保符合适用法律、组织政策和测试授权范围。

## 功能特性

- 支持 `HS256`、`HS384`、`HS512`。
- JWT token 支持直接字符串、按行文件、stdin 输入。
- secret 候选值支持直接字符串、按行文件、stdin 输入。
- 大型 secret 字典使用流式读取，不需要一次性加载完整文件。
- 支持多 worker 线程提升检测速度。
- 一旦发现匹配结果会立即输出。
- 支持候选值转换：`none`、`base64`、`md5`、`md5_len16`。
- 支持包含非 UTF-8 内容的字典条目。

## 安装

如项目提供 GitHub Releases，可以优先下载预编译二进制文件。

从源码构建：

```bash
git clone <repo-url>
cd jwt_cracker
cargo build --release
```

构建后的二进制文件位于：

```bash
target/release/jwt_cracker
```

## 快速开始

使用一个 token 和一个 secret 进行检测：

```bash
jwt_cracker -t '<jwt-token>' -k 'secret'
```

使用 token 文件和字典文件进行检测：

```bash
jwt_cracker -t ./tokens.txt -k ./wordlist.txt -w 8
```

从 stdin 读取 secret 候选值：

```bash
cat ./wordlist.txt | jwt_cracker -t ./tokens.txt -k - -w 8
```

检测前对候选值进行转换：

```bash
jwt_cracker -t ./tokens.txt -k ./wordlist.txt -e md5_len16 -w 8
```

## 用法

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

## 输入格式

token 文件每行一个 JWT：

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9...
```

secret 文件每行一个候选值：

```text
secret
password
hello_world,hello,rust!
```

`-` 可以用于 token 或 secret 的 stdin 输入，但不能同时用于两者。

## 输出

成功匹配会立即输出：

```text
MATCH token=<jwt> key=<secret>
```

未发现匹配时输出：

```text
No matching secret keys found.
```

进度和最终统计信息会输出到 stderr：

```text
Loaded 1 token(s) from file and 14344400 key(s) from file.
Tested 14344400 total attempt(s) across 8 worker(s) in 3.421s.
```

## 支持的算法

`jwt_cracker` 当前支持 HMAC 签名 JWT：

- `HS256`
- `HS384`
- `HS512`

不支持 `RS256`、`ES256` 等非对称算法。

## 开发

运行测试：

```bash
cargo test
```

运行格式和 lint 检查：

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

运行 benchmark：

```bash
cargo bench
```

## 贡献

欢迎提交 issue 和 pull request。请保持改动聚焦，为面向用户的行为补充测试，并避免提交大型字典或私有 token。

## 致谢

感谢 [alwaystest18/jwtCracker](https://github.com/alwaystest18/jwtCracker) 带来的启发。

## 许可证

本项目使用 [LICENSE](LICENSE) 中声明的许可证。
