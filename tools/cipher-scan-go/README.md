# cipher-scan (Go)

High-performance TLS protocol and cipher negotiation scanner for one or many domains.

## Features

- Positional single-domain input (for example `cipher-scan example.com`)
- Batch input with `-f` or `--file`
- Worker pool concurrency (`--concurrency`, default `20`)
- Context timeout control (`--timeout`, default `8` seconds per domain)
- Protocol handshake attempts for:
  - SSLv3
  - TLS 1.0
  - TLS 1.1
  - TLS 1.2
  - TLS 1.3
- Captures cipher suite and certificate expiry when available
- Output formats:
  - `table` (default)
  - `json`
  - `csv`
  - `html`
- Easter egg: `-m` or `--mando`

## Build

```bash
cd tools/cipher-scan-go
./build.sh
```

## Usage

```bash
./cipher-scan example.com
./cipher-scan --file domains.txt --concurrency 40
./cipher-scan --file domains.txt --output json
./cipher-scan --file domains.txt --output csv
./cipher-scan --file domains.txt --output html
./cipher-scan --mando
```
