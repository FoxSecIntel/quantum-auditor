# quantum-auditor

Standalone post-quantum security auditor for remote HTTPS targets.

`quantum-auditor` performs an external Quantum Risk Audit over port 443 only. It does not require local host access, credentials, or agents on the target server.

## Features

- Non-blocking TCP and TLS handshake using Python `socket` and `ssl`
- Certificate parsing with `cryptography.x509`
- CLI interface with `click`
- Barbell strategy checks:
  - Safe anchor: TLS hygiene checks
    - Certificate expiry
    - Revocation metadata signals (OCSP and CRL references)
    - TLS 1.0 and TLS 1.1 acceptance checks
  - Spec risk: post-quantum failings
    - HNDL risk: flags missing hybrid PQC key exchange signals
    - Grover risk: flags AES-128 as MEDIUM and recommends AES-256
    - Shor risk: flags RSA below 3072 bits and standard ECC as HIGH
- Structured terminal table with:
  - Field
  - Current State
  - Quantum Status
  - Remediation
  - Risk band (Immediate, Transition, Long-term)
- JSON output mode for automation and CI pipelines
- Optional TLS trust controls for test environments:
  - `--insecure` for temporary validation bypass
  - `--cafile` for custom CA bundle trust

## Requirements

- Python 3.10+

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
./pqc-audit.py --url https://example.com
```

Optional flags:

```bash
./pqc-audit.py --timeout 8
./pqc-audit.py --json
./pqc-audit.py --skip-legacy-probe
./pqc-audit.py --cafile /path/to/ca-bundle.pem
./pqc-audit.py --insecure
./pqc-audit.py --remediation-guide
./pqc-audit.py --help
```

## Sample output

```text
Quantum Risk Audit Report
Target: https://example.com
Resolved IP: 104.18.26.120
Port: 443
...
```

## Remediation Guide

A built-in remediation guide is available in the help flow:

```bash
./pqc-audit.py --remediation-guide
```

## Notes

- The HNDL check relies on negotiated cipher naming heuristics and known PQC hybrid markers.
- Public web PKI currently uses classical signatures, so certificate checks focus on migration risk visibility.
- Results represent a point-in-time external posture of the tested endpoint.

## Licence

MIT (recommended). Add a `LICENSE` file if you want explicit licensing.
