#!/usr/bin/env python3
"""
Standalone Post-Quantum Security Auditor

Run with:
  ./pqc-audit.py --url https://example.com
"""

from __future__ import annotations

import datetime as dt
import json
import socket
import ssl
import sys
import textwrap
import warnings
from dataclasses import asdict, dataclass
from select import select
from typing import Any, Optional
from urllib.parse import urlparse

import click
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa


PQC_KEYWORDS = (
    "MLKEM",
    "ML-KEM",
    "KYBER",
    "X25519MLKEM",
    "X25519_KYBER",
    "X25519KYBER",
)

REMEDIATION_GUIDE = """
Remediation Guide

1) HNDL mitigation (Harvest Now, Decrypt Later):
   - Enable hybrid post-quantum key exchange in your TLS terminator.
   - Prioritise NIST standardised ML-KEM based hybrid groups where supported.
   - Validate negotiation with test clients and monitor fallback behaviour.

2) Grover vulnerability mitigation:
   - Prefer AES-256-GCM or ChaCha20-Poly1305 where appropriate.
   - De-prioritise AES-128 in modern policy sets.

3) Shor vulnerability mitigation:
   - Replace RSA keys below 3072 bits.
   - Replace legacy ECC curves with stronger migration plans and PQC transition.

4) General TLS hygiene:
   - Disable TLS 1.0 and TLS 1.1.
   - Keep certificate rotation short and automated.
   - Publish OCSP and CRL endpoints and monitor their availability.
""".strip()


@dataclass
class AuditRow:
    field: str
    current_state: str
    quantum_status: str
    remediation: str
    risk_band: str


@dataclass
class TlsSnapshot:
    host: str
    port: int
    ip: str
    tls_version: str
    cipher_name: str
    cert_der: bytes


def normalise_target(url: str) -> tuple[str, int, str]:
    candidate = url if "://" in url else f"https://{url}"
    parsed = urlparse(candidate)

    if parsed.scheme not in ("https", ""):
        raise click.ClickException("Only HTTPS targets are supported.")

    host = parsed.hostname
    if not host:
        raise click.ClickException("Could not parse host from URL.")

    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise click.ClickException(f"Host IDNA normalisation failed for {host}: {exc}") from exc

    port = parsed.port or 443
    return host_ascii, port, host


def resolve_host(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for info in infos:
            af, _, _, _, sa = info
            if af in (socket.AF_INET, socket.AF_INET6):
                return sa[0]
    except socket.gaierror as exc:
        raise click.ClickException(f"DNS resolution failed for {host}: {exc}") from exc
    raise click.ClickException(f"No usable IP address resolved for {host}.")


def open_tcp_non_blocking(host: str, port: int, timeout: float) -> socket.socket:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not infos:
        raise click.ClickException(f"No TCP socket candidates found for {host}:{port}.")

    last_error: Optional[str] = None
    for af, socktype, proto, _, sa in infos:
        sock = socket.socket(af, socktype, proto)
        sock.setblocking(False)
        err = sock.connect_ex(sa)

        in_progress = {0, 115, 10035}
        if err not in in_progress:
            last_error = f"errno {err}"
            sock.close()
            continue

        _, writable, _ = select([], [sock], [], timeout)
        if not writable:
            last_error = "TCP connection timed out"
            sock.close()
            continue

        so_error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if so_error != 0:
            last_error = f"TCP socket error {so_error}"
            sock.close()
            continue

        return sock

    raise click.ClickException(f"TCP connection failed for {host}:{port}: {last_error}")


def build_context(insecure: bool, cafile: Optional[str]) -> ssl.SSLContext:
    if insecure:
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        return ctx

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    else:
        ctx.load_default_certs()
    return ctx


def do_tls_handshake_non_blocking(
    raw_sock: socket.socket,
    host: str,
    timeout: float,
    context: ssl.SSLContext,
    min_version: Optional[ssl.TLSVersion] = None,
    max_version: Optional[ssl.TLSVersion] = None,
) -> ssl.SSLSocket:
    if min_version:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = min_version
    if max_version:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.maximum_version = max_version

    tls_sock = context.wrap_socket(raw_sock, server_hostname=host, do_handshake_on_connect=False)
    tls_sock.setblocking(False)
    deadline = dt.datetime.now(dt.timezone.utc).timestamp() + timeout

    while True:
        try:
            tls_sock.do_handshake()
            return tls_sock
        except ssl.SSLWantReadError:
            remaining = deadline - dt.datetime.now(dt.timezone.utc).timestamp()
            if remaining <= 0:
                tls_sock.close()
                raise click.ClickException("TLS handshake timed out while waiting for read.")
            select([tls_sock], [], [], remaining)
        except ssl.SSLWantWriteError:
            remaining = deadline - dt.datetime.now(dt.timezone.utc).timestamp()
            if remaining <= 0:
                tls_sock.close()
                raise click.ClickException("TLS handshake timed out while waiting for write.")
            select([], [tls_sock], [], remaining)
        except ssl.SSLError as exc:
            tls_sock.close()
            raise click.ClickException(f"TLS handshake failed: {exc}") from exc


def capture_tls_snapshot(host: str, port: int, timeout: float, insecure: bool, cafile: Optional[str]) -> TlsSnapshot:
    ip = resolve_host(host)
    raw = open_tcp_non_blocking(ip, port, timeout)

    try:
        tls = do_tls_handshake_non_blocking(raw, host, timeout, build_context(insecure, cafile))
        cipher_tuple = tls.cipher() or ("Unknown", "", 0)
        cert = tls.getpeercert(binary_form=True)
        version = tls.version() or "Unknown"
        tls.close()
    finally:
        try:
            raw.close()
        except OSError:
            pass

    if not cert:
        raise click.ClickException("No peer certificate received.")

    return TlsSnapshot(host=host, port=port, ip=ip, tls_version=version, cipher_name=cipher_tuple[0], cert_der=cert)


def supports_legacy_version(
    host: str,
    ip: str,
    port: int,
    version: ssl.TLSVersion,
    timeout: float,
    insecure: bool,
    cafile: Optional[str],
) -> bool:
    raw = open_tcp_non_blocking(ip, port, timeout)
    try:
        tls = do_tls_handshake_non_blocking(
            raw,
            host,
            timeout,
            build_context(insecure, cafile),
            min_version=version,
            max_version=version,
        )
        tls.close()
        return True
    except click.ClickException:
        return False
    finally:
        try:
            raw.close()
        except OSError:
            pass


def parse_certificate(cert_der: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(cert_der)
    except ValueError as exc:
        raise click.ClickException(f"Certificate parsing failed: {exc}") from exc


def assess_hndl(cipher_name: str) -> AuditRow:
    upper = cipher_name.upper()
    if any(token in upper for token in PQC_KEYWORDS):
        return AuditRow(
            field="Key Exchange",
            current_state=f"{cipher_name} (cipher naming signal)",
            quantum_status="Lower HNDL exposure signal observed",
            remediation="Maintain ML-KEM or Kyber hybrid preference order",
            risk_band="Transition",
        )

    return AuditRow(
        field="Key Exchange",
        current_state=f"{cipher_name} (no hybrid marker in cipher name)",
        quantum_status="CRITICAL: Vulnerable to HNDL under current policy",
        remediation="Enable hybrid ML-KEM or Kyber key exchange and verify with TLS group-aware tooling",
        risk_band="Immediate",
    )


def assess_grover(cipher_name: str) -> AuditRow:
    name = cipher_name.upper()
    if "AES128" in name or "AES_128" in name:
        return AuditRow(
            field="Symmetric Strength",
            current_state="AES-128 negotiated",
            quantum_status="MEDIUM: Grover effective strength reduction",
            remediation="Prioritise AES-256 suites in TLS policy",
            risk_band="Transition",
        )

    if "AES256" in name or "AES_256" in name:
        return AuditRow(
            field="Symmetric Strength",
            current_state="AES-256 negotiated",
            quantum_status="Stronger posture",
            remediation="Keep AES-256 prioritised",
            risk_band="Long-term",
        )

    if "CHACHA20" in name:
        return AuditRow(
            field="Symmetric Strength",
            current_state="ChaCha20-Poly1305 negotiated",
            quantum_status="Generally robust modern choice",
            remediation="Keep modern AEAD priority with AES-256 where practical",
            risk_band="Long-term",
        )

    return AuditRow(
        field="Symmetric Strength",
        current_state=cipher_name,
        quantum_status="Unknown strength profile",
        remediation="Review cipher policy and prefer AES-256 or ChaCha20",
        risk_band="Transition",
    )


def assess_shor(cert: x509.Certificate) -> AuditRow:
    pub = cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        bits = pub.key_size
        if bits < 3072:
            return AuditRow(
                field="Certificate Public Key",
                current_state=f"RSA {bits}",
                quantum_status="HIGH: Shor vulnerable and below 3072-bit target",
                remediation="Issue certificate with RSA 3072+ and define a PQ migration strategy",
                risk_band="Immediate",
            )
        return AuditRow(
            field="Certificate Public Key",
            current_state=f"RSA {bits}",
            quantum_status="Classical baseline improved, still Shor vulnerable",
            remediation="Plan PQ-safe certificate migration track",
            risk_band="Long-term",
        )

    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve_name = pub.curve.name
        bits = pub.key_size
        status = "HIGH: Standard ECC is Shor vulnerable"
        if curve_name.lower() in {"secp256r1", "prime256v1"}:
            status = "HIGH: P-256 is Shor vulnerable"
        return AuditRow(
            field="Certificate Public Key",
            current_state=f"ECC {curve_name} ({bits} bits)",
            quantum_status=status,
            remediation="Prepare PQ certificate and signature migration roadmap",
            risk_band="Long-term",
        )

    return AuditRow(
        field="Certificate Public Key",
        current_state=pub.__class__.__name__,
        quantum_status="Unknown algorithm type",
        remediation="Validate certificate key algorithm against PQ migration plan",
        risk_band="Transition",
    )


def assess_tls_health(cert: x509.Certificate, tls_version: str, weak_tls10: bool, weak_tls11: bool) -> list[AuditRow]:
    rows: list[AuditRow] = []

    now = dt.datetime.now(dt.timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        legacy_not_after = cert.not_valid_after
        not_after = legacy_not_after.replace(tzinfo=dt.timezone.utc) if legacy_not_after.tzinfo is None else legacy_not_after.astimezone(dt.timezone.utc)
    days_remaining = (not_after - now).days

    if days_remaining < 0:
        rows.append(AuditRow("Certificate Expiry", f"Expires {not_after.isoformat()} ({days_remaining} days)", "CRITICAL: Certificate expired", "Renew certificate immediately", "Immediate"))
    elif days_remaining <= 30:
        rows.append(AuditRow("Certificate Expiry", f"Expires {not_after.isoformat()} ({days_remaining} days)", "HIGH: Certificate near expiry", "Renew within current change window", "Immediate"))
    else:
        rows.append(AuditRow("Certificate Expiry", f"Expires {not_after.isoformat()} ({days_remaining} days)", "Healthy validity window", "Maintain automated rotation", "Long-term"))

    weak_versions = []
    if weak_tls10:
        weak_versions.append("TLS 1.0")
    if weak_tls11:
        weak_versions.append("TLS 1.1")

    if weak_versions:
        rows.append(
            AuditRow(
                field="TLS Versions",
                current_state=f"Legacy protocol support detected: {', '.join(weak_versions)}",
                quantum_status="HIGH: Legacy protocol exposure",
                remediation="Disable TLS 1.0 and TLS 1.1 on all endpoints",
                risk_band="Immediate",
            )
        )
    else:
        rows.append(
            AuditRow(
                field="TLS Versions",
                current_state=f"Negotiated {tls_version}; no TLS 1.0 or 1.1 acceptance observed",
                quantum_status="Modern baseline observed",
                remediation="Continue version hardening and periodic verification",
                risk_band="Long-term",
            )
        )

    has_ocsp = False
    has_crl = False
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        has_ocsp = any(desc.access_method == x509.AuthorityInformationAccessOID.OCSP for desc in aia)
    except x509.ExtensionNotFound:
        pass

    try:
        crl = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        has_crl = len(crl) > 0
    except x509.ExtensionNotFound:
        pass

    if has_ocsp or has_crl:
        refs = []
        if has_ocsp:
            refs.append("OCSP")
        if has_crl:
            refs.append("CRL")
        rows.append(
            AuditRow(
                field="Revocation Signals",
                current_state=f"Certificate publishes {', '.join(refs)} references",
                quantum_status="Metadata present, active revocation check not performed",
                remediation="Ensure responders are reachable and monitored",
                risk_band="Transition",
            )
        )
    else:
        rows.append(
            AuditRow(
                field="Revocation Signals",
                current_state="No OCSP or CRL distribution points found",
                quantum_status="MEDIUM: Weak revocation ecosystem signalling",
                remediation="Publish OCSP and or CRL endpoints in certificate profile",
                risk_band="Transition",
            )
        )

    return rows


def render_table(target: str, original_host: str, snapshot: TlsSnapshot, rows: list[AuditRow]) -> None:
    click.echo("Quantum Risk Audit Report")
    click.echo(f"Target: {target}")
    click.echo(f"Host: {original_host}")
    click.echo(f"Resolved IP: {snapshot.ip}")
    click.echo(f"Port: {snapshot.port}")
    click.echo("")

    headers = ("Field", "Current State", "Quantum Status", "Remediation")
    width = [22, 44, 44, 52]

    def line(char: str = "-") -> str:
        return "+" + "+".join(char * (w + 2) for w in width) + "+"

    def render_row(values: tuple[str, str, str, str]) -> list[str]:
        wrapped = [textwrap.wrap(v, width=w) or [""] for v, w in zip(values, width)]
        h = max(len(c) for c in wrapped)
        out: list[str] = []
        for i in range(h):
            cols = []
            for col, w in zip(wrapped, width):
                val = col[i] if i < len(col) else ""
                cols.append(f" {val.ljust(w)} ")
            out.append("|" + "|".join(cols) + "|")
        return out

    click.echo(line("="))
    for ln in render_row(headers):
        click.echo(ln)
    click.echo(line("="))
    for row in rows:
        for ln in render_row((row.field, row.current_state, f"[{row.risk_band}] {row.quantum_status}", row.remediation)):
            click.echo(ln)
        click.echo(line())


def build_json(target: str, original_host: str, snapshot: TlsSnapshot, rows: list[AuditRow], assumptions: list[str]) -> dict[str, Any]:
    return {
        "tool": "quantum-auditor",
        "target": target,
        "host": original_host,
        "resolved_ip": snapshot.ip,
        "port": snapshot.port,
        "negotiated_tls_version": snapshot.tls_version,
        "negotiated_cipher": snapshot.cipher_name,
        "assumptions": assumptions,
        "rows": [asdict(r) for r in rows],
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--url", "url", required=False, help="Target URL or host to audit on port 443.")
@click.option("--timeout", default=8.0, show_default=True, type=float, help="Connection timeout in seconds.")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON output.")
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification for testing only.")
@click.option("--cafile", type=click.Path(exists=True, dir_okay=False), help="Custom CA bundle file path.")
@click.option("--skip-legacy-probe", is_flag=True, help="Skip explicit TLS 1.0 and TLS 1.1 probe checks.")
@click.option("--remediation-guide", is_flag=True, help="Show the remediation guide and exit.")
def main(
    url: Optional[str],
    timeout: float,
    json_output: bool,
    insecure: bool,
    cafile: Optional[str],
    skip_legacy_probe: bool,
    remediation_guide: bool,
) -> None:
    """
    Standalone post-quantum remote security auditor.

    This tool performs an external audit against port 443 only.

    Remediation Guide:
      Use --remediation-guide for a complete checklist.
    """
    if remediation_guide:
        click.echo(REMEDIATION_GUIDE)
        return

    if not url:
        raise click.ClickException("Please provide --url <target>.")

    if insecure and cafile:
        raise click.ClickException("Use either --insecure or --cafile, not both.")

    host, port, original_host = normalise_target(url)
    snapshot = capture_tls_snapshot(host, port, timeout, insecure, cafile)
    cert = parse_certificate(snapshot.cert_der)

    if skip_legacy_probe:
        weak_tls10 = False
        weak_tls11 = False
    else:
        weak_tls10 = supports_legacy_version(host, snapshot.ip, port, ssl.TLSVersion.TLSv1, timeout, insecure, cafile)
        weak_tls11 = supports_legacy_version(host, snapshot.ip, port, ssl.TLSVersion.TLSv1_1, timeout, insecure, cafile)

    rows: list[AuditRow] = []
    rows.extend(assess_tls_health(cert, snapshot.tls_version, weak_tls10, weak_tls11))
    rows.append(assess_hndl(snapshot.cipher_name))
    rows.append(assess_grover(snapshot.cipher_name))
    rows.append(assess_shor(cert))

    assumptions = [
        "HNDL assessment uses negotiated cipher naming markers and may miss group-level hybrid negotiation details",
        "Revocation check validates metadata presence only, not live responder status",
    ]

    if json_output:
        click.echo(json.dumps(build_json(url, original_host, snapshot, rows, assumptions), indent=2))
        return

    render_table(url, original_host, snapshot, rows)
    click.echo("Assumptions:")
    for a in assumptions:
        click.echo(f"- {a}")


if __name__ == "__main__":
    try:
        main()
    except click.ClickException as exc:
        click.echo(f"Error: {exc.format_message()}", err=True)
        sys.exit(2)
