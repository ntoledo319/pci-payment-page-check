#!/usr/bin/env python3
"""Check a payment page's served HTML against the list you authorized.

Standard library only, on purpose. An action that pip-installs is an action
that breaks in somebody's locked-down runner, and a compliance check that
fails to run is worse than no check — it produces a green tick nobody earned.

The hosted service fetches a public URL or inspects the saved HTML explicitly
selected by the workflow. This client never claims to execute JavaScript, read
HTTP response headers, or fetch referenced script bytes.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

TIMEOUT_SECONDS = 60
MAX_HTML_BYTES = 2_000_000
MAX_RESPONSE_BYTES = 4_000_000
MAX_FINDINGS = 1_000
MAX_OUTPUT_UTF16_BYTES = 900_000
MAX_SUMMARY_BYTES = 900_000
MAX_CELL_CHARS = 1_000
MAX_LOG_CHARS = 1_000
DEFAULT_PAGE_ORIGIN = "https://example.invalid/checkout"

# Ordered, so "fail on medium" also fails on high.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
FAIL_THRESHOLDS = {"low", "medium", "high"}
PAYMENT_PAGE_SCOPES = {"unspecified", "direct", "embedded", "outsourced"}
PRODUCT_PATHS = {
    "/checkout/pci",
    "/checkout/pci_ledger",
    "/samples/pci-dss-6-4-3-remediation-pack",
    "/samples/pci-dss-11-6-1-evidence-ledger",
}
SCOPE_GUIDES = {
    "direct": (
        "Build the required script inventory",
        "https://qi.toledotechnologies.com/pci/pci-dss-6-4-3-script-inventory-template",
    ),
    "embedded": (
        "Confirm the SAQ A embedded-form boundary",
        "https://qi.toledotechnologies.com/pci/saq-a-script-security-confirmation",
    ),
    "outsourced": (
        "Confirm the SAQ A redirect and outsourced boundary",
        "https://qi.toledotechnologies.com/pci/saq-a-script-security-confirmation",
    ),
    "unspecified": (
        "Review the bounded PCI payment-page workflow",
        "https://qi.toledotechnologies.com/pci",
    ),
}


def _in(name: str, default: str = "") -> str:
    return (os.environ.get(f"INPUT_{name}") or default).strip()


def _out(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    if not key.replace("-", "").isalnum():
        _fail("An internal output name was invalid.")
    # Multi-line values need the delimiter form or the runner truncates them.
    # A random delimiter prevents a scanned value from terminating the output.
    with open(path, "a", encoding="utf-8") as handle:
        if "\n" in value or "\r" in value:
            delimiter = f"CSI_{secrets.token_hex(16)}"
            while delimiter in value:
                delimiter = f"CSI_{secrets.token_hex(16)}"
            handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            handle.write(f"{key}={value}\n")


def _summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    encoded = markdown.encode("utf-8")
    if len(encoded) > MAX_SUMMARY_BYTES:
        suffix = b"\n\n_Result truncated to the safe GitHub summary limit._"
        encoded = encoded[: MAX_SUMMARY_BYTES - len(suffix)]
        markdown = encoded.decode("utf-8", errors="ignore") + suffix.decode()
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(markdown + "\n")


def _fail(message: str) -> "None":
    clean = " ".join(str(message).splitlines())[:500]
    clean = clean.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title=PCI payment page script check::{clean}")
    sys.exit(1)


def _https_url(value: str, *, label: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError):
        _fail(f"{label} must be a valid https URL.")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        _fail(f"{label} must be a valid https URL without credentials or a custom port.")
    return value


def _read_workspace_html(raw_path: str) -> str:
    root_raw = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
    try:
        root = Path(root_raw).resolve(strict=True)
    except OSError:
        _fail("The workflow workspace could not be resolved.")
    supplied = Path(raw_path)
    if supplied.is_absolute() or ".." in supplied.parts:
        _fail("html-file must be a relative path inside the workflow workspace.")

    current = root
    for part in supplied.parts:
        current = current / part
        if current.is_symlink():
            _fail("html-file must not use a symbolic link.")
    try:
        candidate = (root / supplied).resolve(strict=True)
        candidate.relative_to(root)
    except FileNotFoundError:
        _fail("html-file was not found in the workflow workspace.")
    except (OSError, ValueError):
        _fail("html-file must stay inside the workflow workspace.")
    if not candidate.is_file():
        _fail("html-file must name a regular file.")
    try:
        content = candidate.read_bytes()
    except OSError:
        _fail("html-file could not be read.")
    if len(content) > MAX_HTML_BYTES:
        _fail(f"html-file exceeds the {MAX_HTML_BYTES}-byte limit.")
    try:
        decoded = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail("html-file must be valid UTF-8.")
    if "\x00" in decoded:
        _fail("html-file must not contain NUL bytes.")
    return decoded


def _api_base() -> str:
    base = _in("API_BASE", "https://qi.toledotechnologies.com").rstrip("/")
    try:
        parsed = urlsplit(base)
        loopback_http = parsed.scheme == "http" and parsed.hostname in {
            "127.0.0.1",
            "localhost",
            "::1",
        }
        valid_base = (
            (parsed.scheme == "https" or loopback_http)
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and parsed.path in {"", "/"}
        )
    except (UnicodeError, ValueError):
        valid_base = False
    if not valid_base:
        _fail("api-base must be an https origin (loopback http is allowed for tests).")
    return base


def _safe_product_url(value: object, *, base: str) -> str:
    """Accept only Tessera's exact readiness-gated first-party result paths."""
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or len(value) > 2_048:
        _fail("The check service returned an invalid next-step URL.")
    try:
        parsed = urlsplit(value)
        origin = urlsplit(base)
        port = parsed.port
    except (UnicodeError, ValueError):
        _fail("The check service returned an invalid next-step URL.")
    if parsed.query or parsed.fragment or parsed.path not in PRODUCT_PATHS:
        _fail("The check service returned an unrecognized next-step path.")
    if not parsed.scheme and not parsed.netloc:
        return f"{base}{parsed.path}"
    same_origin = (
        parsed.scheme == origin.scheme
        and parsed.hostname == origin.hostname
        and port == origin.port
        and parsed.username is None
        and parsed.password is None
    )
    if not same_origin:
        _fail("The check service returned a next-step URL on another origin.")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def build_request_body() -> dict:
    url = _in("URL")
    html_file = _in("HTML_FILE")
    if not url and not html_file:
        _fail("Provide either `url` or `html-file`.")
    if url and html_file:
        _fail("Provide `url` or `html-file`, not both.")

    body: dict = {}
    if html_file:
        body["html"] = _read_workspace_html(html_file)
        # The service uses this only to resolve relative script URLs. It does
        # not fetch page-origin when saved HTML was supplied.
        body["url"] = _https_url(
            _in("PAGE_ORIGIN", DEFAULT_PAGE_ORIGIN), label="page-origin"
        )
    else:
        body["url"] = _https_url(url, label="url")

    allowed = [d.strip() for d in _in("ALLOWED_DOMAINS").split(",") if d.strip()]
    if allowed:
        body["allowed_domains"] = allowed
    scope = _in("PAYMENT_PAGE_SCOPE", "unspecified").lower()
    if scope not in PAYMENT_PAGE_SCOPES:
        _fail(
            "payment-page-scope must be unspecified, direct, embedded, or outsourced."
        )
    if scope != "unspecified":
        body["payment_page_scope"] = scope
    return body


def call_service(body: dict) -> dict:
    base = _api_base()
    request = urllib.request.Request(
        f"{base}/api/v1/scan/pci",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "pci-payment-page-check-action/1",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                _fail("The check service response exceeded the safe size limit.")
            decoded = json.loads(
                payload or b"{}",
                parse_constant=_reject_json_constant,
            )
            if not isinstance(decoded, dict):
                _fail("The check service returned an invalid response shape.")
            return decoded
    except urllib.error.HTTPError as exc:
        _fail(f"The check service returned HTTP {exc.code}.")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        _fail("The check service returned invalid JSON.")
    except (OSError, TimeoutError) as exc:
        _fail(f"Could not reach the check service ({type(exc).__name__}).")
    return {}


def _one_line(value: object, *, limit: int = MAX_LOG_CHARS) -> str:
    text = " ".join(str(value).splitlines())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _cell(value: object) -> str:
    text = _one_line(value, limit=MAX_CELL_CHARS)
    for character, replacement in {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "|": "&#124;",
        "`": "&#96;",
        "[": "&#91;",
        "]": "&#93;",
    }.items():
        text = text.replace(character, replacement)
    return text


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def main() -> int:
    body = build_request_body()
    result = call_service(body)
    if result.get("error"):
        _fail(str(result["error"]))

    threshold = _in("FAIL_ON", "high").lower()
    if threshold not in FAIL_THRESHOLDS and threshold != "never":
        _fail(f"fail-on must be high, medium, low or never (got {threshold!r}).")

    has_complete_findings = "observed_findings" in result
    gaps = (
        result.get("observed_findings")
        if has_complete_findings
        else result.get("proven_gaps") or []
    )
    if not isinstance(gaps, list) or any(not isinstance(gap, dict) for gap in gaps):
        _fail("The check service returned an invalid findings list.")
    if len(gaps) > MAX_FINDINGS:
        _fail("The check service returned too many findings for safe workflow output.")
    severities = [str(gap.get("severity", "")).lower() for gap in gaps]
    if any(severity not in SEVERITY_RANK for severity in severities):
        _fail("The check service returned an unknown finding severity.")
    if threshold in {"medium", "low"} and not has_complete_findings:
        _fail("The check service does not support the requested finding threshold.")
    raw_total = result.get("total_findings", 0)
    if isinstance(raw_total, bool) or not isinstance(raw_total, (int, str)):
        _fail("The check service returned an invalid finding count.")
    if isinstance(raw_total, str) and not raw_total.isdecimal():
        _fail("The check service returned an invalid finding count.")
    total = int(raw_total)
    if total < 0:
        _fail("The check service returned an invalid finding count.")
    if has_complete_findings and total != len(gaps):
        _fail("The check service returned an inconsistent finding count.")
    report = json.dumps(
        result,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    if len(report.encode("utf-16-le")) > MAX_OUTPUT_UTF16_BYTES:
        _fail("The check result is too large for a safe GitHub Actions output.")
    headline = _cell(result.get("headline") or "Check complete.")

    blocking = []
    if threshold != "never":
        floor = SEVERITY_RANK[threshold]
        blocking = [
            g for g in gaps
            if SEVERITY_RANK.get(str(g.get("severity", "")).lower(), 0) >= floor
        ]

    lines = ["## PCI payment page script check", "", headline, ""]
    if gaps:
        lines += ["| Severity | Finding |", "| --- | --- |"]
        for gap in gaps:
            lines.append(
                f"| {_cell(gap.get('severity', '?'))} | {_cell(gap.get('message', ''))} |"
            )
    else:
        lines.append("No finding was returned for the bounded checks performed.")
    if result.get("scope_note"):
        lines.extend(["", f"**Scope:** {_cell(result['scope_note'])}"])
    scope = str(body.get("payment_page_scope") or "unspecified")
    guide_label, guide_url = SCOPE_GUIDES[scope]
    lines.extend(["", "### Put this result to work", "", f"- [{guide_label}]({guide_url})"])
    if scope == "direct":
        base = _api_base()
        sample_url = _safe_product_url(result.get("sample_url"), base=base)
        buy_url = _safe_product_url(result.get("buy_url"), base=base)
        if sample_url:
            lines.append(f"- [Preview the 6.4.3 deliverable]({sample_url})")
        if buy_url:
            lines.append(
                f"- [Continue only if the readiness-checked product fits]({buy_url})"
            )
        monitoring = result.get("ongoing_monitoring")
        if monitoring is not None and not isinstance(monitoring, dict):
            _fail("The check service returned an invalid monitoring offer.")
        if isinstance(monitoring, dict) and "html" not in body:
            ledger_sample = _safe_product_url(monitoring.get("sample_url"), base=base)
            ledger_buy = _safe_product_url(monitoring.get("buy_url"), base=base)
            if ledger_sample:
                lines.append(f"- [Preview the 11.6.1 evidence ledger]({ledger_sample})")
            if ledger_buy:
                lines.append(
                    f"- [Start readiness-checked 72-hour monitoring]({ledger_buy})"
                )
    lines += [
        "",
        "<sub>Software-generated evidence for qualified human review. It does not "
        "determine PCI DSS compliance and does not replace a QSA assessment. The "
        "check reads served HTML; it does not inspect HTTP response headers, fetch "
        "referenced script bytes, or execute the page. It cannot decide whether a "
        "script is authorized — only you can. "
        "[What 6.4.3 and 11.6.1 ask for]"
        "(https://qi.toledotechnologies.com/pci)</sub>",
    ]
    _summary("\n".join(lines))

    passed = not blocking
    _out("passed", "true" if passed else "false")
    _out("findings", str(total))
    _out("report", report)

    print(f"Result: {_one_line(headline)}")
    for gap in gaps:
        severity = _one_line(gap.get("severity", "?"), limit=50)
        message = _one_line(gap.get("message", ""))
        print(f"Finding [{severity}]: {message}")

    if not passed:
        print(f"::error::{len(blocking)} finding(s) at or above '{threshold}'.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
