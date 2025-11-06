# Security Headers Checker

[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.8-yellow.svg)](https://www.python.org/)
<img src="https://img.shields.io/badge/Developed%20on-Kali%20Linux-blueviolet">
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">

![Banner](shot.png)

Security Headers Checker is a command‑line tool that inspects HTTP(S) response headers, fingerprints the web server/application, and highlights missing or weak security controls. It also includes protocol posture checks inspired by **http1mustdie** (ALPN negotiation, `Alt-Svc`, and upstream `Via` hints).

---

## Installation

```bash
git clone https://github.com/sic4rio/security-headers-checker.git
cd security-headers-checker
pip install -r requirements.txt
```

> **Optional, but recommended**
>
> - `rich` → pretty, colorized tables in your terminal  
> - `certifi` → consistent CA bundle across environments  
> - `tabulate` → clean fallback tables and HTML rendering

---

## Quick Start

```bash
python security_headers_checker.py https://example.com
```

Add `-o` to also emit a clean HTML report (`security_report.html`) in the current directory:

```bash
python security_headers_checker.py https://example.com -o
```

---

## CLI Flags & Usage

```
usage: security_headers_checker.py [-h] [--insecure] [--proxy PROXY] [--timeout TIMEOUT]
                                   [--user-agent USER_AGENT] [-o] [--json] [--check-http] [--no-color]
                                   url
```

| Flag | Type | Default | Description |
|---|---|---:|---|
| `url` | str | — | Target URL, e.g., `https://example.com`. (If you pass a bare host the tool will assume `https://`.) |
| `--insecure` | bool | `False` | Disable TLS verification (accept any certificate). |
| `--proxy PROXY` | str | — | HTTP(S) proxy in `host:port` or `scheme://host:port` form. Applies to HTTP and HTTPS probes. |
| `--timeout TIMEOUT` | int | `10` | Request timeout in seconds (also used by the HTTP probe). |
| `--user-agent USER_AGENT` | str | Chrome‑like UA | Override the default User‑Agent. |
| `-o`, `--output-html` | bool | `False` | Write an HTML report to `security_report.html`. |
| `--json` | bool | `False` | Output a machine‑readable JSON blob to stdout (fingerprints, findings, headers, cookies). |
| `--check-http` | bool | `False` | Also probe `http://` and report whether it cleanly redirects to HTTPS; adds findings when HTTP is open and not enforcing redirect. Gracefully handles no listener/timeouts. |
| `--no-color` | bool | `False` | Disable ANSI colors in terminal output (useful for CI logs). |

### What it Checks

- **Header Presence & Strength**: HSTS (max‑age, subdomains, preload), CSP (unsafe‑* / wildcards / report‑only), X‑Frame‑Options or `frame-ancestors`, Referrer‑Policy, Permissions‑Policy (incl. permissive directives), CORP/COOP/COEP, X‑Content‑Type‑Options, Legacy/Deprecated (X‑XSS‑Protection, Expect‑CT, Feature‑Policy), X‑Permitted‑Cross‑Domain‑Policies, Origin‑Agent‑Cluster, Report‑To/NEL notes.
- **Cookies**: `Secure`, `HttpOnly`, `SameSite`, `__Host-` / `__Secure-` rules, `SameSite=None` without `Secure`, `Domain`/`Path` hygiene for session‑ish cookies.
- **CORS**: `ACAO` + `credentials` pitfalls, `Vary: Origin`, broad headers/methods, huge max‑age.
- **Cache‑Control** (HTML): missing/weak cache control; legacy contradictions with `Pragma`/`Expires`.
- **Fingerprinting**: `Server`, `X‑Powered‑By`, `X‑Generator`, common framework breadcrumbs, `Via`.
- **Protocol Posture (http1mustdie)**: ALPN‑negotiated protocol (client→edge), `Alt‑Svc` (`h3`/`h2` hints), `Via` for upstream 1.1 hops.
- **Optional HTTP Probe**: Validate `http://` → `https://` redirect behavior; add informational note where port 80 is closed without HSTS preload.

### Output

Each finding includes:
- **Severity** (Critical/High/Medium/Low/Info)
- **Likelihood** (e.g., Likely/Possible/Unlikely)
- **Consequence** (e.g., Severe/Moderate/Minor/Negligible)
- **Evidence** and **Recommendation**

If `rich` is installed, the **Findings** table is fully colorized by severity (red/orange/green/blue). Without `rich`, the Severity and Issue cells use ANSI colors with a legend.

---

## Examples

**Pretty terminal + HTML report**  
```bash
python security_headers_checker.py https://example.com -o
```

**JSON for pipelines (save to file)**  
```bash
python security_headers_checker.py https://example.com --json > example_headers.json
```

**Probe HTTP redirect posture and be generous with timeouts**  
```bash
python security_headers_checker.py https://example.com --check-http --timeout 20
```

**Run behind a proxy**  
```bash
python security_headers_checker.py https://example.com --proxy http://127.0.0.1:8080
```

**Disable terminal color (CI logs)**  
```bash
python security_headers_checker.py https://example.com --no-color
```

---

## Requirements

Add these to `requirements.txt` (recommended):
```
tabulate>=0.9.0
rich>=13.0.0
certifi>=2024.2.2
```

> The tool works without `rich` and `certifi` (falls back to system CA store and ANSI tables).

---

## Contributing

Contributions are welcome! If you find issues or have ideas, please open an issue or a PR.

---

## License

This project is licensed under the **MIT License**. See `LICENSE` for details.
