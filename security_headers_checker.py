#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import ssl
import http.client
import urllib.request
import urllib.error
import urllib.parse
import socket
import argparse
import json
import re
from tabulate import tabulate

# Optional CA bundle
try:
    import certifi
    HAS_CERTIFI = True
except Exception:
    HAS_CERTIFI = False

# Optional pretty console
try:
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except Exception:
    HAS_RICH = False


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


SECURITY_HEADERS = [
    'X-Content-Type-Options',
    'Content-Security-Policy',
    'X-Permitted-Cross-Domain-Policies',
    'Referrer-Policy',
    'Expect-CT',
    'Permissions-Policy',
    'Cross-Origin-Embedder-Policy',
    'Cross-Origin-Resource-Policy',
    'Cross-Origin-Opener-Policy',
    'X-XSS-Protection',
    'X-Frame-Options',
    'Strict-Transport-Security'
]

DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def rate(sev="Info", likelihood="Unlikely", consequence="Minor"):
    return {"severity": sev, "likelihood": likelihood, "consequence": consequence}


class SecurityHeadersChecker:
    def __init__(self, target, insecure=False, proxy=None, timeout=10, user_agent=DEFAULT_UA,
                 output_html=False, json_out=False, check_http=False, no_color=False):
        self.target = self.normalize(target)
        self.insecure = insecure
        self.proxy = proxy
        self.timeout = timeout
        self.user_agent = user_agent
        self.output_html = output_html
        self.json_out = json_out
        self.check_http = check_http
        self.no_color = no_color

        # allow turning off ANSI colors (useful for CI)
        if self.no_color:
            for k in vars(Colors):
                if not k.startswith("_"):
                    setattr(Colors, k, "")

        self.req_headers = {
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Connection': 'close',
        }
        self.resp_headers = {}
        self.raw_header_items = []
        self.cookies = []
        self.effective_url = None

        self.fingerprints = {
            "web_server": None,
            "via": None,
            "powered_by": [],
            "generator": None,
            "frameworks": [],
            "negotiated_proto": None,   # ALPN selected protocol (edge)
            "alt_svc": None,           # Alt-Svc header (h3/h2 hints)
        }

        self.findings = []
        self.opener = self.build_opener()

    # ---------------- core plumbing ----------------

    def log(self, msg):
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()

    @staticmethod
    def normalize(url):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        return url

    def build_opener(self):
        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy}))

        if self.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            if HAS_CERTIFI:
                ctx = ssl.create_default_context(cafile=certifi.where())
            else:
                ctx = ssl.create_default_context()

        # Advertise ALPN h2/h1 for urllib requests too (helps some stacks)
        try:
            if hasattr(ctx, "set_alpn_protocols"):
                ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass

        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        handlers.append(urllib.request.HTTPHandler())

        opener = urllib.request.build_opener(*handlers)
        opener.addheaders = list(self.req_headers.items())
        return opener

    def fetch_headers(self):
        for method in ("HEAD", "GET"):
            try:
                req = urllib.request.Request(self.target, method=method)
                for k, v in self.req_headers.items():
                    req.add_header(k, v)
                resp = self.opener.open(req, timeout=self.timeout)
                self.effective_url = resp.geturl()

                self.resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                self.raw_header_items = list(resp.headers.items())

                # Cookies (may be multiple Set-Cookie)
                if hasattr(resp.headers, "get_all"):
                    self.cookies = resp.headers.get_all("Set-Cookie") or []
                else:
                    sc = resp.headers.get("Set-Cookie")
                    self.cookies = [sc] if sc else []

                # capture Alt-Svc if present
                self.fingerprints["alt_svc"] = self.resp_headers.get("alt-svc")

                resp.close()
                return True
            except urllib.error.HTTPError as e:
                if method == "HEAD" and e.code in (400, 403, 405):
                    continue
                self.print_error(e)
                return False
            except (urllib.error.URLError, http.client.BadStatusLine, ssl.SSLError,
                    socket.timeout, socket.gaierror) as e:
                self.print_error(e)
                return False
            except Exception as e:
                self.print_error(e)
                return False
        return False

    def print_error(self, e):
        if isinstance(e, urllib.error.HTTPError):
            self.log(f'{Colors.FAIL}HTTPError: {e.code} {e.reason} - {self.target}{Colors.ENDC}')
        elif isinstance(e, urllib.error.URLError):
            self.log(f'{Colors.FAIL}URLError: {e.reason} - {self.target}{Colors.ENDC}')
        elif isinstance(e, http.client.BadStatusLine):
            self.log(f'{Colors.FAIL}BadStatusLine: {e} - {self.target}{Colors.ENDC}')
        elif isinstance(e, ssl.SSLError):
            self.log(f'{Colors.FAIL}SSLError: {e} - {self.target}{Colors.ENDC}')
        elif isinstance(e, socket.timeout):
            self.log(f'{Colors.FAIL}Timeout - {self.target}{Colors.ENDC}')
        elif isinstance(e, socket.gaierror):
            self.log(f'{Colors.FAIL}Invalid host - {self.target}{Colors.ENDC}')
        else:
            self.log(f'{Colors.FAIL}Error: {e} - {self.target}{Colors.ENDC}')

    # ---------------- findings helpers ----------------

    def add_finding(self, title, rating, evidence=None, recommendation=None, category="Configuration"):
        self.findings.append({
            "title": title,
            "severity": rating["severity"],
            "likelihood": rating["likelihood"],
            "consequence": rating["consequence"],
            "evidence": evidence or "",
            "recommendation": recommendation or "",
            "category": category
        })

    @staticmethod
    def sev_style(sev: str) -> str:
        s = (sev or "").lower()
        if s == "critical":
            return "bold red"
        if s == "high":
            return "red"
        if s == "medium":
            return "dark_orange3"
        if s == "low":
            return "green"
        return "cyan"

    @staticmethod
    def sev_ansi(sev: str) -> str:
        s = (sev or "").lower()
        if s == "critical":
            return Colors.BOLD + Colors.FAIL + "Critical" + Colors.ENDC
        if s == "high":
            return Colors.FAIL + "High" + Colors.ENDC
        if s == "medium":
            return Colors.WARNING + "Medium" + Colors.ENDC
        if s == "low":
            return Colors.OKGREEN + "Low" + Colors.ENDC
        return Colors.OKBLUE + "Info" + Colors.ENDC

    # ---------------- analyzers ----------------

    def probe_alpn(self):
        """Determine edge protocol via ALPN (client ↔ edge)."""
        try:
            parsed = urllib.parse.urlparse(self.target)
            host = parsed.hostname
            port = parsed.port or 443
            ctx = ssl.create_default_context(cafile=certifi.where()) if HAS_CERTIFI else ssl.create_default_context()
            if hasattr(ctx, "set_alpn_protocols"):
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    proto = getattr(tls, "selected_alpn_protocol", lambda: None)()
                    self.fingerprints["negotiated_proto"] = proto or "unknown"
        except Exception:
            self.fingerprints["negotiated_proto"] = "unknown"

    def analyze_http1_must_die(self):
        proto = (self.fingerprints.get("negotiated_proto") or "").lower()
        if proto in ("http/1.1", "http1.1", "http/1"):
            self.add_finding(
                "Client→Edge Negotiated HTTP/1.1",
                rate("Medium", "Likely", "Severe"),
                evidence=f"ALPN selected protocol: {self.fingerprints.get('negotiated_proto')}",
                recommendation=("Enable HTTP/2 (and ideally HTTP/3) on the edge so browsers negotiate h2/h3; "
                                "eliminate HTTP/1.1 at the edge to reduce request-desync risk."),
                category="Protocol Posture"
            )
        via = self.resp_headers.get("via", "")
        if "1.1" in via:
            self.add_finding(
                "Upstream Hop Uses HTTP/1.1",
                rate("High", "Likely", "Severe"),
                evidence=f"Via: {via}",
                recommendation=("Migrate reverse-proxy→origin to HTTP/2 end-to-end. "
                                "Any HTTP/1.1 hop sustains request-smuggling risk variants."),
                category="Protocol Posture"
            )
        alt = self.fingerprints.get("alt_svc") or ""
        if "h3" in alt:
            self.add_finding(
                "HTTP/3 Advertised via Alt-Svc",
                rate("Info", "Unlikely", "Negligible"),
                evidence=f"Alt-Svc: {alt}",
                recommendation="Verify reverse-proxy and origin paths properly support h3/h2.",
                category="Protocol Posture"
            )

    def analyze_fingerprints(self):
        h = self.resp_headers
        self.fingerprints["web_server"] = h.get("server")
        self.fingerprints["via"] = h.get("via")

        xpb = h.get("x-powered-by")
        if xpb:
            self.fingerprints["powered_by"] = [v.strip() for v in xpb.split(",")]

        gen = h.get("x-generator")
        if gen:
            self.fingerprints["generator"] = gen

        for key in ["x-aspnet-version", "x-aspnetmvc-version", "x-drupal-cache",
                    "x-runtime", "x-php-version", "x-laravel", "x-nextjs-cache"]:
            if h.get(key):
                self.fingerprints["frameworks"].append(f"{key}: {h.get(key)}")

        if self.fingerprints["powered_by"] or self.fingerprints["generator"] or self.fingerprints["frameworks"]:
            ev = []
            if self.fingerprints["powered_by"]:
                ev.append(f"X-Powered-By: {', '.join(self.fingerprints['powered_by'])}")
            if self.fingerprints["generator"]:
                ev.append(f"X-Generator: {self.fingerprints['generator']}")
            if self.fingerprints["frameworks"]:
                ev.append("; ".join(self.fingerprints["frameworks"]))
            self.add_finding(
                "Technology Stack Disclosure via Response Headers",
                rate("Low", "Possible", "Minor"),
                evidence="; ".join(ev),
                recommendation="Strip or standardize technology-disclosing headers (X-Powered-By, X-Generator, Server)."
            )
        if self.fingerprints["web_server"]:
            banner = self.fingerprints["web_server"]
            if re.search(r"\d", banner or ""):
                self.add_finding(
                    "Web Server Banner Reveals Version",
                    rate("Low", "Possible", "Minor"),
                    evidence=f"Server: {banner}",
                    recommendation="Hide or genericize server banner; avoid precise version exposure."
                )

    def analyze_hsts(self):
        hsts = self.resp_headers.get("strict-transport-security")
        if not hsts:
            self.add_finding(
                "Missing Strict-Transport-Security (HSTS)",
                rate("High", "Likely", "Severe"),
                recommendation="Add HSTS with max-age ≥ 15552000, includeSubDomains, and consider preload."
            )
            return
        max_age = re.search(r"max-age=(\d+)", hsts, re.I)
        include = "includesubdomains" in hsts.lower()
        preload = "preload" in hsts.lower()
        if not max_age or int(max_age.group(1)) < 15552000:
            self.add_finding(
                "Weak HSTS max-age",
                rate("Medium", "Possible", "Moderate"),
                evidence=f"HSTS: {hsts}",
                recommendation="Set HSTS max-age ≥ 15552000 (180 days); includeSubDomains; consider preload."
            )
        if not include:
            self.add_finding(
                "HSTS missing includeSubDomains",
                rate("Low", "Possible", "Minor"),
                evidence=f"HSTS: {hsts}",
                recommendation="Add includeSubDomains to HSTS."
            )
        if not preload:
            self.add_finding(
                "HSTS not preloaded",
                rate("Info", "Unlikely", "Negligible"),
                evidence=f"HSTS: {hsts}",
                recommendation="Optionally add 'preload' and submit to the HSTS preload list."
            )

    def analyze_csp(self):
        csp = self.resp_headers.get("content-security-policy")
        csp_ro = self.resp_headers.get("content-security-policy-report-only")
        if not csp and not csp_ro:
            self.add_finding(
                "Missing Content-Security-Policy",
                rate("Medium", "Possible", "Moderate"),
                recommendation="Implement a restrictive CSP; avoid 'unsafe-inline'/'unsafe-eval' and wildcards."
            )
            return
        active = csp or csp_ro
        is_report_only = bool(csp_ro and not csp)

        issues = []
        if "unsafe-inline" in active:
            issues.append("Uses 'unsafe-inline'.")
        if "unsafe-eval" in active:
            issues.append("Uses 'unsafe-eval'.")
        if re.search(r"[\s:]https?:\s*\*\.", active) or re.search(r"[\s:]https?:\s*\*", active) or "'*'" in active:
            issues.append("Wildcard sources present.")
        if "frame-ancestors" not in active:
            issues.append("Missing frame-ancestors (clickjacking).")
        if "script-src" not in active and "default-src" not in active:
            issues.append("No script-src/default-src.")

        if issues:
            title = "Weak CSP Configuration (Report-Only)" if is_report_only else "Weak CSP Configuration"
            self.add_finding(
                title,
                rate("Medium", "Possible", "Moderate"),
                evidence="; ".join(issues),
                recommendation="Tighten CSP: set explicit script-src without 'unsafe-*', limit to trusted origins, add frame-ancestors."
            )

    def analyze_clickjacking(self):
        xfo = self.resp_headers.get("x-frame-options")
        csp = self.resp_headers.get("content-security-policy")
        if not xfo and (not csp or "frame-ancestors" not in (csp or "")):
            self.add_finding(
                "Missing Clickjacking Protection",
                rate("Medium", "Possible", "Moderate"),
                recommendation="Add X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors."
            )

    def analyze_referrer(self):
        rp = self.resp_headers.get("referrer-policy")
        if not rp:
            self.add_finding(
                "Missing Referrer-Policy",
                rate("Low", "Possible", "Minor"),
                recommendation="Add Referrer-Policy: strict-origin-when-cross-origin, same-origin, or no-referrer."
            )
        elif "no-referrer-when-downgrade" in rp.lower():
            self.add_finding(
                "Weak Referrer-Policy",
                rate("Low", "Possible", "Minor"),
                evidence=f"Referrer-Policy: {rp}",
                recommendation="Use strict-origin-when-cross-origin, same-origin, or no-referrer."
            )

    def analyze_permissions_policy(self):
        pp = self.resp_headers.get("permissions-policy")
        if not pp:
            self.add_finding(
                "Missing Permissions-Policy",
                rate("Low", "Possible", "Minor"),
                recommendation="Add Permissions-Policy to restrict powerful APIs (camera=(), geolocation=(), etc.)."
            )

    def analyze_permissions_policy_strict(self):
        pp = self.resp_headers.get("permissions-policy")
        if not pp:
            return
        wild = []
        for directive in ["camera", "geolocation", "microphone", "usb", "payment",
                          "accelerometer", "gyroscope", "magnetometer", "screen-wake-lock",
                          "clipboard-read", "clipboard-write", "hid", "serial", "bluetooth",
                          "window-placement"]:
            m = re.search(rf"{directive}\s*=\s*([^,;]+)", pp, flags=re.I)
            if m:
                val = m.group(1).strip()
                if val == "*" or val == "\"*\"" or "'*'" in val:
                    wild.append(directive)
        if wild:
            self.add_finding(
                "Permissive Permissions-Policy",
                rate("Low", "Possible", "Minor"),
                evidence=f"Wildcard allow on: {', '.join(sorted(set(wild)))}",
                recommendation="Restrict directives to '()' or specific origins."
            )

    def analyze_xcto(self):
        xcto = self.resp_headers.get("x-content-type-options")
        if not xcto or xcto.lower().strip() != "nosniff":
            self.add_finding(
                "Missing X-Content-Type-Options",
                rate("Low", "Possible", "Minor"),
                recommendation="Set X-Content-Type-Options: nosniff."
            )

    def analyze_corb_coop_coep(self):
        corp = self.resp_headers.get("cross-origin-resource-policy")
        coep = self.resp_headers.get("cross-origin-embedder-policy")
        coop = self.resp_headers.get("cross-origin-opener-policy")

        if not corp:
            self.add_finding(
                "Missing Cross-Origin-Resource-Policy",
                rate("Info", "Unlikely", "Negligible"),
                recommendation="Set CORP to same-site or same-origin."
            )
        if not coep:
            self.add_finding(
                "Missing Cross-Origin-Embedder-Policy",
                rate("Info", "Unlikely", "Negligible"),
                recommendation="Set COEP: require-corp."
            )
        if not coop:
            self.add_finding(
                "Missing Cross-Origin-Opener-Policy",
                rate("Info", "Unlikely", "Negligible"),
                recommendation="Set COOP: same-origin."
            )

    def analyze_deprecated(self):
        if self.resp_headers.get("x-xss-protection"):
            self.add_finding(
                "Deprecated X-XSS-Protection Header Present",
                rate("Info", "Unlikely", "Negligible"),
                evidence=f"X-XSS-Protection: {self.resp_headers.get('x-xss-protection')}",
                recommendation="Remove X-XSS-Protection (deprecated); rely on CSP and modern browser protections."
            )
        if self.resp_headers.get("expect-ct"):
            self.add_finding(
                "Deprecated Expect-CT Header Present",
                rate("Info", "Unlikely", "Negligible"),
                evidence=f"Expect-CT: {self.resp_headers.get('expect-ct')}",
                recommendation="Remove Expect-CT (deprecated)."
            )

    def analyze_cookies(self):
        if not self.cookies:
            return
        insecure = []
        httponly_missing = []
        samesite_missing = []
        bad_prefix = []
        for c in self.cookies:
            parts = [p.strip() for p in c.split(";")]
            name_val = parts[0]
            flags = {p.lower().split("=")[0].strip(): p for p in parts[1:] if "=" in p or p}
            if "secure" not in flags:
                insecure.append(name_val)
            if "httponly" not in flags:
                httponly_missing.append(name_val)
            if not any(p.lower().startswith("samesite=") for p in parts[1:]):
                samesite_missing.append(name_val)
            if name_val.startswith("__Host-"):
                lower = [p.lower() for p in parts[1:]]
                if "secure" not in lower or "path=/" not in lower or any(p.startswith("domain=") for p in lower):
                    bad_prefix.append(name_val + " (invalid __Host- usage)")
            if name_val.startswith("__Secure-") and "secure" not in {p.lower() for p in parts[1:]}:
                bad_prefix.append(name_val + " (missing Secure)")
        if insecure or httponly_missing or samesite_missing or bad_prefix:
            details = []
            if insecure:
                details.append(f"Missing Secure: {', '.join(insecure)}")
            if httponly_missing:
                details.append(f"Missing HttpOnly: {', '.join(httponly_missing)}")
            if samesite_missing:
                details.append(f"Missing SameSite: {', '.join(samesite_missing)}")
            if bad_prefix:
                details.append(f"Prefix issues: {', '.join(bad_prefix)}")
            self.add_finding(
                "Cookie Security Flags Not Strict",
                rate("Medium", "Possible", "Moderate"),
                evidence="; ".join(details),
                recommendation="Set Secure, HttpOnly, SameSite=Lax/Strict; prefer __Host- for primary session cookies.",
                category="Session Management"
            )

    def analyze_cookie_refinements(self):
        if not self.cookies:
            return
        issues = []
        for c in self.cookies:
            parts = [p.strip() for p in c.split(";")]
            name_val = parts[0]
            flags_lower = [p.lower() for p in parts[1:]]
            has_secure = any(p == "secure" for p in flags_lower)
            samesite_none = any(p.startswith("samesite=") and "none" in p for p in flags_lower)
            if samesite_none and not has_secure:
                issues.append(f"{name_val}: SameSite=None without Secure.")
            if any(x in name_val.lower() for x in ["session", "auth", "token"]):
                if not any(p.startswith("path=/") for p in flags_lower):
                    issues.append(f"{name_val}: missing Path=/")
                if any(p.startswith("domain=") for p in flags_lower):
                    issues.append(f"{name_val}: has Domain= (consider host-only or __Host-).")
        if issues:
            self.add_finding(
                "Cookie Hardening Suggestions",
                rate("Low", "Possible", "Minor"),
                evidence="; ".join(issues),
                recommendation="For session cookies, set Path=/, avoid Domain=, use SameSite=Lax/Strict or None+Secure."
            )

    def analyze_cors(self):
        h = self.resp_headers
        acao = h.get("access-control-allow-origin")
        acac = h.get("access-control-allow-credentials")
        acah = h.get("access-control-allow-headers")
        acam = h.get("access-control-allow-methods")
        acma = h.get("access-control-max-age")
        vary = h.get("vary", "")

        issues = []
        if acao:
            if acao.strip() == "*" and (acac or "").lower().strip() == "true":
                issues.append("ACAO '*' with credentials=true (forbidden; browsers drop it, signals misconfig).")
            if "origin" not in vary.lower() and acao != "*":
                issues.append("Missing Vary: Origin with reflected ACAO (cache poisoning risk).")
        if acah and ("*" in acah or "authorization" in acah.lower()):
            issues.append("Overly broad Access-Control-Allow-Headers ('*' or authorization).")
        if acam and ("*" in acam or "put" in acam.lower() or "delete" in acam.lower()):
            issues.append("Overly broad Access-Control-Allow-Methods ('*' or state-changing verbs).")
        if acma:
            try:
                if int(acma) > 86400:
                    issues.append("Large Access-Control-Max-Age (preflight cached too long).")
            except Exception:
                pass

        if issues:
            self.add_finding(
                "Permissive CORS Policy",
                rate("Medium", "Possible", "Moderate"),
                evidence="; ".join(issues),
                recommendation=("Restrict ACAO to exact origins, avoid credentials with '*', add 'Vary: Origin', "
                                "scope headers/methods, keep Max-Age ≤ 1 day."),
                category="CORS"
            )

    def analyze_cache(self):
        h = self.resp_headers
        cc = h.get("cache-control", "")
        pragma = h.get("pragma", "")
        expires = h.get("expires", "")
        ctype = h.get("content-type", "")

        is_html = "text/html" in (ctype or "").lower() or ctype == ""
        if is_html:
            if not cc:
                self.add_finding(
                    "Missing Cache-Control on HTML",
                    rate("Low", "Possible", "Minor"),
                    recommendation="Set Cache-Control: no-store, no-cache, must-revalidate, private for sensitive HTML."
                )
            else:
                lowbars = []
                lc = cc.lower()
                if "no-store" not in lc and "private" not in lc:
                    lowbars.append("No no-store/private on HTML.")
                if "no-cache" not in lc:
                    lowbars.append("Missing no-cache on HTML.")
                if lowbars:
                    self.add_finding(
                        "Weak Cache-Control on HTML",
                        rate("Low", "Possible", "Minor"),
                        evidence=f"Cache-Control: {cc}",
                        recommendation="Use 'no-store, no-cache, must-revalidate, private' for authenticated pages."
                    )
            if "no-cache" in (pragma or "").lower() and "no-cache" not in (cc or "").lower():
                self.add_finding(
                    "Conflicting Legacy Caching Directives",
                    rate("Info", "Unlikely", "Negligible"),
                    evidence=f"Pragma: {pragma}; Cache-Control: {cc}",
                    recommendation="Prefer Cache-Control; align directives consistently."
                )
            if expires and expires.strip() != "0" and "no-store" not in (cc or "").lower():
                self.add_finding(
                    "Non-zero Expires on HTML",
                    rate("Info", "Unlikely", "Negligible"),
                    evidence=f"Expires: {expires}; Cache-Control: {cc}",
                    recommendation="Use Expires: 0 with no-store or rely solely on Cache-Control."
                )

    def analyze_misc_legacy(self):
        h = self.resp_headers
        if h.get("feature-policy"):
            self.add_finding(
                "Deprecated Feature-Policy Header Present",
                rate("Info", "Unlikely", "Negligible"),
                evidence=f"Feature-Policy: {h.get('feature-policy')}",
                recommendation="Migrate to Permissions-Policy with equivalent directives."
            )
        xpcdp = h.get("x-permitted-cross-domain-policies")
        if xpcdp and xpcdp.lower().strip() != "none":
            self.add_finding(
                "Permitted Cross-Domain Policies Not Restricted",
                rate("Info", "Unlikely", "Negligible"),
                evidence=f"X-Permitted-Cross-Domain-Policies: {xpcdp}",
                recommendation="Set X-Permitted-Cross-Domain-Policies: none unless legacy Flash/Silverlight is required."
            )
        if "origin-agent-cluster" not in h:
            self.add_finding(
                "Missing Origin-Agent-Cluster",
                rate("Info", "Unlikely", "Negligible"),
                recommendation="Add Origin-Agent-Cluster: ?1 to improve site isolation."
            )
        if h.get("report-to") or h.get("nel"):
            self.add_finding(
                "Report-To/NEL Present",
                rate("Info", "Unlikely", "Negligible"),
                evidence="Report-To and/or NEL headers observed.",
                recommendation="Be aware these reporting mechanisms are being phased out."
            )

    def analyze_presence_list(self):
        found = []
        missing = []
        for h in SECURITY_HEADERS:
            v = self.resp_headers.get(h.lower())
            if v:
                found.append((h, v))
            else:
                missing.append(h)
        return found, missing

    def analyze_all(self):
        self.probe_alpn()
        self.analyze_http1_must_die()
        self.analyze_fingerprints()
        self.analyze_hsts()
        self.analyze_csp()
        self.analyze_clickjacking()
        self.analyze_referrer()
        self.analyze_permissions_policy()
        self.analyze_permissions_policy_strict()
        self.analyze_xcto()
        self.analyze_corb_coop_coep()
        self.analyze_deprecated()
        self.analyze_cookies()
        self.analyze_cookie_refinements()
        self.analyze_cors()
        self.analyze_cache()
        self.analyze_misc_legacy()

    # ---------------- reporting ----------------

    def report(self):
        eff = self.effective_url or self.target
        found, missing = self.analyze_presence_list()
        self.analyze_all()

        banner = r"""
   _____           __  __               __
  / ___/___  _____/ / / /__  ____ _____/ /__  __________
  \__ \/ _ \/ ___/ /_/ / _ \/ __ `/ __  / _ \/ ___/ ___/
 ___/ /  __/ /__/ __  /  __/ /_/ / /_/ /  __/ /  (__  )
/____/\___/\___/_/ /_/\___/\__,_/\__,_/\___/_/  /____/
    Security Header Check (Sicario)
"""
        if not self.json_out:
            self.log(Colors.HEADER + banner + Colors.ENDC)
            self.log('=' * 80)
            self.log(f'[*] Analyzing: {Colors.OKGREEN}{eff}{Colors.ENDC}')
            if self.fingerprints["web_server"]:
                self.log(f'  [→] Web Server: {Colors.OKBLUE}{self.fingerprints["web_server"]}{Colors.ENDC}')
            if self.fingerprints["powered_by"]:
                self.log(f'  [→] X-Powered-By: {Colors.OKBLUE}{", ".join(self.fingerprints["powered_by"])}{Colors.ENDC}')
            if self.fingerprints["generator"]:
                self.log(f'  [→] Generator: {Colors.OKBLUE}{self.fingerprints["generator"]}{Colors.ENDC}')
            if self.fingerprints["frameworks"]:
                self.log(f'  [→] Frameworks: {Colors.OKBLUE}{"; ".join(self.fingerprints["frameworks"])}{Colors.ENDC}')
            if self.fingerprints["via"]:
                self.log(f'  [→] Via: {Colors.OKBLUE}{self.fingerprints["via"]}{Colors.ENDC}')
            if self.fingerprints.get("negotiated_proto"):
                self.log(f'  [→] Protocol (ALPN): {Colors.OKBLUE}{self.fingerprints["negotiated_proto"]}{Colors.ENDC}')
            if self.fingerprints.get("alt_svc"):
                self.log(f'  [→] Alt-Svc: {Colors.OKBLUE}{self.fingerprints["alt_svc"]}{Colors.ENDC}')

            self.log('-' * 80)
            self.log(Colors.BOLD + "Header Presence" + Colors.ENDC)
            for k, v in found:
                self.log(f'  [+] {k}: {Colors.OKGREEN}{v}{Colors.ENDC}')
            for k in missing:
                self.log(f'  [!] Missing: {Colors.FAIL}{k}{Colors.ENDC}')

            self.log('-' * 80)
            self.log(Colors.BOLD + "Findings" + Colors.ENDC)
            if not self.findings:
                self.log(f'{Colors.OKGREEN}No issues identified from headers.{Colors.ENDC}')
            else:
                ordered = sorted(self.findings, key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0))
                if HAS_RICH and not self.no_color:
                    console = Console()
                    t = Table(show_header=True, header_style="bold", show_lines=False)
                    t.add_column("Issue", style="bold")
                    t.add_column("Severity")
                    t.add_column("Likelihood")
                    t.add_column("Consequence")
                    t.add_column("Category")
                    t.add_column("Evidence")
                    for f in ordered:
                        style = self.sev_style(f["severity"])
                        ev = (f['evidence'][:70] + '...') if len(f['evidence']) > 73 else f['evidence']
                        t.add_row(
                            f"[{style}]{f['title']}[/]",
                            f"[{style}]{f['severity']}[/]",
                            f"[{style}]{f['likelihood']}[/]",
                            f"[{style}]{f['consequence']}[/]",
                            f"[{style}]{f['category']}[/]",
                            f"[{style}]{ev}[/]"
                        )
                    console.print(t)
                    console.print(
                        "\n[bold]Legend:[/bold] "
                        "[bold red]Critical[/] / [red]High[/] · "
                        "[dark_orange3]Medium[/] · "
                        "[green]Low[/] · "
                        "[cyan]Info[/]\n"
                    )
                else:
                    table_rows = []
                    for f in ordered:
                        ev = (f['evidence'][:70] + '...') if len(f['evidence']) > 73 else f['evidence']
                        title_col = (
                            Colors.FAIL + f['title'] + Colors.ENDC
                            if f['severity'] in ("High", "Critical") else
                            Colors.WARNING + f['title'] + Colors.ENDC
                            if f['severity'] == "Medium" else
                            Colors.OKGREEN + f['title'] + Colors.ENDC
                            if f['severity'] == "Low" else
                            Colors.OKBLUE + f['title'] + Colors.ENDC
                        )
                        table_rows.append([
                            title_col,
                            self.sev_ansi(f['severity']),
                            f['likelihood'],
                            f['consequence'],
                            f['category'],
                            ev
                        ])
                    self.log(tabulate(table_rows,
                                      headers=["Issue", "Severity", "Likelihood", "Consequence", "Category", "Evidence"],
                                      tablefmt="github"))
                    self.log("\nLegend: "
                             f"{Colors.BOLD}{Colors.FAIL}Critical{Colors.ENDC} / "
                             f"{Colors.FAIL}High{Colors.ENDC} · "
                             f"{Colors.WARNING}Medium{Colors.ENDC} · "
                             f"{Colors.OKGREEN}Low{Colors.ENDC} · "
                             f"{Colors.OKBLUE}Info{Colors.ENDC}\n")

            self.log('-' * 80)
            self.log(f'Enforced: {Colors.OKGREEN}{len(found)}{Colors.ENDC} | Missing: {Colors.FAIL}{len(missing)}{Colors.ENDC}')
            self.log('')

        if self.output_html:
            self.write_html_report(eff, found, missing)

        if self.json_out:
            out = {
                "target": eff,
                "fingerprints": self.fingerprints,
                "headers": dict(self.resp_headers),
                "cookies": self.cookies,
                "enforced_count": len(found),
                "missing_count": len(missing),
                "findings": self.findings
            }
            print(json.dumps(out, indent=2))

        if self.check_http:
            self.http_probe()

    def write_html_report(self, eff, found, missing):
        findings_rows = ""
        for f in sorted(self.findings, key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0)):
            findings_rows += (
                "<tr>"
                f"<td>{self.escape(f['title'])}</td>"
                f"<td>{self.escape(f['severity'])}</td>"
                f"<td>{self.escape(f['likelihood'])}</td>"
                f"<td>{self.escape(f['consequence'])}</td>"
                f"<td>{self.escape(f['category'])}</td>"
                f"<td>{self.escape(f['evidence'])}</td>"
                f"<td>{self.escape(f['recommendation'])}</td>"
                "</tr>"
            )

        headers_rows = "".join(f"<tr><td>{self.escape(k)}</td><td>{self.escape(v)}</td></tr>" for k, v in found)
        missing_rows = "".join(f"<li>{self.escape(h)}</li>" for h in missing) or "<li>None</li>"

        html = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Security Headers Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; margin:24px}}
h1,h2{{margin:0 0 12px}}
table{{border-collapse:collapse;width:100%;margin:12px 0}}
th,td{{border:1px solid #ddd;padding:8px;vertical-align:top}}
th{{background:#f5f5f5;text-align:left}}
.small{{color:#666;font-size:12px}}
code{{background:#f6f8fa;padding:2px 4px;border-radius:4px}}
</style>
</head>
<body>
<h1>Security Headers Report</h1>
<p><b>Target:</b> {self.escape(eff)}</p>

<h2>Fingerprints</h2>
<ul>
<li><b>Web Server:</b> {self.escape(self.fingerprints.get('web_server') or '—')}</li>
<li><b>Protocol (ALPN):</b> {self.escape(self.fingerprints.get('negotiated_proto') or '—')}</li>
<li><b>Alt-Svc:</b> {self.escape(self.fingerprints.get('alt_svc') or '—')}</li>
<li><b>X-Powered-By:</b> {self.escape(', '.join(self.fingerprints.get('powered_by') or []) or '—')}</li>
<li><b>Generator:</b> {self.escape(self.fingerprints.get('generator') or '—')}</li>
<li><b>Frameworks:</b> {self.escape('; '.join(self.fingerprints.get('frameworks') or []) or '—')}</li>
<li><b>Via:</b> {self.escape(self.fingerprints.get('via') or '—')}</li>
</ul>

<h2>Enforced Headers</h2>
<table><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>
{headers_rows}
</tbody></table>

<h2>Missing Headers</h2>
<ul>{missing_rows}</ul>

<h2>Findings</h2>
<table>
<thead><tr>
<th>Issue</th><th>Severity</th><th>Likelihood</th><th>Consequence</th><th>Category</th><th>Evidence</th><th>Recommendation</th>
</tr></thead>
<tbody>
{findings_rows or '<tr><td colspan="7">No issues identified from headers.</td></tr>'}
</tbody></table>

<p class="small">Generated by Security Header Check (IONIZE).</p>
</body></html>"""
        with open("security_report.html", "w", encoding="utf-8") as f:
            f.write(html)
        if not self.json_out:
            self.log(f"[+] Wrote HTML report: security_report.html")

    @staticmethod
    def escape(s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ---------------- extras ----------------

    def http_probe(self):
        """Optional: probe http:// and check if it cleanly redirects to HTTPS."""
        try:
            parsed = urllib.parse.urlparse(self.target)
            http_url = self.target
            if parsed.scheme == "https":
                http_url = self.target.replace("https://", "http://", 1)
            req = urllib.request.Request(http_url, method="GET", headers={'User-Agent': self.user_agent})
            opener = self.build_opener()
            resp = opener.open(req, timeout=self.timeout)
            final = resp.geturl()
            code = getattr(resp, "status", None) or getattr(resp, "code", None)
            resp.close()
            if not final.startswith("https://"):
                self.log(Colors.WARNING + f"[!] HTTP probe served non-HTTPS content or did not enforce redirect "
                                          f"(status {code}, final {final})" + Colors.ENDC)
            else:
                self.log(Colors.OKGREEN + f"[+] HTTP probe redirected to HTTPS (final {final})" + Colors.ENDC)
        except Exception as e:
            self.log(Colors.WARNING + f"[!] HTTP probe error: {e}" + Colors.ENDC)


# ---------------- CLI ----------------

def parse_args():
    p = argparse.ArgumentParser(description="Security headers checker with fingerprinting, color, and http1mustdie checks.")
    p.add_argument("url", help="Target URL, e.g. https://example.com")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification.")
    p.add_argument("--proxy", help="HTTP(S) proxy (host:port or scheme://host:port).")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout (s).")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent string.")
    p.add_argument("-o", "--output-html", action="store_true", help="Write HTML report (security_report.html).")
    p.add_argument("--json", dest="json_out", action="store_true", help="Output machine-readable JSON.")
    p.add_argument("--check-http", action="store_true", help="Also probe http:// and warn if it doesn’t redirect to https.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors (useful for CI).")
    return p.parse_args()


def main():
    args = parse_args()
    checker = SecurityHeadersChecker(
        target=args.url,
        insecure=args.insecure,
        proxy=args.proxy,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_html=args.output_html,
        json_out=args.json_out,
        check_http=args.check_http,
        no_color=args.no_color
    )
    ok = checker.fetch_headers()
    if ok:
        checker.report()
    else:
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
