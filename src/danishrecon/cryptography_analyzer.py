"""TLS / certificate analysis.

Everything reported here comes from a real handshake with the target. If the target
cannot be reached the result says so (``reachable: False``) - nothing is ever simulated.
"""
import datetime
import socket
import ssl

try:
    from cryptography import x509
    _X509_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    _X509_AVAILABLE = False


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_der(der: bytes) -> dict:
    """Extract subject / issuer / expiry from a DER certificate."""
    info = {"subject": "Unknown", "issuer": "Unknown", "not_after": None, "self_signed": None}
    if not der or not _X509_AVAILABLE:
        return info
    cert = x509.load_der_x509_certificate(der)
    info["subject"] = cert.subject.rfc4514_string()
    info["issuer"] = cert.issuer.rfc4514_string()
    info["self_signed"] = cert.subject == cert.issuer
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:  # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    info["not_after"] = not_after
    return info


def fetch_certificate(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Connect to host:port and describe the certificate the server really presents.

    Returns a dict with:
      reachable       - a TLS handshake completed
      error           - why not, when reachable is False
      trusted         - the chain and hostname verify against the system trust store
      trust_error     - verification failure reason when trusted is False
      subject, issuer, not_after (aware datetime or None), days_remaining, expired,
      self_signed, protocol, cipher
    """
    out = {"reachable": False, "error": None, "trusted": False, "trust_error": None,
           "subject": "Unknown", "issuer": "Unknown", "not_after": None,
           "days_remaining": None, "expired": False, "self_signed": None,
           "protocol": None, "cipher": None}
    port = int(port)

    # 1) Unverified handshake: tells us whether TLS is spoken at all and gives us the
    #    certificate even when it is invalid (which is exactly the case we must report).
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                out["protocol"] = ssock.version()
                cipher = ssock.cipher()
                out["cipher"] = cipher[0] if cipher else None
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    out["reachable"] = True
    try:
        out.update(_parse_der(der))
    except Exception as e:
        out["error"] = f"certificate parse error: {e}"

    if out["not_after"] is not None:
        delta = out["not_after"] - _utcnow()
        out["days_remaining"] = delta.days
        out["expired"] = delta.total_seconds() < 0

    # 2) Verified handshake: does a normal client trust this certificate for this name?
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                out["trusted"] = True
    except ssl.SSLCertVerificationError as e:
        out["trust_error"] = getattr(e, "verify_message", None) or str(e)
    except Exception as e:
        out["trust_error"] = f"{type(e).__name__}: {e}"

    return out


_VERSIONS = [
    ("TLSv1.3", "TLSv1_3", False),
    ("TLSv1.2", "TLSv1_2", False),
    ("TLSv1.1", "TLSv1_1", True),
    ("TLSv1.0", "TLSv1", True),
]


def _probe_version(host: str, port: int, attr: str, timeout: float = 4.0) -> dict:
    """Try a handshake restricted to exactly one protocol version.

    ``tested`` is False when the local OpenSSL build cannot offer that version at all,
    in which case ``supported`` is unknown rather than False.
    """
    try:
        version = getattr(ssl.TLSVersion, attr)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if attr in ("TLSv1", "TLSv1_1"):
            # Legacy versions are disabled at the default OpenSSL security level.
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, AttributeError, ssl.SSLError):
        return {"supported": False, "tested": False}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return {"supported": True, "tested": True}
    except Exception:
        return {"supported": False, "tested": True}


class CryptographyAnalyzer:
    """Analyse the TLS configuration and certificate of ``target:port``."""

    def __init__(self, target, port=443):
        self.target = target
        self.port = int(port)

    def analyze(self):
        result = {
            "reachable": False,
            "certificate_analysis": {
                "valid": False, "trusted": False, "issuer": "Unknown", "subject": "Unknown",
                "expiry": "N/A", "days_remaining": None, "error": None,
            },
            "overall_rating": {"grade": "N/A", "score": 0},
            "tls_versions": {
                "SSLv2":   {"supported": False, "deprecated": True, "tested": False},
                "SSLv3":   {"supported": False, "deprecated": True, "tested": False},
                "TLSv1.0": {"supported": False, "deprecated": True, "tested": False},
                "TLSv1.1": {"supported": False, "deprecated": True, "tested": False},
                "TLSv1.2": {"supported": False, "deprecated": False, "tested": False},
                "TLSv1.3": {"supported": False, "deprecated": False, "tested": False},
            },
            "vulnerabilities": [],
        }

        cert = fetch_certificate(self.target, self.port)
        if not cert["reachable"]:
            result["certificate_analysis"]["error"] = cert["error"]
            return result

        result["reachable"] = True
        result["negotiated"] = {"protocol": cert["protocol"], "cipher": cert["cipher"]}
        valid = bool(cert["trusted"] and not cert["expired"])
        result["certificate_analysis"].update({
            "valid": valid,
            "trusted": cert["trusted"],
            "issuer": cert["issuer"],
            "subject": cert["subject"],
            "expiry": cert["not_after"].strftime("%Y-%m-%d %H:%M:%S UTC") if cert["not_after"] else "N/A",
            "days_remaining": cert["days_remaining"],
            "error": cert["trust_error"],
        })

        for name, attr, deprecated in _VERSIONS:
            probe = _probe_version(self.target, self.port, attr)
            result["tls_versions"][name].update(probe)

        tv = result["tls_versions"]
        vulns = result["vulnerabilities"]

        if tv["TLSv1.1"]["supported"]:
            vulns.append({"type": "Deprecated TLS 1.1 supported", "risk": "MEDIUM", "category": "protocol",
                          "description": "The server accepts TLS 1.1, which is deprecated (RFC 8996)."})
        if tv["TLSv1.0"]["supported"]:
            vulns.append({"type": "Deprecated TLS 1.0 supported", "risk": "MEDIUM", "category": "protocol",
                          "description": "The server accepts TLS 1.0, which is deprecated (RFC 8996)."})
        if cert["expired"]:
            vulns.append({"type": "Expired certificate", "risk": "HIGH", "category": "certificate",
                          "description": f"The certificate expired {-cert['days_remaining']} day(s) ago."})
        elif not cert["trusted"]:
            reason = cert["trust_error"] or "verification failed"
            vulns.append({"type": "Certificate not trusted", "risk": "MEDIUM", "category": "certificate",
                          "description": f"A standard client rejects this certificate: {reason}"})
        elif cert["days_remaining"] is not None and cert["days_remaining"] < 30:
            vulns.append({"type": "Certificate expiring soon", "risk": "LOW", "category": "certificate",
                          "description": f"The certificate expires in {cert['days_remaining']} day(s)."})

        # Indicative grade derived only from the checks above (not an SSL Labs grade).
        if tv["TLSv1.3"]["supported"]:
            grade, score = "A+", 95
        elif tv["TLSv1.2"]["supported"]:
            grade, score = "A", 88
        else:
            grade, score = "C", 60
        if tv["TLSv1.1"]["supported"]:
            grade, score = "B", min(score, 75)
        if tv["TLSv1.0"]["supported"]:
            grade, score = "C", min(score, 65)
        if not valid:
            grade, score = "F", min(score, 40)
        result["overall_rating"] = {"grade": grade, "score": score}
        return result


def analyze_target_crypto(target, port=443):
    """Convenience wrapper: run the TLS analysis for ``target:port``."""
    return CryptographyAnalyzer(target, port).analyze()
