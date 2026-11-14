#!/usr/bin/env python3
"""
DDoS amplification / reflection exposure checks (defensive).

For each UDP service that attackers abuse as a reflector, send ONE small, well-formed probe
to the target and see whether it answers - and how much bigger the answer is than the probe
(the amplification factor). A service that answers an unauthenticated UDP probe with a larger
reply can be abused to reflect/amplify traffic at a third party, so it is a real exposure on
the owner's own host.

This is a single probe packet per vector (standard scanning), never a flood. Run it only
against hosts you are authorized to scan - the engine already gates that.
"""
from __future__ import annotations

import socket
import struct
from typing import Dict, List, Optional


# ── probe payload builders ──────────────────────────────────────────────────────
def dns_query(name: str = "peacecorps.gov", qtype: int = 255) -> bytes:
    """Recursive DNS query (RD=1) for an external name. A host that is not authoritative
    for it yet returns answers is an OPEN RESOLVER (type 255 = ANY maximises the reply)."""
    header = b"\x13\x37" + b"\x01\x00" + struct.pack(">HHHH", 1, 0, 0, 0)  # RD=1, 1 question
    q = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split(".")) + b"\x00"
    q += struct.pack(">HH", qtype, 1)  # qtype, class IN
    return header + q


def ntp_monlist() -> bytes:
    """NTP mode 7 MON_GETLIST_1 (monlist). A reply means the classic ~556x amplifier."""
    return b"\x17\x00\x03\x2a" + b"\x00" * 4


def memcached_stats() -> bytes:
    """UDP memcached 'stats' (8-byte UDP header + command). A reply = exposed (huge amp)."""
    return b"\x00\x01\x00\x00\x00\x01\x00\x00" + b"stats\r\n"


def ssdp_msearch() -> bytes:
    return ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()


def chargen_probe() -> bytes:
    return b"\x01"


def _ber(tag: int, value: bytes) -> bytes:
    """Minimal definite-length BER TLV (lengths < 128 only, enough for this probe)."""
    return bytes([tag]) + bytes([len(value)]) + value


def _ber_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for n in parts[2:]:
        if n < 128:
            body += bytes([n])
        else:
            chunk = []
            while n:
                chunk.insert(0, n & 0x7F)
                n >>= 7
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            body += bytes(chunk)
    return _ber(0x06, body)


def snmp_get(community: str = "public", oid: str = "1.3.6.1.2.1.1.1.0") -> bytes:
    """SNMPv1 GetRequest for sysDescr.0 with the given community. A reply from 'public'
    means SNMP is open (info leak + reflection/amplification vector)."""
    varbind = _ber(0x30, _ber_oid(oid) + _ber(0x05, b""))        # OID + NULL
    varbinds = _ber(0x30, varbind)
    pdu = _ber(0xA0,                                             # GetRequest PDU
               _ber(0x02, b"\x13\x37") +                        # request-id
               _ber(0x02, b"\x00") +                            # error-status
               _ber(0x02, b"\x00") +                            # error-index
               varbinds)
    msg = _ber(0x30,
               _ber(0x02, b"\x00") +                            # version 0 (v1)
               _ber(0x04, community.encode()) +                 # community
               pdu)
    return msg


# ── vector catalogue ────────────────────────────────────────────────────────────
# severity reflects the amplification potential of the vector when it responds.
VECTORS = {
    "memcached": {"port": 11211, "name": "memcached exposed on UDP", "payload": memcached_stats,
                  "severity": "HIGH", "note": "memcached over UDP can amplify traffic by ~10,000-50,000x"},
    "ntp":       {"port": 123,   "name": "NTP monlist enabled", "payload": ntp_monlist,
                  "severity": "HIGH", "note": "ntp monlist amplifies by ~556x (CVE-2013-5211)"},
    "dns":       {"port": 53,    "name": "Open DNS resolver (recursion)", "payload": dns_query,
                  "severity": "HIGH", "note": "open resolvers are abused for DNS amplification (~28-54x)"},
    "ssdp":      {"port": 1900,  "name": "SSDP/UPnP responder exposed", "payload": ssdp_msearch,
                  "severity": "MEDIUM", "note": "SSDP amplifies by ~30x and leaks device info"},
    "snmp":      {"port": 161,   "name": "SNMP open with 'public' community", "payload": snmp_get,
                  "severity": "MEDIUM", "note": "SNMP GetBulk amplifies by ~6x and leaks system info"},
    "chargen":   {"port": 19,    "name": "chargen (UDP) enabled", "payload": chargen_probe,
                  "severity": "MEDIUM", "note": "chargen amplifies by ~358x and should be disabled"},
}


def probe_vector(host: str, vector: str, timeout: float = 3.0) -> Optional[Dict]:
    """Send one probe for ``vector`` to ``host``. Returns a result dict when the service
    answers (so it is a confirmed reflector), else None. Never raises."""
    spec = VECTORS.get(vector)
    if not spec:
        return None
    payload = spec["payload"]()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, spec["port"]))
        total = 0
        first = None
        # UDP amplifiers often answer with several datagrams; read what arrives in the window.
        while True:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                break
            if first is None:
                first = data
            total += len(data)
            if total > 200000:
                break
        if not total:
            return None
        factor = round(total / max(len(payload), 1), 1)
        return {"vector": vector, "port": spec["port"], "name": spec["name"],
                "severity": spec["severity"], "note": spec["note"],
                "request_bytes": len(payload), "response_bytes": total,
                "amplification_factor": factor}
    except (socket.gaierror, OSError):
        return None
    finally:
        sock.close()


def check_host(host: str, vectors: Optional[List[str]] = None, timeout: float = 3.0,
               stop_check=None) -> List[Dict]:
    """Probe all (or the given) amplification vectors on one host; return confirmed hits."""
    results = []
    for v in (vectors or list(VECTORS)):
        if stop_check and stop_check():
            break
        hit = probe_vector(host, v, timeout)
        if hit:
            results.append(hit)
    return results
