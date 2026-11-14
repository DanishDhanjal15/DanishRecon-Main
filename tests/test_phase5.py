"""Tests for DDoS amplification/reflection checks and the botnet YARA rules. Offline:
UDP probes run against a local fake responder; the engine stage uses a stubbed prober."""
import os
import socket
import sys
import tempfile
import threading
import unittest

import danishrecon

APP_DIR = os.path.dirname(os.path.abspath(danishrecon.__file__))   # the installed package

if "danishrecon.scan_core" not in sys.modules:
    os.chdir(tempfile.mkdtemp(prefix="cyberrecon_tests_"))
os.environ["DISABLE_GEMINI"] = "true"

from danishrecon import amplification as amp  # noqa: E402
from danishrecon import scan_core as crp  # noqa: E402


class Payloads(unittest.TestCase):
    def test_dns_query_is_recursive_single_question(self):
        q = amp.dns_query()
        self.assertEqual(q[2:4], b"\x01\x00")          # flags: RD=1
        self.assertEqual(q[4:6], b"\x00\x01")          # QDCOUNT = 1
        self.assertTrue(q.endswith(b"\x00\xff\x00\x01"))  # qtype ANY(255), class IN(1)

    def test_ntp_monlist_bytes(self):
        self.assertEqual(amp.ntp_monlist(), b"\x17\x00\x03\x2a\x00\x00\x00\x00")

    def test_memcached_has_udp_header_and_stats(self):
        p = amp.memcached_stats()
        self.assertEqual(p[:8], b"\x00\x01\x00\x00\x00\x01\x00\x00")
        self.assertTrue(p.endswith(b"stats\r\n"))

    def test_snmp_get_is_v1_public_getrequest(self):
        p = amp.snmp_get()
        self.assertEqual(p[0], 0x30)                   # SEQUENCE
        self.assertIn(b"public", p)
        self.assertIn(b"\xa0", p)                      # GetRequest PDU tag
        self.assertIn(bytes.fromhex("2b06010201010100"), p)  # OID 1.3.6.1.2.1.1.1.0

    def test_vector_catalogue_complete(self):
        for v in ("memcached", "ntp", "dns", "ssdp", "snmp", "chargen"):
            self.assertIn(v, amp.VECTORS)
            self.assertTrue(callable(amp.VECTORS[v]["payload"]))


class LiveProbe(unittest.TestCase):
    def _responder(self, reply):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        def serve():
            try:
                _, addr = s.recvfrom(4096)
                if reply:
                    s.sendto(reply, addr)
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(s.close)
        return port

    def test_detects_amplifier_and_computes_factor(self):
        port = self._responder(b"R" * 4000)
        amp.VECTORS["memcached"]["port"] = port
        try:
            hit = amp.probe_vector("127.0.0.1", "memcached", timeout=2)
        finally:
            amp.VECTORS["memcached"]["port"] = 11211
        self.assertIsNotNone(hit)
        self.assertEqual(hit["response_bytes"], 4000)
        self.assertGreater(hit["amplification_factor"], 100)

    def test_no_response_is_not_a_finding(self):
        port = self._responder(None)      # service that never replies
        amp.VECTORS["chargen"]["port"] = port
        try:
            self.assertIsNone(amp.probe_vector("127.0.0.1", "chargen", timeout=1))
        finally:
            amp.VECTORS["chargen"]["port"] = 19

    def test_closed_port_is_not_a_finding(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        amp.VECTORS["ntp"]["port"] = port
        try:
            self.assertIsNone(amp.probe_vector("127.0.0.1", "ntp", timeout=1))
        finally:
            amp.VECTORS["ntp"]["port"] = 123


class StageWiring(unittest.TestCase):
    def test_stage_records_reflector_findings(self):
        eng = crp.ScanEngine("10.0.0.1", "Quick", {})
        eng.data["hosts"] = ["10.0.0.1"]
        saved = crp.amplification.check_host
        crp.amplification.check_host = lambda host, **k: [
            {"vector": "memcached", "port": 11211, "name": "memcached exposed on UDP",
             "severity": "HIGH", "note": "huge amp", "request_bytes": 15,
             "response_bytes": 30000, "amplification_factor": 2000.0}]
        try:
            n = eng.stage_amplification_check([])
        finally:
            crp.amplification.check_host = saved
        self.assertEqual(n, 1)
        f = eng.data["findings"][0]
        self.assertEqual((f["category"], f["severity"], f["source"]), ("ddos-reflector", "HIGH", "amplification"))
        self.assertIn("2000.0x", f["title"])
        self.assertEqual(f["port"], "11211")

    def test_stage_skipped_when_disabled(self):
        eng = crp.ScanEngine("10.0.0.1", "Quick", {"amplification": False})
        eng.data["hosts"] = ["10.0.0.1"]
        called = {"x": False}
        saved = crp.amplification.check_host
        crp.amplification.check_host = lambda *a, **k: called.update(x=True) or []
        try:
            eng.stage_amplification_check([])
        finally:
            crp.amplification.check_host = saved
        self.assertFalse(called["x"])


class BotnetYara(unittest.TestCase):
    def test_botnet_rules_match_families_and_not_clean(self):
        try:
            import yara
        except Exception:
            self.skipTest("yara-python not installed")
        rules = yara.compile(filepath=os.path.join(APP_DIR, "yara_rules", "botnet.yar"))
        cases = {
            "Mirai_IoT_Botnet": b"MIRAI /bin/busybox table_lock_val table_unlock_val /dev/watchdog attack_udp",
            "Gafgyt_Bashlite_Botnet": b"PING\nPONG\nUDP Flood\nTCP Flood\nGETLOCALIP\nSCANNER ON",
            "DDoS_Attack_Command_Strings": b"methods: syn flood, dns flood, http flood",
            "Classic_DDoS_Agents_2000": b"\x00l44adsl\x00gOrave\x00",
            "IRC_Bot_CnC_Indicators": b"PRIVMSG #c\nJOIN #b\n.ddos 1.2.3.4",
        }
        for rule, data in cases.items():
            self.assertIn(rule, [r.rule for r in rules.match(data=data)], rule)
        self.assertEqual(rules.match(data=b"ordinary program, hello world, read config"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
