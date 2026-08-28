#!/usr/bin/env python3
"""
Unit tests for dashboard.py: HMAC verification, rejection of invalid/missing
signatures, IPv4/IPv6 bind, and fuzz-safety (random bytes must never crash the
receiver).

Run (from the anticheat/ directory):
    python3 -m unittest tests.test_dashboard
"""

import os
import sys
import json
import socket
import hmac
import hashlib
import unittest

# Make the repository root importable so `import dashboard` works.
sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)

import dashboard  # noqa: E402


KEY = "unit-test-secret"


def sign(severity, label, module, message, ts):
    canon = "%s|%s|%s|%s|%s" % (severity, label, module, message, ts)
    return hmac.new(KEY.encode(), canon.encode(),
                    hashlib.sha256).hexdigest()


def make_payload(severity, module, message, ts=None, sig=None):
    ts = ts if ts is not None else 1690000000
    label = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"][max(0, min(4, severity))]
    obj = {
        "severity": severity,
        "sev_label": label,
        "module": module,
        "message": message,
        "ts": ts,
    }
    if sig is not None:
        obj["sig"] = sig
    else:
        obj["sig"] = sign(severity, label, module, message, ts)
    return json.dumps(obj).encode("utf-8")


class TestVerifySig(unittest.TestCase):
    def setUp(self):
        dashboard.NET_KEY = KEY

    def test_valid_signature_passes(self):
        obj = json.loads(make_payload(3, "envguard", "vm detected"))
        self.assertTrue(dashboard.verify_sig(obj))

    def test_wrong_signature_rejected(self):
        obj = json.loads(make_payload(3, "envguard", "vm detected",
                                      sig="0" * 64))
        self.assertFalse(dashboard.verify_sig(obj))

    def test_missing_signature_rejected(self):
        obj = {
            "severity": 2,
            "sev_label": "MEDIUM",
            "module": "x",
            "message": "y",
            "ts": 1,
        }
        self.assertFalse(dashboard.verify_sig(obj))

    def test_malformed_fields_do_not_crash(self):
        # Non-string / missing fields must be handled safely.
        self.assertFalse(dashboard.verify_sig({"severity": 2}))
        self.assertFalse(dashboard.verify_sig(None))
        self.assertFalse(dashboard.verify_sig({"sig": 123, "severity": 2}))

    def test_legacy_mode_accepts_anything(self):
        dashboard.NET_KEY = None
        obj = {"severity": 2, "sev_label": "M", "module": "m",
               "message": "msg", "ts": 1}
        self.assertTrue(dashboard.verify_sig(obj))
        dashboard.NET_KEY = KEY


class TestReceive(unittest.TestCase):
    def setUp(self):
        dashboard.NET_KEY = KEY
        self.sock = dashboard.make_socket("127.0.0.1", 0)
        self.port = self.sock.getsockname()[1]

    def tearDown(self):
        self.sock.close()

    def _send(self, data):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(data, ("127.0.0.1", self.port))
        s.close()

    def test_valid_payload_received(self):
        self._send(make_payload(3, "envguard", "vm detected"))
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["module"], "envguard")

    def test_invalid_signature_dropped(self):
        self._send(make_payload(3, "envguard", "vm detected", sig="f" * 64))
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(len(alerts), 0)

    def test_missing_signature_dropped(self):
        bad = json.dumps({"severity": 2, "sev_label": "MEDIUM",
                          "module": "x", "message": "y", "ts": 1}).encode()
        self._send(bad)
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(len(alerts), 0)

    def test_fuzz_bytes_do_not_crash(self):
        import random
        random.seed(1)
        for _ in range(200):
            blob = bytes(random.getrandbits(8) for _ in range(random.randint(0, 200)))
            self._send(blob)
        # Should never raise; with a key set, junk is dropped.
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(alerts, [])

    def test_fuzz_valid_json_no_sig_dropped(self):
        for i in range(50):
            blob = ("{\"severity\":%d,\"module\":\"a%d\"" % (i % 5, i)).encode()
            self._send(blob)
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(alerts, [])


class TestBind(unittest.TestCase):
    def test_ipv4_bind(self):
        s = dashboard.make_socket("127.0.0.1", 0)
        self.assertEqual(s.family, socket.AF_INET)
        s.close()

    def test_ipv6_bind(self):
        try:
            s = dashboard.make_socket("::1", 0)
        except RuntimeError:
            self.skipTest("IPv6 loopback not available")
        self.assertEqual(s.family, socket.AF_INET6)
        s.close()


if __name__ == "__main__":
    unittest.main()
