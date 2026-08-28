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
import time
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
    ts = ts if ts is not None else int(time.time())
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
        # Each test starts with a clean replay cache so signatures from a
        # previous test are not mistaken for replays.
        dashboard._replay_cache.clear()
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

    def test_replay_rejected(self):
        # Same signed datagram sent twice: the first is accepted, the second is
        # a replay and must be dropped.
        payload = make_payload(2, "replay", "duplicate")
        self._send(payload)
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(len(alerts), 1)
        self._send(payload)
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(len(alerts), 0)

    def test_stale_timestamp_rejected(self):
        stale = int(time.time()) - 100
        self._send(make_payload(3, "envguard", "old", ts=stale))
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(len(alerts), 0)

    def test_future_timestamp_rejected(self):
        future = int(time.time()) + 100
        self._send(make_payload(3, "envguard", "future", ts=future))
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(len(alerts), 0)


class TestFuzz(unittest.TestCase):
    """Fuzz the dashboard receive path: every malformed input must be dropped
    (never crash / never render) when a key is configured."""

    def setUp(self):
        dashboard.NET_KEY = KEY
        dashboard._replay_cache.clear()
        self.sock = dashboard.make_socket("127.0.0.1", 0)
        self.port = self.sock.getsockname()[1]

    def tearDown(self):
        self.sock.close()

    def _send(self, data):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(data, ("127.0.0.1", self.port))
        s.close()

    def _drops_everything(self, blobs):
        for b in blobs:
            self._send(b)
        alerts = dashboard.receive(self.sock, timeout=0.5)
        self.assertEqual(alerts, [])

    def test_truncated_json(self):
        self._drops_everything([b'{"severity":3,"module":"x"',
                                b'{"severity":3,"sev_label":"HIGH","modu',
                                b'{"severity":3,"module":"x","ts":1,"sig":"'])

    def test_oversized_message_accepted(self):
        # A validly-signed, large message (within the ~64KiB UDP datagram
        # limit) must not crash the receiver and must be accepted; this
        # exercises the large-field decode/render path.
        big = "Z" * 60000
        self._send(make_payload(3, "big", big))
        alerts = dashboard.receive(self.sock, timeout=1.0)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0]["message"]), 60000)

    def test_wrong_field_types(self):
        # Types that can never match a client-signed canonical: lists / dicts.
        self._drops_everything([
            json.dumps({"severity": [3], "sev_label": "HIGH", "module": "x",
                        "message": "y", "ts": int(time.time()),
                        "sig": "0" * 64}).encode(),
            json.dumps({"severity": 3, "sev_label": "HIGH", "module": "x",
                        "message": {"k": 1}, "ts": int(time.time()),
                        "sig": "0" * 64}).encode(),
            # ts as a string instead of int -> freshness rejects it.
            json.dumps({"severity": 3, "sev_label": "HIGH", "module": "x",
                        "message": "y", "ts": "1690000000",
                        "sig": "0" * 64}).encode(),
        ])

    def test_missing_fields(self):
        self._drops_everything([
            json.dumps({"severity": 3, "sev_label": "HIGH",
                        "message": "y", "ts": int(time.time()),
                        "sig": "0" * 64}).encode(),  # no module
            json.dumps({"severity": 3, "sev_label": "HIGH", "module": "x",
                        "message": "y", "ts": int(time.time())}).encode(),  # no sig
            json.dumps({"module": "x", "message": "y"}).encode(),  # no ts/sig
        ])

    def test_non_utf8_bytes(self):
        self._drops_everything([
            b'\xff\xfe\x00\x80\xbf\x00',
            b'\xc3\x28',  # invalid UTF-8 sequence
            bytes(range(256)),  # all byte values
        ])

    def test_malformed_nonhex_sig(self):
        self._drops_everything([
            json.dumps({"severity": 3, "sev_label": "HIGH", "module": "x",
                        "message": "y", "ts": int(time.time()),
                        "sig": "!!not-hex!!"}).encode(),
            json.dumps({"severity": 3, "sev_label": "HIGH", "module": "x",
                        "message": "y", "ts": int(time.time()),
                        "sig": "zzzzzzzz"}).encode(),
        ])

    def test_wrong_length_sig(self):
        self._drops_everything([
            json.dumps({"severity": 3, "sev_label": "HIGH", "module": "x",
                        "message": "y", "ts": int(time.time()),
                        "sig": "abcd"}).encode(),  # too short
            json.dumps({"severity": 3, "sev_label": "HIGH", "module": "x",
                        "message": "y", "ts": int(time.time()),
                        "sig": "ab" * 100}).encode(),  # too long
        ])


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
