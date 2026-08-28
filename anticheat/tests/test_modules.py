#!/usr/bin/env python3
"""End-to-end tests for the detection modules that need a live process.

These drive the built `anticheat` binary (and a ptrace tracer helper) and
assert on its human-readable stdout, covering:

  * memguard live-patch self-test detection
  * debugger detection (clean vs. traced)
  * MEDIUM -> HIGH escalation when a VM is confirmed alongside a debugger
"""
import os
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ANTICHEAT_BIN = os.path.join(REPO, "anticheat")
TRACER_BIN = os.path.join(HERE, "ptrace_tracer")


def _combined(proc):
    out = (proc.stdout or b"") + (proc.stderr or b"")
    return out.decode("utf-8", "replace")


class ModuleBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(ANTICHEAT_BIN):
            raise unittest.SkipTest(
                "anticheat binary not built (run `make` first)")
        if not os.path.exists(TRACER_BIN):
            raise unittest.SkipTest(
                "ptrace_tracer helper not built (run `make` first)")

    def _run(self, cmd, env=None, timeout=30):
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        return subprocess.run(
            cmd, env=full_env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout)

    def test_memguard_selftest_detects_patch(self):
        # NB: -q would suppress the finding line, so run verbose.
        proc = self._run([ANTICHEAT_BIN, "-s"], timeout=30)
        out = _combined(proc).lower()
        self.assertIn(
            "live patch was detected",
            out,
            "memguard self-test should report a detected live patch")

    def test_debugger_clean(self):
        proc = self._run([ANTICHEAT_BIN], timeout=30)
        out = _combined(proc).lower()
        self.assertIn(
            "no debugger attached to this process",
            out,
            "untraced run should report no debugger")

    def test_debugger_traced(self):
        proc = self._run([TRACER_BIN, ANTICHEAT_BIN], timeout=30)
        out = _combined(proc).lower()
        self.assertIn(
            "this process is being traced or debugged",
            out,
            "ptraced run should report an attached debugger")

    def test_vm_debugger_escalation(self):
        env = {"ANTICHEAT_TEST_HV_SIG": "VMwareVMware"}
        proc = self._run([TRACER_BIN, ANTICHEAT_BIN], env=env, timeout=30)
        out = _combined(proc).lower()
        self.assertIn(
            "reverse-engineering sandbox",
            out,
            "VM + debugger should escalate to HIGH (reverse-engineering sandbox)")


if __name__ == "__main__":
    unittest.main()
