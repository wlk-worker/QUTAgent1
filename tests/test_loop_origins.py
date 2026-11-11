"""Regression: platform service origins must keep the real http/https scheme."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.loop import _service_origins  # noqa: E402


class _Task:
    def __init__(self, raw=None):
        self.raw = raw or {}


class ServiceOriginTests(unittest.TestCase):
    def test_https_service_keeps_https_and_default_port(self):
        self.assertEqual(
            _service_origins(_Task(), {"services": [
                {"service_type": "https", "host": "a.example", "port": 443}]}),
            ["https://a.example"],
        )

    def test_http_service_keeps_explicit_port(self):
        self.assertEqual(
            _service_origins(_Task(), {"services": [
                {"service_type": "http", "host": "a.example", "port": 8080}]}),
            ["http://a.example:8080"],
        )

    def test_https_without_port(self):
        self.assertEqual(
            _service_origins(_Task(), {"target_services": [
                {"service_type": "https", "host": "b.example"}]}),
            ["https://b.example"],
        )

    def test_non_http_service_is_not_an_http_origin(self):
        self.assertEqual(
            _service_origins(_Task(), {"services": [
                {"service_type": "tcp", "host": "pwn.example", "port": 31337}]}),
            [],
        )

    def test_explicit_url_is_normalized(self):
        self.assertEqual(
            _service_origins(_Task(), {"attack_surface": {"services": [
                {"url": "https://c.example:443/"}]}}),
            ["https://c.example"],
        )


if __name__ == "__main__":
    unittest.main()
