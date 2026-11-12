"""Tolerant action parsing: the three mechanical failure shapes from CTFARENA."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.loop import VALID_ACTIONS, parse_action_ex  # noqa: E402
from agent.repair import repair_parse  # noqa: E402


class RepairTests(unittest.TestCase):
    def test_clean_json_is_not_reported_as_repaired(self):
        action, repaired = parse_action_ex(json.dumps({"action": "shell", "command": "ls"}))
        self.assertEqual(action["action"], "shell")
        self.assertFalse(repaired)

    def test_literal_newline_inside_command(self):
        text = '{"action":"shell","command":"cd /tmp\nfor p in a b; do\n  curl -s $p\ndone"}'
        action, repaired = parse_action_ex(text)
        self.assertTrue(repaired)
        self.assertEqual(action["action"], "shell")
        self.assertIn("curl -s $p", action["command"])

    def test_unescaped_quote_inside_command(self):
        text = '{"action":"shell","command":"grep -oE "(api|vault)" index.html -- $" }'
        repaired = repair_parse(text, VALID_ACTIONS)
        self.assertIsNotNone(repaired)
        self.assertEqual(repaired["action"], "shell")

    def test_truncated_string_is_closed(self):
        text = '{"action":"shell","command":"curl -sk https://h/api/xhr/3b26'
        repaired = repair_parse(text, VALID_ACTIONS)
        self.assertIsNotNone(repaired)
        self.assertEqual(repaired["action"], "shell")
        self.assertTrue(repaired["command"].startswith("curl -sk"))

    def test_prose_then_json_is_recovered(self):
        text = 'Let me check the vault.\n{"action":"shell","command":"cat vault.html"}'
        action, _repaired = parse_action_ex(text)
        self.assertEqual(action["action"], "shell")


if __name__ == "__main__":
    unittest.main()
