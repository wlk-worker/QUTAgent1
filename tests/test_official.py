"""Official runner pagination: never silently drop challenges after the first page."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.official import _all_challenges, _challenge_ids  # noqa: E402


class _PagedPlatform:
    def __init__(self, total: int):
        self.total = total
        self.offsets = []

    def challenges(self, competition_id: str, *, limit: int = 100, offset: int = 0) -> dict:
        self.offsets.append(offset)
        items = [{"id": f"C-{index}", "name": str(index)}
                 for index in range(offset, min(offset + limit, self.total))]
        return {"items": items, "total": self.total, "limit": limit, "offset": offset}


class OfficialPaginationTests(unittest.TestCase):
    def test_all_challenges_pages_past_one_hundred(self):
        platform = _PagedPlatform(117)
        items = _all_challenges(platform, "comp")
        self.assertEqual(len(items), 117)
        self.assertEqual(items[-1]["id"], "C-116")
        self.assertEqual(platform.offsets, [0, 100])

    def test_requested_challenge_beyond_first_page_is_selectable(self):
        platform = _PagedPlatform(117)
        selected = _challenge_ids(_all_challenges(platform, "comp"), ["C-112"], 4)
        self.assertEqual([item["id"] for item in selected], ["C-112"])


if __name__ == "__main__":
    unittest.main()
