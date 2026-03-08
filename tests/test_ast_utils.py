from __future__ import annotations

import unittest
from types import SimpleNamespace

from cwrappers.finder.ast_utils import _callsite_loc


class AstUtilsTests(unittest.TestCase):
    def test_callsite_loc_keeps_unknown_file_locations(self) -> None:
        call = SimpleNamespace(
            location=SimpleNamespace(
                file=None,
                line=17,
                column=9,
            )
        )

        self.assertEqual(_callsite_loc(call), "<unknown>:17:9")


if __name__ == "__main__":
    unittest.main()
