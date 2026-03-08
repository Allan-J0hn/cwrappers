from __future__ import annotations

import unittest

from cwrappers.finder.callgraph import DetailedEdge, FunctionDef
from cwrappers.finder.runner import _trace_reachable_callee_names


class RunnerCalleeTracingTests(unittest.TestCase):
    def test_reachable_callee_names_include_transitive_and_external_calls(self) -> None:
        function_defs = {
            "usr:foo": FunctionDef(function_key="usr:foo", function="foo", file="/repo/foo.c", line=1),
            "usr:helper": FunctionDef(function_key="usr:helper", function="helper", file="/repo/helper.c", line=1),
        }
        edges = [
            DetailedEdge(
                caller_key="usr:foo",
                callee_key="usr:helper",
                caller="foo",
                callee="helper",
                loc="/repo/foo.c:10:3",
                translation_unit="/repo/foo.c",
            ),
            DetailedEdge(
                caller_key="usr:helper",
                callee_key="malloc@<unknown>",
                caller="helper",
                callee="malloc",
                loc="/repo/helper.c:12:3",
                translation_unit="/repo/helper.c",
            ),
        ]

        reachable = _trace_reachable_callee_names(edges, function_defs)

        self.assertEqual(reachable["usr:foo"], ["helper", "malloc"])
        self.assertEqual(reachable["usr:helper"], ["malloc"])


if __name__ == "__main__":
    unittest.main()
