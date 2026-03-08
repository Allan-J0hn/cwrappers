from __future__ import annotations

import unittest

from cwrappers.finder.callgraph import (
    DetailedEdge,
    FunctionDef,
    build_edge_evidence_rows,
    resolve_edge_query,
)


class EdgeEvidenceTests(unittest.TestCase):
    def test_resolve_edge_query_rejects_ambiguous_names(self) -> None:
        defs = [
            FunctionDef(function_key="usr:a", function="target", file="/repo/a.c", line=10),
            FunctionDef(function_key="usr:b", function="target", file="/repo/b.c", line=20),
        ]

        with self.assertRaisesRegex(ValueError, "ambiguous"):
            resolve_edge_query("target", defs)

    def test_build_edge_evidence_rows_preserves_direction_and_translation_unit(self) -> None:
        query = FunctionDef(function_key="usr:foo", function="foo", file="/repo/foo.c", line=10)
        edges = [
            DetailedEdge(
                caller_key="usr:main",
                callee_key="usr:foo",
                caller="main",
                callee="foo",
                loc="/repo/a.c:20:3",
                translation_unit="/repo/a.c",
            ),
            DetailedEdge(
                caller_key="usr:foo",
                callee_key="usr:bar",
                caller="foo",
                callee="bar",
                loc="/repo/a.c:12:3",
                translation_unit="/repo/a.c",
            ),
            DetailedEdge(
                caller_key="usr:inline_call",
                callee_key="foo@<unknown>",
                caller="inline_call",
                callee="foo",
                loc="/repo/helpers.h:4:5",
                translation_unit="/repo/a.c",
            ),
            DetailedEdge(
                caller_key="usr:inline_call",
                callee_key="foo@<unknown>",
                caller="inline_call",
                callee="foo",
                loc="/repo/helpers.h:4:5",
                translation_unit="/repo/b.c",
            ),
            DetailedEdge(
                caller_key="foo@<unknown>",
                callee_key="usr:bar",
                caller="foo",
                callee="bar",
                loc="/repo/helpers.h:8:5",
                translation_unit="/repo/b.c",
            ),
            DetailedEdge(
                caller_key="usr:foo",
                callee_key="usr:foo",
                caller="foo",
                callee="foo",
                loc="/repo/foo.c:30:3",
                translation_unit="/repo/a.c",
            ),
        ]

        rows = build_edge_evidence_rows(query, edges)

        self.assertEqual(len(rows), 7)

        incoming = [row for row in rows if row.direction == "incoming"]
        outgoing = [row for row in rows if row.direction == "outgoing"]
        self.assertEqual(len(incoming), 4)
        self.assertEqual(len(outgoing), 3)

        duplicate_header_rows = [
            row for row in incoming
            if row.callsite_file == "/repo/helpers.h" and row.callsite_line == 4
        ]
        self.assertEqual(
            [row.translation_unit for row in duplicate_header_rows],
            ["/repo/a.c", "/repo/b.c"],
        )
        self.assertTrue(all(row.match_kind == "name_fallback" for row in duplicate_header_rows))

        self_call_rows = [
            row for row in rows
            if row.callsite_file == "/repo/foo.c" and row.callsite_line == 30
        ]
        self.assertEqual(
            sorted((row.direction, row.match_kind) for row in self_call_rows),
            [
                ("incoming", "resolved_key"),
                ("outgoing", "resolved_key"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
