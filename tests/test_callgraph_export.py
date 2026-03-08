from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from cwrappers.finder.callgraph import DetailedEdge, FunctionDef, write_callgraph
from cwrappers.finder.models import TranslationUnitReport


class CallgraphExportTests(unittest.TestCase):
    def test_write_callgraph_preserves_same_callsite_across_translation_units(self) -> None:
        edges = [
            DetailedEdge(
                caller_key="c:helper.h@F@inline_call",
                callee_key="c:@F@foo",
                caller="inline_call",
                callee="foo",
                loc="/repo/helper.h:12:7",
                translation_unit="/repo/a.c",
            ),
            DetailedEdge(
                caller_key="c:helper.h@F@inline_call",
                callee_key="c:@F@foo",
                caller="inline_call",
                callee="foo",
                loc="/repo/helper.h:12:7",
                translation_unit="/repo/b.c",
            ),
        ]
        project_defs = [
            FunctionDef(function_key="c:helper.h@F@inline_call", function="inline_call", file="/repo/helper.h", line=1),
            FunctionDef(function_key="c:@F@foo", function="foo", file="/repo/foo.c", line=3),
        ]
        tu_reports = [
            TranslationUnitReport(
                translation_unit="/repo/a.c",
                parse_succeeded=True,
                retry_used=False,
                diagnostic_ignored_count=0,
                diagnostic_note_count=0,
                diagnostic_warning_count=0,
                diagnostic_error_count=1,
                diagnostic_fatal_count=0,
                total_diagnostic_count=1,
                had_errors=True,
                parse_failure="",
            ),
            TranslationUnitReport(
                translation_unit="/repo/b.c",
                parse_succeeded=True,
                retry_used=True,
                diagnostic_ignored_count=0,
                diagnostic_note_count=0,
                diagnostic_warning_count=1,
                diagnostic_error_count=0,
                diagnostic_fatal_count=0,
                total_diagnostic_count=1,
                had_errors=False,
                parse_failure="",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            write_callgraph(out_dir, edges, project_function_defs=project_defs, tu_reports=tu_reports)

            with open(out_dir / "callgraph_edges.csv", newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))

            self.assertEqual(len(rows), 2)
            self.assertEqual(
                list(rows[0].keys()),
                [
                    "caller",
                    "caller_key",
                    "caller_project_key",
                    "caller_in_project",
                    "callee",
                    "callee_key",
                    "callee_project_key",
                    "callee_in_project",
                    "callsite",
                    "callsite_file",
                    "callsite_line",
                    "callsite_column",
                    "translation_unit",
                ],
            )
            self.assertEqual(
                [row["translation_unit"] for row in rows],
                ["/repo/a.c", "/repo/b.c"],
            )
            self.assertTrue(all(row["caller_in_project"] == "TRUE" for row in rows))
            self.assertTrue(all(row["callee_in_project"] == "TRUE" for row in rows))
            self.assertTrue(all(row["callsite_file"] == "/repo/helper.h" for row in rows))
            self.assertTrue(all(row["callsite_line"] == "12" for row in rows))
            self.assertTrue(all(row["callsite_column"] == "7" for row in rows))

            with open(out_dir / "call_counts.csv", newline="", encoding="utf-8") as f:
                counts = list(csv.DictReader(f))

            self.assertEqual(len(counts), 1)
            self.assertEqual(counts[0]["callee_name"], "foo")
            self.assertEqual(counts[0]["total_calls"], "2")
            self.assertEqual(counts[0]["unique_callsite_count"], "1")
            self.assertEqual(counts[0]["unique_translation_unit_count"], "2")
            self.assertEqual(counts[0]["unique_caller_count"], "1")
            self.assertEqual(counts[0]["unique_caller_name_count"], "1")
            self.assertEqual(counts[0]["caller_names"], "inline_call")
            self.assertEqual(counts[0]["translation_units"], "/repo/a.c;/repo/b.c")

            with open(out_dir / "function_fan_summary.csv", newline="", encoding="utf-8") as f:
                summary_rows = list(csv.DictReader(f))

            summary_by_name = {row["function"]: row for row in summary_rows}
            self.assertEqual(summary_by_name["foo"]["fan_in"], "1")
            self.assertEqual(summary_by_name["foo"]["incoming_edge_count"], "2")
            self.assertEqual(summary_by_name["inline_call"]["fan_out"], "1")
            self.assertEqual(summary_by_name["inline_call"]["outgoing_edge_count"], "2")

            with open(out_dir / "translation_units.csv", newline="", encoding="utf-8") as f:
                tu_rows = list(csv.DictReader(f))

            self.assertEqual(len(tu_rows), 2)
            self.assertEqual(tu_rows[0]["translation_unit"], "/repo/a.c")
            self.assertEqual(tu_rows[0]["diagnostic_error_count"], "1")
            self.assertEqual(tu_rows[0]["had_errors"], "TRUE")
            self.assertEqual(tu_rows[0]["exported_edge_count"], "1")
            self.assertEqual(tu_rows[1]["retry_used"], "TRUE")

    def test_write_callgraph_can_sort_by_unique_callers(self) -> None:
        edges = [
            DetailedEdge(
                caller_key="c:@F@a1",
                callee_key="c:@F@alpha",
                caller="a1",
                callee="alpha",
                loc="/repo/a.c:1:1",
                translation_unit="/repo/a.c",
            ),
            DetailedEdge(
                caller_key="c:@F@a2",
                callee_key="c:@F@alpha",
                caller="a2",
                callee="alpha",
                loc="/repo/a.c:2:1",
                translation_unit="/repo/a.c",
            ),
            DetailedEdge(
                caller_key="c:@F@b1",
                callee_key="c:@F@beta",
                caller="b1",
                callee="beta",
                loc="/repo/b.c:1:1",
                translation_unit="/repo/b.c",
            ),
            DetailedEdge(
                caller_key="c:@F@b1",
                callee_key="c:@F@beta",
                caller="b1",
                callee="beta",
                loc="/repo/b.c:2:1",
                translation_unit="/repo/b.c",
            ),
            DetailedEdge(
                caller_key="c:@F@b1",
                callee_key="c:@F@beta",
                caller="b1",
                callee="beta",
                loc="/repo/b.c:3:1",
                translation_unit="/repo/b.c",
            ),
        ]
        project_defs = [
            FunctionDef(function_key="c:@F@a1", function="a1", file="/repo/a.c", line=10),
            FunctionDef(function_key="c:@F@a2", function="a2", file="/repo/a.c", line=11),
            FunctionDef(function_key="c:@F@alpha", function="alpha", file="/repo/a.c", line=20),
            FunctionDef(function_key="c:@F@b1", function="b1", file="/repo/b.c", line=10),
            FunctionDef(function_key="c:@F@beta", function="beta", file="/repo/b.c", line=20),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            write_callgraph(out_dir, edges, unique_callers=False, project_function_defs=project_defs)
            with open(out_dir / "call_counts.csv", newline="", encoding="utf-8") as f:
                default_rows = list(csv.DictReader(f))

            write_callgraph(out_dir, edges, unique_callers=True, project_function_defs=project_defs)
            with open(out_dir / "call_counts.csv", newline="", encoding="utf-8") as f:
                unique_rows = list(csv.DictReader(f))

        self.assertEqual(default_rows[0]["callee_name"], "beta")
        self.assertEqual(unique_rows[0]["callee_name"], "alpha")

    def test_write_callgraph_project_summary_excludes_external_callees(self) -> None:
        edges = [
            DetailedEdge(
                caller_key="c:@F@main",
                callee_key="c:@F@foo",
                caller="main",
                callee="foo",
                loc="/repo/main.c:10:3",
                translation_unit="/repo/main.c",
            ),
            DetailedEdge(
                caller_key="c:@F@main",
                callee_key="write@<unknown>",
                caller="main",
                callee="write",
                loc="/repo/main.c:11:3",
                translation_unit="/repo/main.c",
            ),
        ]
        project_defs = [
            FunctionDef(function_key="c:@F@main", function="main", file="/repo/main.c", line=1),
            FunctionDef(function_key="c:@F@foo", function="foo", file="/repo/foo.c", line=1),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            write_callgraph(out_dir, edges, project_function_defs=project_defs, tu_reports=[])

            with open(out_dir / "callgraph_edges.csv", newline="", encoding="utf-8") as f:
                edge_rows = list(csv.DictReader(f))
            with open(out_dir / "call_counts.csv", newline="", encoding="utf-8") as f:
                count_rows = list(csv.DictReader(f))
            with open(out_dir / "function_fan_summary.csv", newline="", encoding="utf-8") as f:
                summary_rows = list(csv.DictReader(f))

        self.assertEqual([row["callee"] for row in edge_rows], ["foo", "write"])
        self.assertEqual([row["callee_in_project"] for row in edge_rows], ["TRUE", "FALSE"])
        self.assertEqual([row["callee_name"] for row in count_rows], ["foo"])

        summary_by_name = {row["function"]: row for row in summary_rows}
        self.assertEqual(summary_by_name["main"]["fan_out"], "2")
        self.assertEqual(summary_by_name["main"]["callee_names"], "foo;write")
        self.assertEqual(summary_by_name["foo"]["fan_in"], "1")


if __name__ == "__main__":
    unittest.main()
