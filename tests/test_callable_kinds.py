from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cwrappers.finder.callgraph import (
    collect_callgraph_for_tu_detailed,
    collect_function_defs_for_tu,
)
from cwrappers.finder.clang_bootstrap import cindex


class CallableKindsTests(unittest.TestCase):
    def test_collectors_include_cpp_methods_constructors_and_destructors(self) -> None:
        source = """
        class Widget {
        public:
          Widget();
          ~Widget();
          void helper();
        };

        void sink();

        Widget::Widget() { helper(); }
        Widget::~Widget() { sink(); }
        void Widget::helper() { sink(); }
        """

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "widget.cpp"
            src.write_text(source, encoding="utf-8")

            tu = cindex.Index.create().parse(
                str(src),
                args=["-x", "c++", "-std=c++17"],
                options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )

            defs = collect_function_defs_for_tu(tu)
            edges, _seen = collect_callgraph_for_tu_detailed(tu, translation_unit=str(src))

        def_names = {fn.function for fn in defs}
        self.assertIn("Widget", def_names)
        self.assertIn("~Widget", def_names)
        self.assertIn("helper", def_names)

        edge_pairs = {(edge.caller, edge.callee) for edge in edges}
        self.assertIn(("Widget", "helper"), edge_pairs)
        self.assertIn(("~Widget", "sink"), edge_pairs)
        self.assertIn(("helper", "sink"), edge_pairs)

        ctor_edges = [edge for edge in edges if edge.caller == "Widget" and edge.callee == "helper"]
        self.assertEqual(len(ctor_edges), 1)
        self.assertFalse(ctor_edges[0].callee_key.endswith("@<unknown>"))


if __name__ == "__main__":
    unittest.main()
