from __future__ import annotations

import unittest
from pathlib import Path

from cwrappers.finder.compile_commands import (
    _sanitize_clang_args_for_libclang,
    make_retry_clang_args,
)


class CompileCommandSanitizerTests(unittest.TestCase):
    def test_sanitizer_preserves_semantically_important_compile_flags(self) -> None:
        args = [
            "clang++",
            "-std",
            "c++17",
            "-m64",
            "-U",
            "OLD_MACRO",
            "-D",
            "NEW_MACRO=1",
            "-stdlib=libc++",
            "-c",
            "src.cpp",
            "-o",
            "src.o",
        ]

        sanitized = _sanitize_clang_args_for_libclang(
            args,
            Path("/repo/src.cpp"),
            Path("/repo"),
        )

        self.assertIn("-std", sanitized)
        self.assertIn("c++17", sanitized)
        self.assertIn("-m64", sanitized)
        self.assertIn("-U", sanitized)
        self.assertIn("OLD_MACRO", sanitized)
        self.assertIn("-D", sanitized)
        self.assertIn("NEW_MACRO=1", sanitized)
        self.assertIn("-stdlib=libc++", sanitized)
        self.assertNotIn("-o", sanitized)
        self.assertNotIn("src.o", sanitized)

    def test_retry_args_strip_arch_flags_but_keep_language_flags(self) -> None:
        cleaned = make_retry_clang_args(
            [
                "-x",
                "c++",
                "-std",
                "c++17",
                "-m64",
                "-I",
                "/repo/include",
            ]
        )

        self.assertEqual(cleaned, ["-x", "c++", "-std", "c++17", "-I", "/repo/include"])


if __name__ == "__main__":
    unittest.main()
