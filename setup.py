"""Compatibility setup.py for older setuptools/pip editable installs."""

from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).resolve().parent
README = (ROOT / "README.md").read_text(encoding="utf-8")

about: dict[str, str] = {}
exec((ROOT / "cwrappers" / "__init__.py").read_text(encoding="utf-8"), about)

setup(
    name="cwrappers",
    version=about["__version__"],
    description="Wrapper detection and fuzzy scoring for C codebases",
    long_description=README,
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    packages=find_packages(include=["cwrappers", "cwrappers.*"]),
    include_package_data=True,
    package_data={"cwrappers": ["data/*.yaml"]},
    install_requires=[
        "pyyaml>=6.0",
        "clang>=14.0",
        "rapidfuzz>=3.0",
    ],
    entry_points={
        "console_scripts": [
            "cwrappers=cwrappers.cli:main",
            "cwrappers-finder=cwrappers.finder.cli:main",
            "cwrappers-fuzzy=cwrappers.fuzzy.cli:main",
        ]
    },
)
