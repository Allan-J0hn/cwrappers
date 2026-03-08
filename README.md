# cwrappers

`cwrappers` is a Python CLI toolkit for finding wrapper-like C/C++ functions (libc/syscall oriented) and optionally ranking them with fuzzy matching.

It is designed around `compile_commands.json` and Clang AST parsing.

## Install

Editable install:

```bash
python3 -m pip install -e .
```

This exposes three console scripts:

- `cwrappers`
- `cwrappers-finder`
- `cwrappers-fuzzy`

## Quick Start

Finder only:

```bash
cwrappers-finder \
  --compile-commands /path/to/compile_commands.json \
  --out wrappers.csv
```

Fuzzy scoring only:

```bash
cwrappers-fuzzy wrappers.csv
```

Combined pipeline:

```bash
cwrappers pipeline \
  --compile-commands /path/to/compile_commands.json \
  --out wrappers.csv \
  --fuzzy
```

Callgraph-only export:

```bash
cwrappers-finder \
  --compile-commands /path/to/compile_commands.json \
  --callgraph-only \
  --callgraph-out /path/to/callgraph_out
```

Single-function raw edge evidence export:

```bash
cwrappers-finder \
  --compile-commands /path/to/compile_commands.json \
  --edge-evidence target_function \
  --out target_function_edges.csv
```

`--callgraph-only` writes:

- `callgraph_edges.csv`: raw edge rows, including `caller_in_project` / `callee_in_project`
- `call_counts.csv`: project-only per-callee incoming aggregates for project-defined callees
- `function_fan_summary.csv`: project-only per-function `fan_in` / `fan_out` summary, while still reflecting external callers/callees on those project rows
- `translation_units.csv`: per-translation-unit parse diagnostics and exported-edge counts

## Catalog YAML

`cwrappers` ships with a bundled default catalog at `cwrappers/data/categorized_methods.yaml`.

- `cwrappers-finder` uses it automatically when `--yaml` is not provided.
- `cwrappers-fuzzy` uses it automatically when `--yaml` is not provided.
- You can always override with `--yaml /path/to/custom.yaml`.

## Command Overview

Unified CLI:

```bash
cwrappers --help
cwrappers finder --help
cwrappers fuzzy --help
cwrappers pipeline --help
```

Direct subtool CLIs:

```bash
cwrappers-finder --help
cwrappers-fuzzy --help
```

## Requirements

- Python 3.9+
- Clang/libclang available in your environment
- A valid `compile_commands.json` (for finder/pipeline)

## Project Layout

This repository uses a flat layout for packaging:

```text
pyproject.toml
README.md
cwrappers/
  __init__.py
  cli.py
  data/
  finder/
  fuzzy/
  shared/
```

## License

MIT
