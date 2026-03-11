# GHIDRA-NO-MCP

Export Ghidra decompilation results as source files for use with AI IDEs. 

Runs from cmd, uses pyghidra and headless mode and doesn't require the Ghidra GUI.

**Just copy-paste the uvx command into the agent or skill.**

Inspired by: https://github.com/P4nda0s/IDA-NO-MCP

> Text, Source Code, and Shell are LLM's native languages.

## Installation

### With uvx from GitHub
```bash
uvx git+https://github.com/gxenos/ghidra-no-mcp
```

### Local developement 

```bash
uv venv && uv pip install -e .
```

## Usage

```bash
uv run ghidra-no-mcp -g /path/to/GHIDRA /path/to/binary /output/dir
```

### Options

| Option | Description |
|--------|-------------|
| `-g, --ghidra-path` | Path to Ghidra installation |
| `-v, --verbose` | Enable verbose logging |

### Examples

```bash
# Using environment variable
export GHIDRA_INSTALL_DIR=/opt/ghidra/ghidra_12.0.4_PUBLIC
uv run ghidra-no-mcp ./malware.exe ./analysis

# Using CLI argument
uv run ghidra-no-mcp -g /opt/ghidra ./malware.exe ./analysis

# With uvx
GHIDRA_INSTALL_DIR=/opt/ghidra uvx git+https://github.com/gxenos/ghidra-no-mcp ./malware.exe ./analysis
```

## Output

| Directory/File | Description |
|---------------|-------------|
| `call_graph.json` | Function call graph (nodes + edges), includes function names, addresses, caller/callee counts |
| `decompile/` | Decompiled C files (one per function), includes function name, address, callers, callees|
| `strings.txt` | String table |
| `imports.txt` | Import table |
| `exports.txt` | Export table |
| `memory/` | Memory hexdumps, 1MB chunks|
| `decompile_skipped.txt` | Skipped functions |
| `decompile_failed.txt` | Failed functions |

Each `.c` file includes metadata header:
```c
/*
 * func-name: main
 * func-address: 0x401000
 * callers: 0x402000
 * callees: 0x404000
 */
```

The `call_graph.json` file contains the full call graph:
```json
{
  "nodes": [
    {"address": "0x401000", "name": "main", "is_external": false, "caller_count": 0, "callee_count": 2},
    {"address": "0x402000", "name": "validate_input", "is_external": false, "caller_count": 1, "callee_count": 3}
  ],
  "edges": [
    {"caller": "0x401000", "caller_name": "main", "callee": "0x402000", "callee_name": "validate_input"}
  ],
  "stats": {"total_functions": 150, "total_calls": 342, "external_calls": 45}
}
```

## Analysis

By default, the script runs Ghidra with the default analysis options.

### Analysis Options

| Option | Description |
|--------|-------------|
| `--no-memory` | Skip memory hexdump export |
| `--no-strings` | Skip string extraction |
| `--no-imports` | Skip import table export |
| `--no-exports` | Skip export table export |
| `--decompiler-timeout` | Timeout per function in seconds (0 = unlimited, default: 0) |
| `--max-payload` | Max decompiler payload size in MB (default: 100) |
