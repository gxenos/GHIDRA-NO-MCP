# GHIDRA-NO-MCP

Export Ghidra decompilation results as source files for use with AI IDEs.

Inspired by: https://github.com/P4nda0s/IDA-NO-MCP

> Text, Source Code, and Shell are LLM's native languages.

## Installation

### Local developement 

```bash
uv venv && uv pip install -e .
uv venv  uv pip install -e .
```

### With uvx from GitHub
```bash
uvx git+https://github.com/gxenos/ghidra-no-mcp
```

## Usage

```bash
ghidra-no-mcp -g /path/to/GHIDRA /path/to/binary /output/dir
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
ghidra-no-mcp ./malware.exe ./analysis

# Using CLI argument
ghidra-no-mcp -g /opt/ghidra ./malware.exe ./analysis

# With uvx
GHIDRA_INSTALL_DIR=/opt/ghidra uvx git+https://github.com/gxenos/ghidra-no-mcp ./malware.exe ./analysis
```

## Output

| Directory/File | Description |
|---------------|-------------|
| `decompile/` | Decompiled C files (one per function) |
| `strings.txt` | String table |
| `imports.txt` | Import table |
| `exports.txt` | Export table |
| `memory/` | Memory hexdumps |
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
