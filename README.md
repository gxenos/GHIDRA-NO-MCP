# GHIDRA-NO-MCP

**AI Reverse Engineering, Zero MCP.**

Export Ghidra decompilation results as source files for use with AI IDEs.

## Installation

### From PyPI (recommended)
```bash
pip install ghidra-no-mcp
```

### From GitHub (latest)
```bash
uvx git+https://github.com/gxenos/ghidra-no-mcp
```

### Local development
```bash
uv pip install -e .
```

## Usage

```bash
ghidra-no-mcp /path/to/binary /output/dir
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

## License

Apache 2.0
