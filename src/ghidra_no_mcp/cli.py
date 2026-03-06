import argparse
import logging
import os
import sys
import tempfile
from pathlib import Path

import pyghidra
from pyghidra import program_loader

from ghidra_no_mcp.exporter import GhidraExporter

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


def main():
    parser = argparse.ArgumentParser(
        description="Export Ghidra analysis for AI - Zero MCP, maximum compatibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/binary /output/dir
  %(prog)s ./my_binary ./ai_export
  %(prog)s /bin/ls ./ls_export
        """,
    )
    parser.add_argument(
        "binary",
        help="Path to the binary to analyze",
        type=Path,
    )
    parser.add_argument(
        "output_dir",
        help="Output directory for exported files",
        type=Path,
    )
    parser.add_argument(
        "-g",
        "--ghidra-path",
        help="Path to Ghidra installation (or set GHIDRA_INSTALL_DIR)",
        type=Path,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--no-memory",
        action="store_true",
        help="Skip memory hexdump export",
    )
    parser.add_argument(
        "--no-strings",
        action="store_true",
        help="Skip string extraction",
    )
    parser.add_argument(
        "--no-imports",
        action="store_true",
        help="Skip import table export",
    )
    parser.add_argument(
        "--no-exports",
        action="store_true",
        help="Skip export table export",
    )
    parser.add_argument(
        "--decompiler-timeout",
        type=int,
        default=0,
        help="Timeout per function in seconds (0 = unlimited, default: 0)",
    )
    parser.add_argument(
        "--max-payload",
        type=int,
        default=100,
        help="Max decompiler payload size in MB (default: 100)",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    binary_path = args.binary.resolve()
    output_dir = args.output_dir.resolve()

    if not binary_path.exists():
        print(f"Error: Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    ghidra_path = args.ghidra_path
    if ghidra_path:
        ghidra_path = ghidra_path.resolve()
        if not ghidra_path.exists():
            print(f"Error: Ghidra not found at {ghidra_path}", file=sys.stderr)
            sys.exit(1)
    else:
        ghidra_path = os.environ.get("GHIDRA_INSTALL_DIR")
        if ghidra_path:
            ghidra_path = Path(ghidra_path)
            if not ghidra_path.exists():
                print(
                    f"Error: GHIDRA_INSTALL_DIR points to non-existent path: {ghidra_path}",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            print(
                "Error: GHIDRA_INSTALL_DIR not set.\n"
                "Download Ghidra from https://github.com/NationalSecurityAgency/ghidra\n"
                "Then set: export GHIDRA_INSTALL_DIR=/path/to/ghidra",
                file=sys.stderr,
            )
            sys.exit(1)

    print(f"Loading: {binary_path}")
    print(f"Output:  {output_dir}")
    print(f"Ghidra:  {ghidra_path}")
    print()

    try:
        pyghidra.start(verbose=args.verbose, install_dir=ghidra_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            loader = program_loader()
            loader.source(str(binary_path))
            results = loader.load()
            loaded = results.getPrimary()
            program = loaded.getDomainObject()

            exporter = GhidraExporter(
                program,
                skip_memory=args.no_memory,
                skip_strings=args.no_strings,
                skip_imports=args.no_imports,
                skip_exports=args.no_exports,
                decompiler_timeout=args.decompiler_timeout,
                max_payload_mb=args.max_payload,
            )
            exporter.export_all(output_dir)

        print()
        print(f"Export complete! Files written to: {output_dir}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
