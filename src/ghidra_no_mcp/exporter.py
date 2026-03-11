import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults, DecompInterface
    from ghidra.program.model.listing import Function, Program
    from ghidra.program.model.symbol import Symbol
    from ghidra.program.model.mem import MemoryBlock

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


class GhidraExporter:
    def __init__(
        self,
        program: "Program",
        skip_memory: bool = False,
        skip_strings: bool = False,
        skip_imports: bool = False,
        skip_exports: bool = False,
        decompiler_timeout: int = 0,
        max_payload_mb: int = 100,
    ):
        self.program = program
        self.skip_memory = skip_memory
        self.skip_strings = skip_strings
        self.skip_imports = skip_imports
        self.skip_exports = skip_exports
        self.decompiler_timeout = decompiler_timeout
        self.max_payload_mb = max_payload_mb
        self.decompiler = self._setup_decompiler()
        self.stats = {
            "total_functions": 0,
            "exported": 0,
            "skipped": 0,
            "failed": 0,
            "memory_files": 0,
            "memory_bytes": 0,
        }

    def _setup_decompiler(self) -> "DecompInterface":
        from ghidra.app.decompiler import DecompileOptions, DecompInterface

        prog_options = DecompileOptions()
        prog_options.grabFromProgram(self.program)
        prog_options.setMaxPayloadMBytes(self.max_payload_mb)

        decomp = DecompInterface()
        decomp.setOptions(prog_options)
        decomp.openProgram(self.program)
        return decomp

    def export_all(self, output_dir: Path) -> dict:
        import pyghidra

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Exporting to: {output_dir}")
        logger.info("-" * 50)

        logger.info("Analyzing program...")
        pyghidra.analyze(self.program)
        logger.info("Analysis complete.")

        self.export_call_graph(output_dir)
        self.export_functions(output_dir)

        if not self.skip_strings:
            self.export_strings(output_dir)
        else:
            logger.info("  Strings: skipped")

        if not self.skip_imports:
            self.export_imports(output_dir)
        else:
            logger.info("  Imports: skipped")

        if not self.skip_exports:
            self.export_exports(output_dir)
        else:
            logger.info("  Exports: skipped")

        if not self.skip_memory:
            self.export_memory(output_dir)
        else:
            logger.info("  Memory: skipped")

        self._print_statistics()
        return self.stats

    def export_call_graph(self, output_dir: Path):
        import json

        graph_file = output_dir / "call_graph.json"
        fm = self.program.getFunctionManager()
        functions = list(fm.getFunctions(True))

        nodes = []
        edges = []
        address_to_func = {}

        logger.info("Building call graph...")

        for func in functions:
            addr = str(func.getEntryPoint())
            address_to_func[addr] = {
                "address": addr,
                "name": func.getName(),
                "is_external": func.isExternal(),
            }

        external_calls = 0

        for func in functions:
            caller_addr = str(func.getEntryPoint())
            caller_name = func.getName()

            try:
                called_funcs = func.getCalledFunctions()
                if called_funcs:
                    for callee in called_funcs:
                        callee_addr = str(callee.getEntryPoint())
                        callee_name = callee.getName()

                        if callee.isExternal():
                            external_calls += 1

                        edges.append(
                            {
                                "caller": caller_addr,
                                "caller_name": caller_name,
                                "callee": callee_addr,
                                "callee_name": callee_name,
                            }
                        )
            except Exception:
                pass

        for func in functions:
            addr = str(func.getEntryPoint())
            name = func.getName()
            is_external = func.isExternal()

            caller_count = 0
            callee_count = 0

            try:
                calling_funcs = func.getCallingFunctions()
                if calling_funcs:
                    caller_count = len(list(calling_funcs))
            except Exception:
                pass

            try:
                called_funcs = func.getCalledFunctions()
                if called_funcs:
                    callee_count = len(list(called_funcs))
            except Exception:
                pass

            nodes.append(
                {
                    "address": addr,
                    "name": name,
                    "is_external": is_external,
                    "caller_count": caller_count,
                    "callee_count": callee_count,
                }
            )

        graph_data = {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_functions": len(nodes),
                "total_calls": len(edges),
                "external_calls": external_calls,
            },
        }

        with open(graph_file, "w") as f:
            json.dump(graph_data, f, indent=2)

        logger.info(f"  Call graph: {len(nodes)} nodes, {len(edges)} edges")

    def export_functions(self, output_dir: Path):
        from ghidra.util.task import ConsoleTaskMonitor

        decompile_dir = output_dir / "decompile"
        decompile_dir.mkdir(parents=True, exist_ok=True)

        failed_file = output_dir / "decompile_failed.txt"
        skipped_file = output_dir / "decompile_skipped.txt"

        monitor = ConsoleTaskMonitor()
        fm = self.program.getFunctionManager()
        functions = list(fm.getFunctions(True))

        self.stats["total_functions"] = len(functions)

        failed_count = 0
        skipped_count = 0

        logger.info(f"Exporting {len(functions)} functions...")

        with open(failed_file, "w") as failed_f, open(skipped_file, "w") as skipped_f:
            for i, func in enumerate(functions):
                if i > 0 and i % 100 == 0:
                    logger.info(f"  Progress: {i}/{len(functions)}")

                func_name = func.getName()
                func_addr = str(func.getEntryPoint())

                if func.isExternal() or func.isThunk():
                    skipped_f.write(f"{func_addr}:{func_name} (external/thunk)\n")
                    skipped_count += 1
                    self.stats["skipped"] += 1
                    continue

                try:
                    result: "DecompileResults" = self.decompiler.decompileFunction(
                        func, self.decompiler_timeout, monitor
                    )
                    if result.getErrorMessage():
                        failed_f.write(
                            f"{func_addr}:{func_name} - {result.getErrorMessage()}\n"
                        )
                        failed_count += 1
                        self.stats["failed"] += 1
                        continue

                    code = result.decompiledFunction.getC()
                    content = self._build_function_file(func, code)

                    filename = self._sanitize_filename(func_name) + ".c"
                    filepath = decompile_dir / filename
                    filepath.write_text(content)

                    self.stats["exported"] += 1

                except Exception as e:
                    failed_f.write(f"{func_addr}:{func_name} - {str(e)}\n")
                    failed_count += 1
                    self.stats["failed"] += 1

        logger.info(f"  Decompiled: {self.stats['exported']} functions")
        logger.info(f"  Skipped: {skipped_count} (external/thunk)")
        logger.info(f"  Failed: {failed_count}")

    def _build_function_file(self, func: "Function", code: str) -> str:
        func_name = func.getName()
        func_addr = str(func.getEntryPoint())

        callers = []
        callees = []

        try:
            calling_funcs = func.getCallingFunctions()
            if calling_funcs:
                callers = [str(f.getEntryPoint()) for f in calling_funcs]
        except Exception:
            pass

        try:
            called_funcs = func.getCalledFunctions()
            if called_funcs:
                callees = [str(f.getEntryPoint()) for f in called_funcs]
        except Exception:
            pass

        callers_str = ", ".join(callers) if callers else "none"
        callees_str = ", ".join(callees) if callees else "none"

        header = f"""/*
 * func-name: {func_name}
 * func-address: {func_addr}
 * callers: {callers_str}
 * callees: {callees_str}
 */

"""
        return header + code

    def _sanitize_filename(self, name: str) -> str:
        import re

        name = name.replace("/", "_").replace("\\", "_")
        name = re.sub(r"[^\w\-_.]", "_", name)
        if len(name) > 200:
            name = name[:200]
        return name

    def export_strings(self, output_dir: Path):
        strings_file = output_dir / "strings.txt"
        count = 0

        listing = self.program.getListing()
        data_iter = listing.getDefinedData(True)

        with open(strings_file, "w") as f:
            for data in data_iter:
                try:
                    dt = data.getDataType()
                    dt_name = dt.getName()

                    if (
                        "char" not in dt_name.lower()
                        and "string" not in dt_name.lower()
                    ):
                        continue

                    addr = str(data.getAddress())
                    value = data.getValue()
                    length = len(str(value))

                    f.write(f"{addr}:{length}:{dt_name}:{value}\n")
                    count += 1
                except Exception as e:
                    logger.debug(f"Failed to get string: {e}")

        logger.info(f"  Strings: {count} exported")

    def export_imports(self, output_dir: Path):
        imports_file = output_dir / "imports.txt"
        count = 0

        st = self.program.getSymbolTable()
        external_symbols = st.getExternalSymbols()

        with open(imports_file, "w") as f:
            for symbol in external_symbols:
                library = str(symbol.getParentNamespace())
                name = symbol.getName()
                f.write(f"{library}:{name}\n")
                count += 1

        logger.info(f"  Imports: {count} exported")

    def export_exports(self, output_dir: Path):
        exports_file = output_dir / "exports.txt"
        count = 0

        st = self.program.getSymbolTable()
        all_symbols = st.getAllSymbols(True)

        with open(exports_file, "w") as f:
            for symbol in all_symbols:
                if symbol.isExternalEntryPoint():
                    addr = str(symbol.getAddress())
                    name = symbol.getName()
                    f.write(f"{addr}:{name}\n")
                    count += 1

        logger.info(f"  Exports: {count} exported")

    def export_memory(self, output_dir: Path):
        memory_dir = output_dir / "memory"
        memory_dir.mkdir(parents=True, exist_ok=True)

        mem = self.program.getMemory()
        blocks = mem.getBlocks()

        MAX_SIZE = 1024 * 1024
        file_count = 0
        total_bytes = 0

        for block in blocks:
            if block.isOverlay():
                continue

            if not block.isInitialized():
                continue

            start = block.getStart()
            end = block.getEnd()
            size = block.getSize()

            if size <= 0:
                continue

            logger.info(f"  Memory: {start} - {end} ({size} bytes)")

            offset = 0

            while offset < size:
                chunk_size = min(size - offset, MAX_SIZE)
                chunk_start_addr = start.add(offset)

                try:
                    content = self._read_hexdump(chunk_start_addr, chunk_size)

                    filename = (
                        f"{chunk_start_addr}--{chunk_start_addr.add(chunk_size)}.txt"
                    )
                    filepath = memory_dir / filename
                    filepath.write_text(content)

                    file_count += 1
                    total_bytes += chunk_size
                except Exception as e:
                    logger.debug(
                        f"    Failed to read memory at {chunk_start_addr}: {e}"
                    )

                offset += chunk_size

        self.stats["memory_files"] = file_count
        self.stats["memory_bytes"] = total_bytes

        logger.info(f"  Memory: {file_count} files ({total_bytes} bytes)")

    def _read_hexdump(self, start, size: int) -> str:
        from jpype import JByte

        mem = self.program.getMemory()
        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(start, buf)

        if n <= 0:
            return ""

        data = [b & 0xFF for b in buf[:n]]  # type: ignore[reportGeneralTypeIssues]

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            addr = start.add(i)

            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(48)

            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

            lines.append(f"{addr}  {hex_part}  {ascii_part}")

        return "\n".join(lines)

    def _print_statistics(self):
        logger.info("-" * 50)
        logger.info("Export Summary:")
        logger.info(f"  Total functions: {self.stats['total_functions']}")
        logger.info(f"  Exported:        {self.stats['exported']}")
        logger.info(f"  Skipped:         {self.stats['skipped']}")
        logger.info(f"  Failed:          {self.stats['failed']}")
        logger.info(f"  Memory files:    {self.stats['memory_files']}")
        logger.info(f"  Memory bytes:    {self.stats['memory_bytes']}")
