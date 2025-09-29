import argparse
import sys
from pathlib import Path

from mini_vm import VM, assemble_file, assemble_from_text


def cmd_run_asm(asm_path: str, debug: bool):
    program = assemble_file(asm_path)
    vm = VM(program, debug=debug)
    vm.run()


def cmd_exec_bin(bin_path: str, debug: bool):
    program = Path(bin_path).read_bytes()
    vm = VM(program, debug=debug)
    vm.run()


def cmd_assemble(asm_path: str, out_path: str):
    program = assemble_file(asm_path)
    Path(out_path).write_bytes(program)
    print(f"Wrote bytecode: {out_path} ({len(program)} bytes)")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Minimal stack-based VM")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Assemble and run an .asm file")
    p_run.add_argument("asm", help="Path to .asm source")
    p_run.add_argument("--debug", action="store_true", help="Enable VM trace")

    p_exec = sub.add_parser("exec", help="Execute a compiled .bin bytecode file")
    p_exec.add_argument("bin", help="Path to .bin bytecode")
    p_exec.add_argument("--debug", action="store_true", help="Enable VM trace")

    p_asm = sub.add_parser("assemble", help="Assemble .asm into .bin")
    p_asm.add_argument("asm", help="Input .asm source")
    p_asm.add_argument("out", help="Output .bin path")

    p_gui = sub.add_parser("gui", help="Launch Tkinter GUI")
    p_gui.add_argument("--example", help="Pre-load an .asm file in the editor", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "run":
        cmd_run_asm(args.asm, args.debug)
    elif args.cmd == "exec":
        cmd_exec_bin(args.bin, args.debug)
    elif args.cmd == "assemble":
        cmd_assemble(args.asm, args.out)
    elif args.cmd == "gui":
        from gui import launch
        launch(args.example)
    else:
        parser.print_help()
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
