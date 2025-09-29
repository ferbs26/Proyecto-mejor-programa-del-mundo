from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
from enum import IntEnum


class OpCode(IntEnum):
    NOP = 0x00
    PUSH = 0x01
    POP = 0x02
    ADD = 0x03
    SUB = 0x04
    MUL = 0x05
    DIV = 0x06
    MOD = 0x07
    DUP = 0x08
    SWAP = 0x09
    PRINT = 0x0A
    HALT = 0x0B
    JMP = 0x0C
    JZ = 0x0D
    JNZ = 0x0E
    CALL = 0x0F
    RET = 0x10
    LOAD = 0x11
    STORE = 0x12
    IN = 0x13
    OUTC = 0x14
    INCH = 0x15


@dataclass
class Instr:
    mnemonic: str
    operand: Optional[str]
    line_no: int


INSTR_DEF: Dict[str, Tuple[OpCode, bool]] = {
    # mnemonic: (opcode, has_imm)
    "NOP": (OpCode.NOP, False),
    "PUSH": (OpCode.PUSH, True),
    "POP": (OpCode.POP, False),
    "ADD": (OpCode.ADD, False),
    "SUB": (OpCode.SUB, False),
    "MUL": (OpCode.MUL, False),
    "DIV": (OpCode.DIV, False),
    "MOD": (OpCode.MOD, False),
    "DUP": (OpCode.DUP, False),
    "SWAP": (OpCode.SWAP, False),
    "PRINT": (OpCode.PRINT, False),
    "HALT": (OpCode.HALT, False),
    "JMP": (OpCode.JMP, True),
    "JZ": (OpCode.JZ, True),
    "JNZ": (OpCode.JNZ, True),
    "CALL": (OpCode.CALL, True),
    "RET": (OpCode.RET, False),
    "LOAD": (OpCode.LOAD, True),
    "STORE": (OpCode.STORE, True),
    "IN": (OpCode.IN, False),
    "OUTC": (OpCode.OUTC, False),
    "INCH": (OpCode.INCH, False),
}


def _strip_comment(line: str) -> str:
    # Support ';' and '#' comments
    for sep in (';', '#'):
        if sep in line:
            line = line.split(sep, 1)[0]
    return line.strip()


def _parse_number_or_label(token: str, labels: Dict[str, int], line_no: int) -> int:
    if token in labels:
        return labels[token]
    s = token.replace('_', '')
    try:
        if s.lower().startswith('0x'):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        raise SyntaxError(f"Line {line_no}: invalid operand '{token}'")


def _instr_size(mnemonic: str) -> int:
    _, has_imm = INSTR_DEF[mnemonic]
    return 1 + (4 if has_imm else 0)


def parse_source(text: str) -> Tuple[List[Instr], Dict[str, int]]:
    instrs: List[Instr] = []
    labels: Dict[str, int] = {}
    pc = 0

    lines = text.splitlines()

    # First pass: collect labels and compute addresses
    for idx, line in enumerate(lines, start=1):
        raw = _strip_comment(line)
        if not raw:
            continue
        # Handle label definitions (e.g., 'loop:') possibly with instruction on same line
        while True:
            if ':' in raw:
                label, rest = raw.split(':', 1)
                label = label.strip()
                if not label.isidentifier():
                    raise SyntaxError(f"Line {idx}: invalid label '{label}'")
                if label in labels:
                    raise SyntaxError(f"Line {idx}: duplicate label '{label}'")
                labels[label] = pc
                raw = rest.strip()
                if not raw:
                    break  # line had only label
                # fallthrough to parse instr on same line
            else:
                break
        if not raw:
            continue
        parts = raw.replace(',', ' ').split()
        mnem = parts[0].upper()
        if mnem not in INSTR_DEF:
            raise SyntaxError(f"Line {idx}: unknown instruction '{mnem}'")
        operand = parts[1] if len(parts) > 1 else None
        if INSTR_DEF[mnem][1] and operand is None:
            raise SyntaxError(f"Line {idx}: '{mnem}' requires an operand")
        if (not INSTR_DEF[mnem][1]) and operand is not None:
            raise SyntaxError(f"Line {idx}: '{mnem}' takes no operand")
        instrs.append(Instr(mnemonic=mnem, operand=operand, line_no=idx))
        pc += _instr_size(mnem)

    return instrs, labels


def assemble_from_text(text: str) -> bytes:
    instrs, labels = parse_source(text)

    out = bytearray()
    for ins in instrs:
        opcode, has_imm = INSTR_DEF[ins.mnemonic]
        out.append(int(opcode))
        if has_imm:
            assert ins.operand is not None
            val = _parse_number_or_label(ins.operand, labels, ins.line_no)
            out.extend(int(val).to_bytes(4, byteorder='little', signed=True))
    return bytes(out)


def assemble_file(path: str) -> bytes:
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    return assemble_from_text(text)
