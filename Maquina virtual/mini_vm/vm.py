from __future__ import annotations
from enum import IntEnum
from typing import List, Optional, Callable


class OpCode(IntEnum):
    NOP = 0x00
    PUSH = 0x01  # + i32
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
    JMP = 0x0C   # + i32 (absolute PC)
    JZ = 0x0D    # + i32 (pop cond; jump if zero)
    JNZ = 0x0E   # + i32 (pop cond; jump if non-zero)
    CALL = 0x0F  # + i32 (absolute PC)
    RET = 0x10
    LOAD = 0x11  # + i32 (addr in memory cells)
    STORE = 0x12 # + i32 (addr in memory cells)
    IN = 0x13    # read integer input and push
    OUTC = 0x14  # pop int -> output as single char
    INCH = 0x15  # read a single char, push its code


class VMWaitForInput(Exception):
    """Signal that the VM attempted to read input but none is available yet."""
    pass


class VM:
    """Minimal stack-based bytecode VM.

    - Program format: sequence of bytes; 1-byte opcode; some opcodes carry a 4-byte little-endian signed immediate.
    - Jumps/CALL use absolute byte offsets into the program.
    - Memory is an array of 32-bit signed integers ("cells"). LOAD/STORE address these cells, not bytes.
    """

    def __init__(self, program: bytes, memory_cells: int = 4096, debug: bool = False,
                 output_func: Optional[Callable[[str], None]] = None,
                 input_func: Optional[Callable[[], int]] = None,
                 output_char_func: Optional[Callable[[str], None]] = None,
                 input_char_func: Optional[Callable[[], int]] = None):
        self.program = program
        self.pc = 0  # program counter: byte index into program
        self.stack: List[int] = []
        self.callstack: List[int] = []
        self.memory: List[int] = [0] * memory_cells  # 32-bit cell memory
        self.running = True
        self.debug = debug
        self.steps = 0
        # IO hooks
        self._out = output_func if output_func is not None else (lambda s: print(s))
        self._in_func = input_func
        self._out_char = output_char_func
        self._in_char = input_char_func
        self._waiting_for_input = False

    def _read_i32(self) -> int:
        if self.pc + 4 > len(self.program):
            raise RuntimeError("Program ended unexpectedly while reading immediate")
        val = int.from_bytes(self.program[self.pc:self.pc + 4], byteorder="little", signed=True)
        self.pc += 4
        return val

    def _fetch_opcode(self) -> OpCode:
        if self.pc >= len(self.program):
            # Implicit HALT if program counter reaches end
            self.running = False
            return OpCode.HALT
        op = self.program[self.pc]
        self.pc += 1
        try:
            return OpCode(op)
        except ValueError:
            raise RuntimeError(f"Invalid opcode 0x{op:02X} at pc={self.pc - 1}")

    def _pop2(self) -> tuple[int, int]:
        if len(self.stack) < 2:
            raise RuntimeError("Stack underflow: need two values")
        b = self.stack.pop()
        a = self.stack.pop()
        return a, b

    def _pop1(self) -> int:
        if not self.stack:
            raise RuntimeError("Stack underflow: need one value")
        return self.stack.pop()

    def _check_pc(self, target: int):
        if not (0 <= target <= len(self.program)):
            raise RuntimeError(f"Jump target out of range: {target}")

    def _emit(self, v: int):
        self._out(str(v))

    def _read_input(self) -> int:
        if self._in_func is not None:
            try:
                return int(self._in_func())
            except VMWaitForInput:
                raise
            except EOFError:
                raise VMWaitForInput()
            except Exception as e:
                # Treat empty/invalid input as waiting
                raise VMWaitForInput() from e
        # Fallback to console input
        return int(input("VM IN> "))

    def _emit_char(self, v: int):
        ch = chr(int(v) & 0xFF)
        if self._out_char is not None:
            self._out_char(ch)
        else:
            # Fallback: print without newline
            print(ch, end='', flush=True)

    def _read_char(self) -> int:
        if self._in_char is not None:
            try:
                return int(self._in_char())
            except VMWaitForInput:
                raise
            except EOFError:
                raise VMWaitForInput()
            except Exception as e:
                raise VMWaitForInput() from e
        try:
            s = input("VM CH> ")
        except EOFError:
            raise VMWaitForInput()
        if not s:
            raise VMWaitForInput()
        return ord(s[0])

    def step(self) -> bool:
        if not self.running:
            return False
        if self._waiting_for_input:
            return False
        op = self._fetch_opcode()
        if self.debug:
            print(f"[VM] pc={self.pc - 1} op={op.name} stack={self.stack}")

        try:
            if op == OpCode.NOP:
                pass
            elif op == OpCode.PUSH:
                val = self._read_i32()
                self.stack.append(val)
            elif op == OpCode.POP:
                self._pop1()
            elif op == OpCode.ADD:
                a, b = self._pop2()
                self.stack.append(a + b)
            elif op == OpCode.SUB:
                a, b = self._pop2()
                self.stack.append(a - b)
            elif op == OpCode.MUL:
                a, b = self._pop2()
                self.stack.append(a * b)
            elif op == OpCode.DIV:
                a, b = self._pop2()
                if b == 0:
                    raise RuntimeError("Division by zero")
                self.stack.append(int(a / b))
            elif op == OpCode.MOD:
                a, b = self._pop2()
                if b == 0:
                    raise RuntimeError("Modulo by zero")
                self.stack.append(a % b)
            elif op == OpCode.DUP:
                v = self._pop1()
                self.stack.append(v)
                self.stack.append(v)
            elif op == OpCode.SWAP:
                if len(self.stack) < 2:
                    raise RuntimeError("Stack underflow on SWAP")
                self.stack[-1], self.stack[-2] = self.stack[-2], self.stack[-1]
            elif op == OpCode.PRINT:
                v = self._pop1()
                self._emit(v)
            elif op == OpCode.HALT:
                self.running = False
                return False
            elif op == OpCode.IN:
                try:
                    val = self._read_input()
                    self.stack.append(int(val))
                except VMWaitForInput:
                    # roll back to re-execute IN on resume
                    self.pc -= 1
                    self._waiting_for_input = True
                    raise
            elif op == OpCode.OUTC:
                v = self._pop1()
                self._emit_char(v)
            elif op == OpCode.INCH:
                try:
                    val = self._read_char()
                    self.stack.append(int(val))
                except VMWaitForInput:
                    self.pc -= 1
                    self._waiting_for_input = True
                    raise
            elif op == OpCode.JMP:
                target = self._read_i32()
                self._check_pc(target)
                self.pc = target
            elif op == OpCode.JZ:
                target = self._read_i32()
                cond = self._pop1()
                if cond == 0:
                    self._check_pc(target)
                    self.pc = target
            elif op == OpCode.JNZ:
                target = self._read_i32()
                cond = self._pop1()
                if cond != 0:
                    self._check_pc(target)
                    self.pc = target
            elif op == OpCode.CALL:
                target = self._read_i32()
                self._check_pc(target)
                self.callstack.append(self.pc)
                self.pc = target
            elif op == OpCode.RET:
                if not self.callstack:
                    raise RuntimeError("Call stack underflow on RET")
                self.pc = self.callstack.pop()
            elif op == OpCode.LOAD:
                addr = self._read_i32()
                if not (0 <= addr < len(self.memory)):
                    raise RuntimeError(f"LOAD address out of range: {addr}")
                self.stack.append(self.memory[addr])
            elif op == OpCode.STORE:
                addr = self._read_i32()
                val = self._pop1()
                if not (0 <= addr < len(self.memory)):
                    raise RuntimeError(f"STORE address out of range: {addr}")
                self.memory[addr] = int(val)
            else:
                raise RuntimeError(f"Unimplemented opcode: {op}")
        except VMWaitForInput:
            # Pause execution until input is provided
            return False
        except RuntimeError as e:
            # Halt on error but surface message
            print(f"[VM ERROR] {e}")
            self.running = False
            return False

        self.steps += 1
        return True

    def run(self, max_steps: Optional[int] = None):
        while self.running:
            progressed = self.step()
            if self._waiting_for_input:
                # Pause until input is provided
                break
            if max_steps is not None and self.steps >= max_steps:
                print("[VM] Max steps reached; stopping.")
                break

    def resume_after_input(self):
        """Call when new input is available to clear waiting state."""
        self._waiting_for_input = False
