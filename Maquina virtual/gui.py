import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import Optional

import json
import os

from mini_vm import VM, assemble_from_text, VMWaitForInput, OpCode
from mini_vm.assembler import parse_source, INSTR_DEF


class VMGui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Mini VM - Tkinter GUI")

        # Layout
        self._build_layout()

        # VM/runtime state
        self.vm = None
        self.program = None
        self.loop_running = False
        self.after_id = None
        # moved to above to initialize early
        self.trace_enabled = False
        self.breakpoints = set()      # PCs
        self.bp_lines = set()         # source lines
        self.pc_to_line = {}
        self.line_to_pc = {}
        self.over_mode = False
        self.over_depth = 0
        self.over_target_pc: Optional[int] = None
        self.out_mode = False
        self.out_target_depth = 0
        self.labels = {}
        # I/O queues
        self.input_queue = []
        self.input_char_queue = []
        # Watches
        self.watches = []  # list of int addresses
        # Disassembly window refs
        self.disasm_win = None
        self.disasm_text = None

        # Load default example
        self._load_default()
        # Load persisted state
        self._load_state()
        # Save on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- UI construction ----------
    def _build_layout(self):
        main = ttk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(main)
        right = ttk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False)

        # Toolbar
        toolbar = ttk.Frame(left)
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Run", command=self.run).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Step", command=self.step).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Step Over", command=self.step_over).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Step Out", command=self.step_out).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Pause", command=self.pause).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Reset", command=self.reset).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Toggle BP", command=self.toggle_breakpoint_current).pack(side=tk.LEFT, padx=8, pady=2)
        self.trace_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar, text="Trace", variable=self.trace_var, command=self.on_trace_toggle).pack(side=tk.LEFT, padx=2)
        # Speed controls
        self.delay_var = tk.IntVar(value=10)
        self.batch_var = tk.IntVar(value=500)
        ttk.Label(toolbar, text="Delay(ms)").pack(side=tk.LEFT, padx=(8,2))
        tk.Scale(toolbar, from_=0, to=100, orient=tk.HORIZONTAL, showvalue=True, variable=self.delay_var, length=120).pack(side=tk.LEFT)
        ttk.Label(toolbar, text="Batch").pack(side=tk.LEFT, padx=(8,2))
        tk.Scale(toolbar, from_=1, to=2000, orient=tk.HORIZONTAL, showvalue=True, variable=self.batch_var, length=120).pack(side=tk.LEFT)
        # Disassembly and label BP
        ttk.Button(toolbar, text="Disassemble", command=self.open_disasm_window).pack(side=tk.LEFT, padx=8)
        self.bp_label_entry = ttk.Entry(toolbar, width=12)
        self.bp_label_entry.pack(side=tk.LEFT)
        ttk.Button(toolbar, text="BP Label", command=self.add_breakpoint_by_label).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Open", command=self.open_file).pack(side=tk.LEFT, padx=8, pady=2)
        ttk.Button(toolbar, text="Save", command=self.save_file).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Load Example", command=self.load_example_menu).pack(side=tk.LEFT, padx=8, pady=2)

        # Editor
        editor_frame = ttk.Frame(left)
        editor_frame.pack(fill=tk.BOTH, expand=True)
        self.editor = tk.Text(editor_frame, wrap="none", font=("Consolas", 10))
        self.editor.pack(fill=tk.BOTH, expand=True)
        # Tags for highlighting
        self.editor.tag_configure('current', background='#e6f0ff')
        self.editor.tag_configure('bp', background='#ffecec')
        # Click to toggle breakpoint on double-click
        self.editor.bind('<Double-Button-1>', self.on_editor_double_click)

        # Output
        ttk.Label(right, text="Output").pack(anchor="w")
        self.output = tk.Text(right, height=12, width=42, state="disabled")
        self.output.pack(fill=tk.BOTH, expand=False)

        # Input (int and char)
        input_frame = ttk.Frame(right)
        input_frame.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(input_frame, text="Input int:").pack(side=tk.LEFT)
        self.input_entry = ttk.Entry(input_frame, width=12)
        self.input_entry.pack(side=tk.LEFT, padx=4)
        ttk.Button(input_frame, text="Send Int", command=self.send_input).pack(side=tk.LEFT)
        inputc_frame = ttk.Frame(right)
        inputc_frame.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(inputc_frame, text="Input char:").pack(side=tk.LEFT)
        self.input_char_entry = ttk.Entry(inputc_frame, width=6)
        self.input_char_entry.pack(side=tk.LEFT, padx=4)
        ttk.Button(inputc_frame, text="Send Char", command=self.send_input_char).pack(side=tk.LEFT)

        # State
        self.state_label = ttk.Label(right, text="PC: -, Steps: -, Waiting: False")
        self.state_label.pack(anchor="w", pady=(6, 0))

        ttk.Label(right, text="Stack (top first)").pack(anchor="w")
        self.stack_list = tk.Listbox(right, height=10)
        self.stack_list.pack(fill=tk.BOTH, expand=True)

        ttk.Label(right, text="Callstack").pack(anchor="w")
        self.callstack_list = tk.Listbox(right, height=6)
        self.callstack_list.pack(fill=tk.BOTH, expand=True)

        # Memory inspector
        ttk.Label(right, text="Memory").pack(anchor="w", pady=(6, 0))
        mem_ctrl = ttk.Frame(right)
        mem_ctrl.pack(fill=tk.X)
        ttk.Label(mem_ctrl, text="Start:").pack(side=tk.LEFT)
        self.mem_start = ttk.Entry(mem_ctrl, width=6)
        self.mem_start.insert(0, "0")
        self.mem_start.pack(side=tk.LEFT, padx=2)
        ttk.Label(mem_ctrl, text="Count:").pack(side=tk.LEFT)
        self.mem_count = ttk.Entry(mem_ctrl, width=6)
        self.mem_count.insert(0, "32")
        self.mem_count.pack(side=tk.LEFT, padx=2)
        ttk.Button(mem_ctrl, text="Refresh", command=self.mem_refresh).pack(side=tk.LEFT, padx=4)
        self.mem_list = tk.Listbox(right, height=10)
        self.mem_list.pack(fill=tk.BOTH, expand=True)
        mem_set = ttk.Frame(right)
        mem_set.pack(fill=tk.X)
        ttk.Label(mem_set, text="Addr:").pack(side=tk.LEFT)
        self.mem_addr = ttk.Entry(mem_set, width=8)
        self.mem_addr.pack(side=tk.LEFT, padx=2)
        ttk.Label(mem_set, text="Value:").pack(side=tk.LEFT)
        self.mem_value = ttk.Entry(mem_set, width=10)
        self.mem_value.pack(side=tk.LEFT, padx=2)
        ttk.Button(mem_set, text="Set", command=self.mem_set).pack(side=tk.LEFT, padx=4)

        # Breakpoints list
        ttk.Label(right, text="Breakpoints (lines)").pack(anchor="w", pady=(6, 0))
        self.bp_list = tk.Listbox(right, height=6)
        self.bp_list.pack(fill=tk.BOTH, expand=True)
        ttk.Button(right, text="Clear BPs", command=self.clear_all_breakpoints).pack(anchor='e', pady=(2, 0))

        # Watches
        ttk.Label(right, text="Watches").pack(anchor="w", pady=(6, 0))
        wctrl = ttk.Frame(right)
        wctrl.pack(fill=tk.X)
        ttk.Label(wctrl, text="Addr:").pack(side=tk.LEFT)
        self.watch_addr = ttk.Entry(wctrl, width=8)
        self.watch_addr.pack(side=tk.LEFT, padx=2)
        ttk.Button(wctrl, text="Add", command=self.watch_add).pack(side=tk.LEFT)
        ttk.Button(wctrl, text="Remove", command=self.watch_remove).pack(side=tk.LEFT, padx=2)
        ttk.Button(wctrl, text="Refresh", command=self.watch_refresh).pack(side=tk.LEFT, padx=4)
        self.watch_list = tk.Listbox(right, height=6)
        self.watch_list.pack(fill=tk.BOTH, expand=True)

    # ---------- Helpers ----------
    def log(self, text: str):
        self.output.configure(state="normal")
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.configure(state="disabled")

    def output_hook(self, s: str):
        self.log(s)

    def output_char_hook(self, ch: str):
        self.output.configure(state="normal")
        self.output.insert(tk.END, ch)
        self.output.see(tk.END)
        self.output.configure(state="disabled")

    def input_hook(self) -> int:
        if self.input_queue:
            return self.input_queue.pop(0)
        else:
            raise VMWaitForInput()

    def input_char_hook(self) -> int:
        if self.input_char_queue:
            return self.input_char_queue.pop(0)
        else:
            raise VMWaitForInput()

    def assemble(self) -> bool:
        src = self.editor.get("1.0", tk.END)
        try:
            self.program = assemble_from_text(src)
            self.recompute_mapping(src)
            # Clear breakpoints after assembling to avoid stale PCs
            self.breakpoints.clear()
            self.bp_lines.clear()
            self.apply_bp_tags()
            self.update_breakpoint_list()
            return True
        except Exception as e:
            messagebox.showerror("Assemble error", str(e))
            return False

    def ensure_vm(self) -> bool:
        if self.vm is None:
            if not self.program and not self.assemble():
                return False
            self.vm = VM(self.program, debug=False,
                         output_func=self.output_hook, input_func=self.input_hook,
                         output_char_func=self.output_char_hook, input_char_func=self.input_char_hook)
        return True

    # ---------- Mapping / Breakpoints ----------
    def recompute_mapping(self, src_text: Optional[str] = None):
        if src_text is None:
            src_text = self.editor.get("1.0", tk.END)
        try:
            instrs, labels = parse_source(src_text)
        except Exception:
            self.pc_to_line = {}
            self.line_to_pc = {}
            self.labels = {}
            return
        pc = 0
        pc_to_line = {}
        line_to_pc = {}
        for ins in instrs:
            pc_to_line[pc] = ins.line_no
            if ins.line_no not in line_to_pc:
                line_to_pc[ins.line_no] = pc
            opcode, has_imm = INSTR_DEF[ins.mnemonic]
            pc += 1 + (4 if has_imm else 0)
        self.pc_to_line = pc_to_line
        self.line_to_pc = line_to_pc
        # Capture labels mapping to PCs
        lbl_map = {}
        # Re-parse to associate labels with PC: parse_source already gave labels
        try:
            _, lbls = parse_source(src_text)
            lbl_map.update(lbls)
        except Exception:
            pass
        self.labels = lbl_map

    def on_trace_toggle(self):
        self.trace_enabled = bool(self.trace_var.get())

    def toggle_breakpoint_current(self):
        idx = self.editor.index(tk.INSERT)
        line = int(idx.split('.')[0])
        if line not in self.line_to_pc:
            messagebox.showinfo("Breakpoint", f"No instruction at line {line}")
            return
        pc = self.line_to_pc[line]
        if pc in self.breakpoints:
            self.breakpoints.remove(pc)
            self.bp_lines.discard(line)
        else:
            self.breakpoints.add(pc)
            self.bp_lines.add(line)
        self.apply_bp_tags()
        self.update_breakpoint_list()

    def add_breakpoint_by_label(self):
        name = self.bp_label_entry.get().strip()
        if not name:
            return
        if name not in self.labels:
            messagebox.showerror("BP Label", f"Label '{name}' not found")
            return
        pc = self.labels[name]
        self.breakpoints.add(pc)
        # Map pc to line if available for UI
        line = self.pc_to_line.get(pc)
        if line:
            self.bp_lines.add(line)
        self.apply_bp_tags()
        self.update_breakpoint_list()

    def clear_all_breakpoints(self):
        self.breakpoints.clear()
        self.bp_lines.clear()
        self.apply_bp_tags()
        self.update_breakpoint_list()

    def apply_bp_tags(self):
        self.editor.tag_remove('bp', '1.0', tk.END)
        for line in sorted(self.bp_lines):
            start = f"{line}.0"
            end = f"{line}.end"
            self.editor.tag_add('bp', start, end)

    def highlight_current_line(self):
        self.editor.tag_remove('current', '1.0', tk.END)
        if not self.vm:
            return
        line = self.pc_to_line.get(self.vm.pc)
        if line:
            start = f"{line}.0"
            end = f"{line}.end"
            self.editor.tag_add('current', start, end)

    def update_breakpoint_list(self):
        self.bp_list.delete(0, tk.END)
        for line in sorted(self.bp_lines):
            self.bp_list.insert(tk.END, str(line))

    def on_editor_double_click(self, event):
        try:
            idx = self.editor.index(f"@{event.x},{event.y}")
            line = int(idx.split('.')[0])
        except Exception:
            return
        if line not in self.line_to_pc:
            return
        pc = self.line_to_pc[line]
        if pc in self.breakpoints:
            self.breakpoints.remove(pc)
            self.bp_lines.discard(line)
        else:
            self.breakpoints.add(pc)
            self.bp_lines.add(line)
        self.apply_bp_tags()
        self.update_breakpoint_list()

    # ---------- Actions ----------
    def run(self):
        if not self.ensure_vm():
            return
        if self.loop_running:
            return
        self.loop_running = True
        self.run_loop()

    def run_loop(self):
        if not self.loop_running or self.vm is None:
            return
        steps = 0
        max_steps = int(self.batch_var.get()) if hasattr(self, 'batch_var') else 500
        try:
            while steps < max_steps and self.vm.running and not self.vm._waiting_for_input:
                # Breakpoint check
                if self.vm.pc in self.breakpoints and not (self.over_mode or self.out_mode):
                    self.loop_running = False
                    break
                if self.trace_enabled:
                    self.trace_current()
                self.vm.step()
                steps += 1
                # Step-over completion
                if self.over_mode and self.over_target_pc is not None:
                    if len(self.vm.callstack) <= self.over_depth and self.vm.pc == self.over_target_pc:
                        self.over_mode = False
                        self.loop_running = False
                        break
                # Step-out completion
                if self.out_mode:
                    if len(self.vm.callstack) <= self.out_target_depth:
                        self.out_mode = False
                        self.loop_running = False
                        break
        except VMWaitForInput:
            pass
        self.update_state()
        self.highlight_current_line()
        if self.vm and self.vm.running and self.loop_running and not self.vm._waiting_for_input:
            delay = int(self.delay_var.get()) if hasattr(self, 'delay_var') else 10
            self.after_id = self.root.after(delay, self.run_loop)
        else:
            self.loop_running = False

    def step(self):
        if not self.ensure_vm():
            return
        try:
            if self.trace_enabled:
                self.trace_current()
            self.vm.step()
        except VMWaitForInput:
            messagebox.showinfo("VM", "VM awaiting input.")
        self.update_state()
        self.highlight_current_line()

    def step_over(self):
        if not self.ensure_vm():
            return
        # Determine if current op is CALL
        if self.vm.pc < len(self.vm.program):
            op = self.vm.program[self.vm.pc]
            try:
                opcode = OpCode(op)
            except Exception:
                opcode = None
            if opcode == OpCode.CALL:
                # Next instruction PC is current + size(CALL)=5
                self.over_mode = True
                self.over_depth = len(self.vm.callstack)
                self.over_target_pc = self.vm.pc + 5
                self.loop_running = True
                self.run_loop()
                return
        # Default: single step
        self.step()

    def step_out(self):
        if not self.ensure_vm():
            return
        self.out_mode = True
        self.out_target_depth = max(0, len(self.vm.callstack) - 1)
        self.loop_running = True
        self.run_loop()

    def pause(self):
        self.loop_running = False
        if self.after_id:
            try:
                self.root.after_cancel(self.after_id)
            except Exception:
                pass
            self.after_id = None
        self.update_state()

    def reset(self):
        self.pause()
        self.vm = None
        self.program = None
        self.breakpoints.clear()
        self.bp_lines.clear()
        self.pc_to_line.clear()
        self.line_to_pc.clear()
        self.apply_bp_tags()
        self.over_mode = False
        self.out_mode = False
        self.over_target_pc = None
        self.out_target_depth = 0
        self.stack_list.delete(0, tk.END)
        self.callstack_list.delete(0, tk.END)
        self.state_label.config(text="PC: -, Steps: -, Waiting: False")
        self.log("--- Reset ---")

    def send_input(self):
        text = self.input_entry.get().strip()
        if not text:
            return
        try:
            val = int(text)
        except ValueError:
            messagebox.showerror("Input", "Please enter an integer.")
            return
        self.input_queue.append(val)
        self.input_entry.delete(0, tk.END)
        if self.vm:
            self.vm.resume_after_input()
            if not self.loop_running:
                self.loop_running = True
                self.run_loop()

    def send_input_char(self):
        text = self.input_char_entry.get()
        if not text:
            return
        ch = text[0]
        self.input_char_queue.append(ord(ch))
        self.input_char_entry.delete(0, tk.END)
        if self.vm:
            self.vm.resume_after_input()
            if not self.loop_running:
                self.loop_running = True
                self.run_loop()

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("ASM files", "*.asm"), ("All files", "*.*")])
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except Exception as e:
            messagebox.showerror("Open", str(e))
            return
        self.editor.delete("1.0", tk.END)
        self.editor.insert("1.0", text)
        self.reset()

    def save_file(self):
        path = filedialog.asksaveasfilename(defaultextension=".asm", filetypes=[("ASM files", "*.asm")])
        if not path:
            return
        try:
            Path(path).write_text(self.editor.get("1.0", tk.END), encoding="utf-8")
            self.log(f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Save", str(e))

    def load_example_menu(self):
        menu = tk.Toplevel(self.root)
        menu.title("Load Example")
        frame = ttk.Frame(menu, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        examples = [
            ("hello.asm", "examples/hello.asm"),
            ("loop.asm", "examples/loop.asm"),
            ("input_echo.asm", "examples/input_echo.asm"),
            ("call_store.asm", "examples/call_store.asm"),
            ("hello_text.asm", "examples/hello_text.asm"),
            ("input_char_echo.asm", "examples/input_char_echo.asm"),
        ]

        def load(path: str):
            try:
                text = Path(path).read_text(encoding="utf-8")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                return
            self.editor.delete("1.0", tk.END)
            self.editor.insert("1.0", text)
            self.reset()
            menu.destroy()

        for name, path in examples:
            ttk.Button(frame, text=name, command=lambda p=path: load(p)).pack(fill=tk.X, pady=2)

    def update_state(self):
        if not self.vm:
            return
        self.stack_list.delete(0, tk.END)
        for v in reversed(self.vm.stack):
            self.stack_list.insert(tk.END, str(v))
        self.callstack_list.delete(0, tk.END)
        for v in reversed(self.vm.callstack):
            self.callstack_list.insert(tk.END, str(v))
        self.state_label.config(text=f"PC: {self.vm.pc}, Steps: {self.vm.steps}, Waiting: {self.vm._waiting_for_input}")
        self.watch_refresh()
        self.update_disasm_highlight()

    # ---------- Memory inspector ----------
    def mem_refresh(self):
        self.mem_list.delete(0, tk.END)
        if not self.vm:
            return
        try:
            start = int(self.mem_start.get())
            count = int(self.mem_count.get())
        except ValueError:
            messagebox.showerror("Memory", "Start and Count must be integers")
            return
        end = max(0, start) + max(0, count)
        mem = self.vm.memory
        for i in range(start, min(end, len(mem))):
            self.mem_list.insert(tk.END, f"[{i}] = {mem[i]}")

    def mem_set(self):
        if not self.vm:
            return
        try:
            addr = int(self.mem_addr.get())
            value = int(self.mem_value.get())
        except ValueError:
            messagebox.showerror("Memory", "Addr and Value must be integers")
            return
        if not (0 <= addr < len(self.vm.memory)):
            messagebox.showerror("Memory", "Address out of range")
            return
        self.vm.memory[addr] = value
        self.mem_refresh()

    # ---------- Trace helper ----------
    def trace_current(self):
        if not self.vm or self.vm.pc >= len(self.vm.program):
            return
        op = self.vm.program[self.vm.pc]
        try:
            name = OpCode(op).name
        except Exception:
            name = f"0x{op:02X}"
        self.log(f"TRACE pc={self.vm.pc} op={name}")

    # ---------- Disassembly ----------
    def open_disasm_window(self):
        if self.disasm_win and tk.Toplevel.winfo_exists(self.disasm_win):
            try:
                self.disasm_win.lift()
                return
            except Exception:
                pass
        self.disasm_win = tk.Toplevel(self.root)
        self.disasm_win.title("Disassembly")
        self.disasm_text = tk.Text(self.disasm_win, wrap='none', font=("Consolas", 10), height=30, width=60)
        self.disasm_text.pack(fill=tk.BOTH, expand=True)
        self.disasm_text.tag_configure('pc', background='#ddffdd')
        self.refresh_disassembly()

    def refresh_disassembly(self):
        if self.disasm_text is None:
            return
        self.disasm_text.configure(state='normal')
        self.disasm_text.delete('1.0', tk.END)
        if not self.program:
            self.disasm_text.insert(tk.END, "<no program>\n")
        else:
            lines = self.disassemble_program(self.program)
            for line in lines:
                self.disasm_text.insert(tk.END, line + "\n")
        self.disasm_text.configure(state='disabled')
        self.update_disasm_highlight()

    def update_disasm_highlight(self):
        if self.disasm_text is None or not self.vm:
            return
        self.disasm_text.configure(state='normal')
        self.disasm_text.tag_remove('pc', '1.0', tk.END)
        # Each disasm line starts with address in brackets [xxxx]
        # Find line with current pc
        pc = self.vm.pc
        idx = '1.0'
        while True:
            pos = self.disasm_text.search(f"[{pc}]", idx, stopindex=tk.END)
            if not pos:
                break
            line_start = pos.split('.')[0] + '.0'
            line_end = pos.split('.')[0] + '.end'
            self.disasm_text.tag_add('pc', line_start, line_end)
            self.disasm_text.see(line_start)
            break
        self.disasm_text.configure(state='disabled')

    def disassemble_program(self, program: bytes):
        out = []
        i = 0
        n = len(program)
        while i < n:
            op = program[i]
            addr = i
            i += 1
            try:
                opcode = OpCode(op)
                name = opcode.name
            except Exception:
                name = f"0x{op:02X}"
                out.append(f"[{addr}] {name}")
                continue
            imm = None
            if name in ("PUSH", "JMP", "JZ", "JNZ", "CALL", "LOAD", "STORE"):
                if i + 4 <= n:
                    imm = int.from_bytes(program[i:i+4], 'little', signed=True)
                    i += 4
            if imm is None:
                out.append(f"[{addr}] {name}")
            else:
                out.append(f"[{addr}] {name} {imm}")
        return out

    # ---------- Watches ----------
    def watch_add(self):
        try:
            addr = int(self.watch_addr.get())
        except ValueError:
            messagebox.showerror("Watch", "Addr must be an integer")
            return
        if addr < 0:
            return
        if addr not in self.watches:
            self.watches.append(addr)
        self.watch_refresh()

    def watch_remove(self):
        sel = list(self.watch_list.curselection())
        if not sel:
            return
        for idx in reversed(sel):
            try:
                line = self.watch_list.get(idx)
                # format: [addr] = value
                addr = int(line.split(']')[0][1:])
                if addr in self.watches:
                    self.watches.remove(addr)
            except Exception:
                pass
        self.watch_refresh()

    def watch_refresh(self):
        self.watch_list.delete(0, tk.END)
        if not self.vm:
            return
        for addr in self.watches:
            if 0 <= addr < len(self.vm.memory):
                self.watch_list.insert(tk.END, f"[{addr}] = {self.vm.memory[addr]}")
            else:
                self.watch_list.insert(tk.END, f"[{addr}] = <out of range>")

    # ---------- Persistence ----------
    def _state_path(self) -> Path:
        try:
            return Path(os.getcwd()) / 'vm_gui_state.json'
        except Exception:
            return Path('vm_gui_state.json')

    def _load_state(self):
        p = self._state_path()
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            return
        # Restore editor, breakpoints lines, speeds, watches
        txt = data.get('editor_text')
        if isinstance(txt, str):
            self.editor.delete('1.0', tk.END)
            self.editor.insert('1.0', txt)
        # Collect saved breakpoint lines to reapply after assemble
        saved_bp_lines = []
        for line in data.get('bp_lines', []):
            try:
                saved_bp_lines.append(int(line))
            except Exception:
                continue
        delay = data.get('delay')
        batch = data.get('batch')
        if isinstance(delay, int):
            self.delay_var.set(delay)
        if isinstance(batch, int):
            self.batch_var.set(batch)
        w = data.get('watches', [])
        self.watches = []
        for addr in w:
            try:
                self.watches.append(int(addr))
            except Exception:
                pass
        # Re-assemble to build mapping and apply bp_lines
        self.assemble()
        # Reapply saved breakpoints by line and update UI
        self.bp_lines = set(saved_bp_lines)
        # Rebuild PC breakpoint set from lines
        self.breakpoints.clear()
        for line in self.bp_lines:
            pc = self.line_to_pc.get(line)
            if pc is not None:
                self.breakpoints.add(pc)
        self.apply_bp_tags()
        self.update_breakpoint_list()
        # Apply watched
        self.watch_refresh()

    def _save_state(self):
        data = {
            'editor_text': self.editor.get('1.0', tk.END),
            'bp_lines': sorted(list(self.bp_lines)),
            'delay': int(self.delay_var.get()),
            'batch': int(self.batch_var.get()),
            'watches': list(self.watches),
        }
        try:
            self._state_path().write_text(json.dumps(data), encoding='utf-8')
        except Exception:
            pass

    def on_close(self):
        try:
            self._save_state()
        finally:
            self.root.destroy()

    def _load_default(self):
        try:
            text = Path("examples/hello.asm").read_text(encoding="utf-8")
        except Exception:
            text = "; Write your program here\nHALT\n"
        self.editor.insert("1.0", text)


def launch(example_path: Optional[str] = None):
    root = tk.Tk()
    app = VMGui(root)
    if example_path:
        try:
            text = Path(example_path).read_text(encoding='utf-8')
            app.editor.delete("1.0", tk.END)
            app.editor.insert("1.0", text)
        except Exception:
            pass
    root.mainloop()


if __name__ == "__main__":
    launch()
