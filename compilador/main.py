# Compilador Python Simple con interfaz Tkinter
# Autor: Proyecto de ejemplo
# Licencia: MIT (puedes cambiarla)

import os
import re
import sys
import subprocess
import threading
import tempfile
import py_compile
import minilang
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText


class SimpleCompilerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Compilador MiniLang")
        self.root.geometry("1000x700")

        # Estado
        self.show_generated_var = tk.BooleanVar(value=False)
        self.current_file: str | None = None

        self._build_menu()
        self._build_toolbar()
        self._build_main_area()
        self._bind_shortcuts()
        self._update_title()

    # ---------- UI ----------
    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)

        menu_archivo = tk.Menu(menubar, tearoff=0)
        menu_archivo.add_command(label="Nuevo", command=self.new_file, accelerator="Ctrl+N")
        menu_archivo.add_command(label="Abrir...", command=self.open_file, accelerator="Ctrl+O")
        menu_archivo.add_separator()
        menu_archivo.add_command(label="Guardar", command=self.save_file, accelerator="Ctrl+S")
        menu_archivo.add_command(label="Guardar como...", command=self.save_file_as, accelerator="Ctrl+Shift+S")
        menu_archivo.add_separator()
        menu_archivo.add_command(label="Salir", command=self.root.quit)

        menu_acciones = tk.Menu(menubar, tearoff=0)
        menu_acciones.add_command(label="Ejecutar", command=self.run_code, accelerator="F5")
        menu_acciones.add_command(label="Compilar a .pyc", command=self.compile_code, accelerator="Ctrl+B")
        menu_acciones.add_separator()
        menu_acciones.add_command(label="Limpiar salida", command=self.clear_output, accelerator="Ctrl+L")

        menu_ayuda = tk.Menu(menubar, tearoff=0)
        menu_ayuda.add_command(label="Acerca de", command=self.show_about)

        menubar.add_cascade(label="Archivo", menu=menu_archivo)
        menubar.add_cascade(label="Acciones", menu=menu_acciones)
        menubar.add_cascade(label="Ayuda", menu=menu_ayuda)

        self.root.config(menu=menubar)

    def _build_toolbar(self) -> None:
        bar = tk.Frame(self.root, bd=1, relief=tk.RAISED)

        btn_run = tk.Button(bar, text="▶ Ejecutar", command=self.run_code)
        btn_compile = tk.Button(bar, text="⚙ Compilar .pyc", command=self.compile_code)
        btn_save = tk.Button(bar, text="💾 Guardar", command=self.save_file)

        btn_run.pack(side=tk.LEFT, padx=4, pady=4)
        btn_compile.pack(side=tk.LEFT, padx=4, pady=4)
        btn_save.pack(side=tk.LEFT, padx=4, pady=4)
        # Opción de mostrar el código generado
        show_gen = tk.Checkbutton(bar, text="Mostrar generado", variable=self.show_generated_var)
        show_gen.pack(side=tk.LEFT, padx=8, pady=4)

        bar.pack(side=tk.TOP, fill=tk.X)

    def _build_main_area(self) -> None:
        paned = tk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Editor
        editor_frame = tk.Frame(paned)
        self.editor = ScrolledText(editor_frame, wrap=tk.NONE, undo=True, font=("Consolas", 11))
        self.editor.pack(fill=tk.BOTH, expand=True)
        paned.add(editor_frame)

        # Consola de salida
        console_frame = tk.Frame(paned)
        self.console = ScrolledText(console_frame, height=12, wrap=tk.WORD, state=tk.NORMAL, font=("Consolas", 10))
        self.console.pack(fill=tk.BOTH, expand=True)
        paned.add(console_frame)

        # Texto inicial (MiniLang, español - Ventana + Cubo con WASD)
        self.editor.insert(
            tk.END,
            "Ventana \"Juego\", 600, 400\n"
            "Cubo jugador, 100, 100, 50, \"#2ecc71\"\n"
            "Wasd jugador, 8\n"
            "Escribe \"Usa W A S D para mover el cubo (clic en la ventana si no responde)\"\n",
        )

    def _bind_shortcuts(self) -> None:
        self.root.bind("<Control-n>", lambda e: self.new_file())
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.bind("<Control-s>", lambda e: self.save_file())
        self.root.bind("<Control-S>", lambda e: self.save_file_as())
        self.root.bind("<F5>", lambda e: self.run_code())
        self.root.bind("<Control-b>", lambda e: self.compile_code())
        self.root.bind("<Control-l>", lambda e: self.clear_output())

    def _update_title(self) -> None:
        name = os.path.basename(self.current_file) if self.current_file else "Sin título"
        self.root.title(f"Compilador MiniLang - {name}")

    # ---------- Helpers ----------
    def log(self, text: str) -> None:
        self.console.configure(state=tk.NORMAL)
        self.console.insert(tk.END, text)
        self.console.see(tk.END)
        self.console.configure(state=tk.NORMAL)

    def log_line(self, text: str) -> None:
        self.log(text + "\n")

    def clear_output(self) -> None:
        self.console.configure(state=tk.NORMAL)
        self.console.delete("1.0", tk.END)
        self.console.configure(state=tk.NORMAL)

    def _ensure_saved_for_compile(self) -> bool:
        """Asegura que el archivo esté guardado antes de compilar. Retorna True si listo."""
        if self.current_file is None:
            if messagebox.askyesno("Guardar requerido", "Debes guardar el archivo antes de compilar. ¿Deseas guardarlo ahora?"):
                return self.save_file_as()
            return False
        # Guardar siempre para que la compilación use lo último
        return self.save_file()

    def _write_temp_file(self) -> str:
        """Escribe el contenido actual a un archivo temporal .py y devuelve su ruta."""
        tmp_dir = tempfile.mkdtemp(prefix="simple_compiler_")
        tmp_path = os.path.join(tmp_dir, "temp_run.py")
        code = self.editor.get("1.0", tk.END)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(code)
        return tmp_path

    def _write_temp_py(self, code: str, filename: str = "temp_run.py") -> str:
        """Escribe 'code' a un archivo temporal Python y devuelve su ruta."""
        tmp_dir = tempfile.mkdtemp(prefix="simple_compiler_")
        tmp_path = os.path.join(tmp_dir, filename)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(code)
        return tmp_path

    def _program_uses_read(self, source: str) -> bool:
        try:
            names = minilang.collect_read_vars(source)
            return len(names) > 0
        except Exception:
            sl = source.lower()
            return ("read" in sl) or ("introduce" in sl)

    def _ask_inputs(self, source: str) -> list[str]:
        """Pide al usuario una lista de entradas para Read, separadas por comas.
        Devuelve una lista de strings. Vacía si no hay entradas o si cancela.
        """
        placeholder = ""  # opcionalmente mostrar variables detectadas
        try:
            vars_ = minilang.collect_read_vars(source)
            if vars_:
                placeholder = f"Ej: valores para {', '.join(vars_)}. Usa comas para separar."
        except Exception:
            pass
        resp = simpledialog.askstring(
            "Entradas para Introduce",
            ("Proporciona entradas para Introduce, separadas por comas.\n"
             + (placeholder if placeholder else "Ej: 10, 20, hola")),
            parent=self.root,
        )
        if not resp:
            return []
        parts = [p.strip() for p in re.split(r"[,\n;]+", resp) if p.strip()]
        return parts

    # ---------- Archivo ----------
    def new_file(self) -> None:
        if not self._confirm_discard_changes():
            return
        self.editor.delete("1.0", tk.END)
        self.current_file = None
        self._update_title()

    def open_file(self) -> None:
        if not self._confirm_discard_changes():
            return
        path = filedialog.askopenfilename(
            title="Abrir archivo MiniLang",
            filetypes=[("MiniLang", "*.ml"), ("Todos", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.editor.delete("1.0", tk.END)
            self.editor.insert(tk.END, content)
            self.current_file = path
            self._update_title()
            self.log_line(f"[INFO] Abierto: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el archivo:\n{e}")

    def save_file(self) -> bool:
        if self.current_file is None:
            return self.save_file_as()
        try:
            content = self.editor.get("1.0", tk.END)
            with open(self.current_file, "w", encoding="utf-8") as f:
                f.write(content)
            self.log_line(f"[OK] Guardado: {self.current_file}")
            self._update_title()
            return True
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{e}")
            return False

    def save_file_as(self) -> bool:
        path = filedialog.asksaveasfilename(
            defaultextension=".ml",
            filetypes=[("MiniLang", "*.ml"), ("Todos", "*.*")],
            title="Guardar como",
        )
        if not path:
            return False
        self.current_file = path
        return self.save_file()

    def _confirm_discard_changes(self) -> bool:
        # Versión simple: preguntar siempre. Para algo más fino, habría que detectar modificaciones.
        if self.editor.get("1.0", tk.END).strip():
            res = messagebox.askyesnocancel("Confirmación", "¿Deseas guardar los cambios antes de continuar?")
            if res is None:
                return False
            if res:
                return self.save_file()
            return True
        return True

    # ---------- Acciones ----------
    def run_code(self) -> None:
        self.clear_output()
        # MiniLang: transpilar a Python temporal y ejecutar
        source = self.editor.get("1.0", tk.END)
        inputs: list[str] = []
        if self._program_uses_read(source):
            inputs = self._ask_inputs(source)
        try:
            py_code = minilang.transpile(source, inputs=inputs)
        except Exception as e:
            self.log_line("[ERROR] Fallo al transpilar MiniLang")
            self.log_line(str(e))
            return
        if self.show_generated_var.get():
            self.log_line("[GENERADO - Python]:")
            self.log(py_code)
            self.log_line("".rstrip())
        src_path = self._write_temp_py(py_code, filename="minilang_transpiled_run.py")

        self.log_line(f"[EJECUTANDO] {src_path}")

        def _worker(path: str) -> None:
            try:
                creationflags = 0
                if os.name == "nt":
                    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                proc = subprocess.run(
                    [sys.executable, path],
                    capture_output=True,
                    text=True,
                    creationflags=creationflags,
                )
                if proc.stdout:
                    self.log(proc.stdout)
                if proc.stderr:
                    self.log(proc.stderr)
                self.log_line(f"[FIN] Código de salida: {proc.returncode}")
            except Exception as e:
                self.log_line("[ERROR] Fallo al ejecutar")
                self.log_line(str(e))

        threading.Thread(target=_worker, args=(src_path,), daemon=True).start()

    def compile_code(self) -> None:
        # MiniLang → Transpilar a Python temporal y compilar ese .py a .pyc
        self.clear_output()
        source = self.editor.get("1.0", tk.END)
        self.log_line("[COMPILANDO MiniLang → .pyc]")
        inputs: list[str] = []
        if self._program_uses_read(source):
            inputs = self._ask_inputs(source)
        try:
            py_code = minilang.transpile(source, inputs=inputs)
            if self.show_generated_var.get():
                self.log_line("[GENERADO - Python]:")
                self.log(py_code)
            tmp_py = self._write_temp_py(py_code, filename="minilang_transpiled_compile.py")
            compiled_path = py_compile.compile(tmp_py, doraise=True)
            self.log_line(f"[OK] Compilado a bytecode: {compiled_path}")
            messagebox.showinfo("Compilación exitosa", f"Archivo .pyc generado:\n{compiled_path}")
        except py_compile.PyCompileError as ce:
            self.log_line("[ERROR] Error de compilación")
            self.log_line(str(ce))
            messagebox.showerror("Error de compilación", str(ce))
        except Exception as e:
            self.log_line("[ERROR] Fallo durante la compilación")
            self.log_line(str(e))
            messagebox.showerror("Error", str(e))

    # ---------- Ayuda ----------
    def show_about(self) -> None:
        messagebox.showinfo(
            "Acerca de",
            "Compilador MiniLang\n\n- Edita, ejecuta (F5) y compila a bytecode .pyc (Ctrl+B).\n- Transpila MiniLang a Python internamente.\n\nNota: la entrada interactiva (input) no está soportada durante la ejecución desde la app.",
        )


def main() -> None:
    root = tk.Tk()
    app = SimpleCompilerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
