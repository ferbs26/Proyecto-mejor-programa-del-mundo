# Mini VM (Ruta A) en Python

## Estructura
- `mini_vm/vm.py`: intérprete de bytecode (VM).
- `mini_vm/assembler.py`: ensamblador (.asm -> .bin) con etiquetas.
- `main.py`: CLI para ejecutar/ensamblar.
- `gui.py`: interfaz gráfica (Tkinter) con editor, salida e input.
- `examples/`: programas de ejemplo.
## Requisitos
- Python 3.9+ (no requiere librerías externas).

## Interfaz gráfica (Tkinter)
- Editor para escribir/abrir/guardar `.asm`.
- Botones: `Run`, `Step`, `Step Over`, `Step Out`, `Pause`, `Reset`, `Open`, `Save`, `Load Example`.
- Consola de salida (muestra `PRINT` y `OUTC`), soporte de `Trace`.
- Entrada: `IN` (enteros) y `INCH` (carácter) con cajas "Input int" y "Input char".
- Breakpoints por línea (botón o doble click) y por etiqueta (campo "BP Label").
- Resaltado de línea actual durante la ejecución.
- Inspector de memoria (rango y edición) y lista de `Watches`.
- Ventana de desensamblado con resaltado del `PC`.
- Persistencia de estado (texto, BPs, velocidad y watches) entre sesiones.

Ejecuta:
```bash
python main.py gui --example examples/input_echo.asm
```

Cuando la VM necesita entrada (`IN`/`INCH`), se pausa hasta que envíes un valor con "Send Int" o "Send Char".

## ISA (instrucciones)
- `PUSH <i32>`: apila un entero (32-bit, little-endian).
- `POP`: descarta tope de pila.
- `ADD|SUB|MUL|DIV|MOD`: operaciones aritméticas sobre los dos topes (a op b).
- `DUP`: duplica el tope.
- `SWAP`: intercambia los dos topes.
- `PRINT`: saca y muestra el tope como entero con salto de línea.
- `IN`: lee un entero (desde la GUI o consola) y lo apila.
- `OUTC`: saca un entero y escribe su byte bajo como carácter (sin salto de línea).
- `INCH`: lee un carácter y apila su código (0..255).
- `HALT`: detiene la VM.
- `JMP <addr>`: salta a `addr` (offset absoluto en bytes dentro del programa).
- `JZ <addr>`: saca cond y salta si cond == 0.
- `JNZ <addr>`: saca cond y salta si cond != 0.
- `CALL <addr>` / `RET`: llamadas y retorno (usa callstack interna).

## Ejemplos incluidos
- `examples/hello.asm`: `(2 + 3) * 4 -> PRINT 20`.
- `examples/loop.asm`: cuenta regresiva `5..1`.
- `examples/input_echo.asm`: usa `IN`, imprime el valor y su cuadrado.
- `examples/call_store.asm`: demuestra `CALL/RET` y `LOAD/STORE` (imprime 49).
- `examples/hello_text.asm`: imprime "HI" y salto de línea usando `OUTC`.
- `examples/input_char_echo.asm`: lee un carácter con `INCH` y lo devuelve con `OUTC`.

## Extensiones posibles
- Depurador paso a paso y breakpoints.
- Sistema de llamadas (syscalls) para E/S Avanzada.
- Tipos adicionales (booleans, strings) y memoria de bytes.
