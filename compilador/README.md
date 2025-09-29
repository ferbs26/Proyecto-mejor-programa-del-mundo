# Compilador MiniLang

Una pequeña app con interfaz Tkinter para editar, ejecutar y compilar **MiniLang** (transpilado a Python).

- Ejecutar con un clic (F5).
- Compilar a bytecode `.pyc` (Ctrl+B) usando `py_compile`.

## Requisitos

- Python 3.10+ (Tkinter viene incluido en la instalación estándar de Python en Windows).
- No requiere dependencias externas.

## Instalación

Opcional, crear entorno virtual:

```bash
python -m venv .venv
.venv\\Scripts\\activate
```

Instalar dependencias (no hay, el archivo existe por formalidad):

```bash
pip install -r requirements.txt
```

## Uso

Ejecuta la app:

```bash
python main.py
```

- Pulsa "▶ Ejecutar" (o F5) para correr el script. La salida aparecerá en la consola inferior.
- Pulsa "⚙ Compilar .pyc" (o Ctrl+B) para generar el bytecode. El `.pyc` se creará en `__pycache__/`.
 
Trabaja con archivos **MiniLang** (`.ml`). Opcionalmente, activa "Mostrar generado" para ver el Python emitido al ejecutar/compilar.

## Sintaxis MiniLang v0 (español)

- **Asignación**: `nombre es igual a expr` (también se acepta `nombre = expr`). Las palabras clave y las variables no distinguen mayúsculas/minúsculas.
- **Salida**: `Escribe expr` | `Escribe(expr[, expr]*)` | `Escribe expr1, expr2`
- **Lectura**: `Introduce nombre[, nombre]*`
- **Ventana**: `Ventana "Título"[, ancho[, alto]]` (paréntesis opcionales). Si no se indica tamaño, usa `800x600`.
- **Condicional**: `Si condicion { ... } [Si no { ... }]`
- **Bucle**: `Mientras condicion { ... }`
- **Comparaciones**:
  - `a es igual a b` ⇒ `==`
  - `a es igual o mayor a b` ⇒ `>=`
  - `a es igual o menor a b` / `a es igual o menos a b` ⇒ `<=`
  - `a no es igual a b` ⇒ `!=`
  - `a es mayor que b` ⇒ `>`
  - `a es menor que b` ⇒ `<`
- **Lógicos**: `y` (AND), `o` (OR), `no` (NOT)
- **Expresiones**: `+ - * / %`, paréntesis `(...)`
- **Literales**: números (int/float) y cadenas con `""`
- **Comentarios**: `#` hasta fin de línea
- **Separador**: `;` opcional entre sentencias

Ejemplo:

```text
Introduce nombre, edad, tope
Escribe "Hola", nombre

Si edad es igual o mayor a 18 {
  Escribe "Sos mayor"
} Si no {
  Escribe "Sos menor"
}

contador es igual a 1
acumulado es igual a 0
Mientras contador es igual o menor a tope {
  acumulado es igual a acumulado + contador
  contador es igual a contador + 1
}
Escribe "Suma de 1 a", tope, "=", acumulado
```

Ejemplo extra (lógicos y comparadores):

```text
Introduce edad
Si edad es mayor que 17 y no (edad es igual a 21) {
  Escribe "Mayor y no 21"
} Si no {
  Escribe "17 o menos, o exactamente 21"
}

Si edad es igual a 18 o edad es igual a 19 {
  Escribe "18 o 19"
}
```

### Notas

- La ejecución desde la app no soporta entrada interactiva (`input()`).
- La compilación genera bytecode `.pyc` (no un `.exe`). Para empaquetar un `.exe` en el futuro puedes usar [PyInstaller](https://pyinstaller.org/):
  
  ```bash
  pip install pyinstaller
  pyinstaller --onefile --noconsole main.py
  ```

## Atajos de teclado

- Ctrl+N: Nuevo
- Ctrl+O: Abrir
- Ctrl+S: Guardar
- Ctrl+Shift+S: Guardar como
- F5: Ejecutar
- Ctrl+B: Compilar a .pyc
- Ctrl+L: Limpiar salida
