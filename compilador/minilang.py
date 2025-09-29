"""
MiniLang v0 - Transpilador a Python

 Características v0 (sintaxis en español):
- Asignación: nombre es igual a expr  (también se acepta `=`)
- Escritura: Escribe expr | Escribe(expr[, expr]*) | Escribe expr1, expr2
- Lectura: Introduce nombre[, nombre]*
- Condicional: Si condicion { ... } [Si no { ... }]
- Bucle: Mientras condicion { ... }
- Comparaciones en español: "es igual a" (==), "es mayor que" (>), "es menor que" (<), "no es igual a" (!=), "es igual o mayor a" (>=), "es igual o menor a" (<=)
- Expresiones aritméticas: + - * / % y paréntesis
- Literales: números (int/float) y cadenas con ""
- Comentarios con # hasta fin de línea
- Punto y coma opcional ;

Uso: transpile(source: str) -> str
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Union


# ----------------- Errores -----------------
class MiniLangError(Exception):
    def __init__(self, message: str, line: int, col: int):
        super().__init__(f"[L{line}:C{col}] {message}")
        self.line = line
        self.col = col


# ----------------- Tokens -----------------
@dataclass
class Token:
    type: str
    lexeme: str
    line: int
    col: int


KEYWORDS = {
    "let": "LET",
    "print": "PRINT",
    "write": "WRITE",
    "escribe": "WRITE",
    "read": "READ",
    "introduce": "READ",
    "if": "IF",
    "si": "IF",
    "else": "ELSE",
    "sino": "ELSE",
    "while": "WHILE",
    "mientras": "WHILE",
    "and": "AND",
    "or": "OR",
    "not": "NOT",
    "y": "AND",
    "o": "OR",
    "no": "NOT",
    "true": "TRUE",
    "false": "FALSE",
    "ventana": "WINDOW",
    "cubo": "CUBE",
    "wasd": "WASD",
}


class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.i = 0
        self.line = 1
        self.col = 1

    def _peek(self) -> str:
        return "" if self.i >= len(self.source) else self.source[self.i]

    def _advance(self) -> str:
        ch = self._peek()
        if ch == "":
            return ""
        self.i += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _make_token(self, type_: str, lex: str, line: int, col: int) -> Token:
        return Token(type_, lex, line, col)

    def _skip_whitespace_and_comments(self):
        while True:
            ch = self._peek()
            if ch in (" ", "\t", "\r"):
                self._advance()
                continue
            if ch == "#":
                while self._peek() not in ("", "\n"):
                    self._advance()
                continue
            # newlines are treated as whitespace too
            if ch == "\n":
                self._advance()
                continue
            break

    def _number(self) -> Token:
        start_i = self.i
        start_line, start_col = self.line, self.col
        saw_dot = False
        while self._peek().isdigit() or (self._peek() == "." and not saw_dot):
            if self._peek() == ".":
                saw_dot = True
            self._advance()
        lex = self.source[start_i:self.i]
        return self._make_token("NUMBER", lex, start_line, start_col)

    def _identifier(self) -> Token:
        start_i = self.i
        start_line, start_col = self.line, self.col
        while True:
            ch = self._peek()
            if ch.isalnum() or ch == "_":
                self._advance()
            else:
                break
        lex = self.source[start_i:self.i]
        lex_lower = lex.lower()
        ttype = KEYWORDS.get(lex_lower, "IDENT")
        # Identificadores en minúsculas para ser case-insensitive
        if ttype == "IDENT":
            return self._make_token(ttype, lex_lower, start_line, start_col)
        return self._make_token(ttype, lex, start_line, start_col)

    def _string(self) -> Token:
        # starting '"' already peeked
        start_line, start_col = self.line, self.col
        self._advance()  # consume opening quote
        chars = []
        while True:
            ch = self._peek()
            if ch == "":
                raise MiniLangError("Cadena sin cerrar", start_line, start_col)
            if ch == "\n":
                raise MiniLangError("Salto de línea dentro de cadena", self.line, self.col)
            if ch == "\\":
                self._advance()
                esc = self._peek()
                if esc == "":
                    raise MiniLangError("Secuencia de escape inválida", self.line, self.col)
                mapping = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
                chars.append(mapping.get(esc, esc))
                self._advance()
                continue
            if ch == '"':
                self._advance()  # closing quote
                break
            chars.append(ch)
            self._advance()
        return self._make_token("STRING", "".join(chars), start_line, start_col)

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        while True:
            self._skip_whitespace_and_comments()
            ch = self._peek()
            if ch == "":
                tokens.append(self._make_token("EOF", "", self.line, self.col))
                break
            line, col = self.line, self.col
            # operadores de 2 caracteres y comparadores
            if ch in ("<", ">"):
                self._advance()
                if self._peek() == "=":
                    op = "<=" if ch == "<" else ">="
                    self._advance()
                    tokens.append(self._make_token("LTE" if ch == "<" else "GTE", op, line, col))
                else:
                    tokens.append(self._make_token("LT" if ch == "<" else "GT", ch, line, col))
                continue
            if ch == "!":
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    tokens.append(self._make_token("BANGEQ", "!=", line, col))
                else:
                    tokens.append(self._make_token("BANG", "!", line, col))
                continue
            if ch == "=":
                # '==' o '='
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    tokens.append(self._make_token("EQEQ", "==", line, col))
                else:
                    tokens.append(self._make_token("EQUAL", "=", line, col))
                continue
            if ch.isdigit():
                tokens.append(self._number())
                continue
            if ch.isalpha() or ch == "_":
                tokens.append(self._identifier())
                continue
            if ch == '"':
                tokens.append(self._string())
                continue
            single = {
                "+": "PLUS",
                "-": "MINUS",
                "*": "STAR",
                "/": "SLASH",
                "%": "PERCENT",
                "(": "LPAREN",
                ")": "RPAREN",
                "{": "LBRACE",
                "}": "RBRACE",
                ";": "SEMICOLON",
                ",": "COMMA",
            }
            if ch in single:
                self._advance()
                tokens.append(self._make_token(single[ch], ch, line, col))
                continue
            raise MiniLangError(f"Carácter inesperado: {repr(ch)}", line, col)
        return tokens


# ----------------- AST -----------------
class Expr: ...

@dataclass
class Literal(Expr):
    value: Union[int, float, str, bool]

@dataclass
class Var(Expr):
    name: str

@dataclass
class Unary(Expr):
    op: str
    right: Expr

@dataclass
class Binary(Expr):
    left: Expr
    op: str
    right: Expr


class Stmt: ...

@dataclass
class Let(Stmt):
    name: str
    expr: Expr

@dataclass
class Assign(Stmt):
    name: str
    expr: Expr

@dataclass
class PrintStmt(Stmt):
    exprs: List[Expr]

@dataclass
class ReadStmt(Stmt):
    names: List[str]

@dataclass
class WindowStmt(Stmt):
    title: Expr
    width: Optional[Expr]
    height: Optional[Expr]

@dataclass
class CubeStmt(Stmt):
    name: str
    x: Expr
    y: Expr
    size: Expr
    color: Optional[Expr]

@dataclass
class WasdStmt(Stmt):
    name: str
    speed: Optional[Expr]

@dataclass
class IfStmt(Stmt):
    condition: Expr
    then_branch: List[Stmt]
    else_branch: Optional[List[Stmt]]

@dataclass
class WhileStmt(Stmt):
    condition: Expr
    body: List[Stmt]


@dataclass
class Program:
    statements: List[Stmt]


# ----------------- Parser -----------------
class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.i = 0

    def _peek(self) -> Token:
        return self.tokens[self.i]

    def _advance(self) -> Token:
        tok = self._peek()
        if self.i < len(self.tokens) - 1:
            self.i += 1
        return tok

    def _check(self, ttype: str) -> bool:
        return self._peek().type == ttype

    def _match(self, *types: str) -> bool:
        if self._peek().type in types:
            self._advance()
            return True
        return False

    def _expect(self, ttype: str, message: str) -> Token:
        if not self._check(ttype):
            tok = self._peek()
            raise MiniLangError(message, tok.line, tok.col)
        return self._advance()

    def parse(self) -> Program:
        stmts: List[Stmt] = []
        while not self._check("EOF"):
            stmts.append(self._statement())
            # ; opcional entre sentencias
            self._match("SEMICOLON")
        return Program(stmts)

    def _statement(self) -> Stmt:
        if self._match("LET"):
            name_tok = self._expect("IDENT", "Se esperaba un identificador después de 'let'")
            self._expect("EQUAL", "Se esperaba '=' en declaración 'let'")
            expr = self._expression()
            return Let(name_tok.lexeme, expr)
        if self._match("READ"):
            names: List[str] = []
            if self._match("LPAREN"):
                if not self._check("RPAREN"):
                    names.append(self._expect("IDENT", "Se esperaba un identificador en Read").lexeme)
                    while self._match("COMMA"):
                        names.append(self._expect("IDENT", "Se esperaba un identificador en Read").lexeme)
                self._expect("RPAREN", "Falta ')' en Read(...)")
            else:
                names.append(self._expect("IDENT", "Se esperaba un identificador en Read").lexeme)
                while self._match("COMMA"):
                    names.append(self._expect("IDENT", "Se esperaba un identificador en Read").lexeme)
                # tolerar un ')' extra
                self._match("RPAREN")
            return ReadStmt(names)
        if self._match("WRITE") or self._match("PRINT"):
            # Admite: Write expr | Write(expr[, expr]*) | Write expr1, expr2 (sin paréntesis)
            exprs: List[Expr] = []
            if self._match("LPAREN"):
                # permitir print() vacío
                if not self._check("RPAREN"):
                    exprs.append(self._expression())
                    while self._match("COMMA"):
                        exprs.append(self._expression())
                self._expect("RPAREN", "Falta ')' en print(...) ")
            else:
                exprs.append(self._expression())
                while self._match("COMMA"):
                    exprs.append(self._expression())
                # tolerar un paréntesis de cierre suelto al final (p.ej., Write a, b))
                self._match("RPAREN")
            return PrintStmt(exprs)
        if self._match("WINDOW"):
            # Ventana titulo[, ancho[, alto]] con o sin paréntesis
            parts: List[Expr] = []
            if self._match("LPAREN"):
                if not self._check("RPAREN"):
                    parts.append(self._expression())
                    while self._match("COMMA"):
                        parts.append(self._expression())
                self._expect("RPAREN", "Falta ')' en Ventana(...)")
            else:
                parts.append(self._expression())
                while self._match("COMMA"):
                    parts.append(self._expression())
                # tolerar un ')' extra
                self._match("RPAREN")
            if not parts:
                tok = self._peek()
                raise MiniLangError("Se esperaba un título para Ventana", tok.line, tok.col)
            title = parts[0]
            width = parts[1] if len(parts) > 1 else None
            height = parts[2] if len(parts) > 2 else None
            return WindowStmt(title, width, height)
        if self._match("CUBE"):
            # Cubo nombre, x, y, tamaño[, color]
            name_tok = self._expect("IDENT", "Se esperaba un nombre de cubo (identificador)")
            self._expect("COMMA", "Se esperaba ',' después del nombre del cubo")
            x = self._expression()
            self._expect("COMMA", "Se esperaba ',' después de X")
            y = self._expression()
            self._expect("COMMA", "Se esperaba ',' después de Y")
            size = self._expression()
            color: Optional[Expr] = None
            if self._match("COMMA"):
                color = self._expression()
            # tolerar paréntesis de cierre suelto
            self._match("RPAREN")
            return CubeStmt(name_tok.lexeme, x, y, size, color)
        if self._match("WASD"):
            # WASD nombre[, velocidad]
            name_tok = self._expect("IDENT", "Se esperaba un nombre de cubo para WASD")
            speed: Optional[Expr] = None
            if self._match("COMMA"):
                speed = self._expression()
            self._match("RPAREN")
            return WasdStmt(name_tok.lexeme, speed)
        if self._match("IF"):
            cond = self._expression()
            then_branch = self._block()
            else_branch: Optional[List[Stmt]] = None
            if self._match("ELSE"):
                else_branch = self._block()
            else:
                # Aceptar español: 'Si no' como else (dos palabras)
                if (
                    self.i + 1 < len(self.tokens)
                    and (
                        (self._check("IDENT") and self.tokens[self.i].lexeme.lower() == "si")
                        or (self._check("IF") and self.tokens[self.i].lexeme.lower() == "si")
                    )
                    and (
                        (self.tokens[self.i + 1].type == "IDENT" and self.tokens[self.i + 1].lexeme == "no")
                        or self.tokens[self.i + 1].type == "NOT"
                    )
                ):
                    self._advance()  # 'si'
                    self._advance()  # 'no' (IDENT) o token NOT
                    else_branch = self._block()
            return IfStmt(cond, then_branch, else_branch)
        if self._match("WHILE"):
            cond = self._expression()
            body = self._block()
            return WhileStmt(cond, body)
        # Asignación simple: IDENT = expr  |  IDENT es igual a expr
        if self._check("IDENT"):
            # mirar si hay '=' luego
            ident_tok = self._peek()
            # lookahead
            if self.tokens[self.i + 1].type == "EQUAL":
                self._advance()  # consume IDENT
                self._advance()  # consume '='
                expr = self._expression()
                return Assign(ident_tok.lexeme, expr)
            # forma en español: es igual a
            if (
                self.i + 3 < len(self.tokens)
                and self.tokens[self.i + 1].type == "IDENT" and self.tokens[self.i + 1].lexeme == "es"
                and self.tokens[self.i + 2].type == "IDENT" and self.tokens[self.i + 2].lexeme == "igual"
                and self.tokens[self.i + 3].type == "IDENT" and self.tokens[self.i + 3].lexeme == "a"
            ):
                self._advance()  # consume IDENT (nombre)
                self._advance()  # 'es'
                self._advance()  # 'igual'
                self._advance()  # 'a'
                expr = self._expression()
                return Assign(ident_tok.lexeme, expr)
        # Si no coincide, error
        tok = self._peek()
        raise MiniLangError(f"Sentencia no reconocida cerca de '{tok.lexeme}'", tok.line, tok.col)

    # Precedencias: or > and > equality > comparison > term > factor > unary > primary
    def _expression(self) -> Expr:
        return self._or()

    def _or(self) -> Expr:
        expr = self._and()
        while self._match("OR"):
            op = "or"
            right = self._and()
            expr = Binary(expr, op, right)
        return expr

    def _and(self) -> Expr:
        expr = self._equality()
        while self._match("AND"):
            op = "and"
            right = self._equality()
            expr = Binary(expr, op, right)
        return expr

    def _equality(self) -> Expr:
        expr = self._comparison()
        while True:
            if self._match("EQEQ", "BANGEQ"):
                op = self.tokens[self.i - 1].lexeme
                right = self._comparison()
                expr = Binary(expr, op, right)
                continue
            # Español: "es igual a" como operador de igualdad
            if (
                self._check("IDENT")
                and self.i + 2 < len(self.tokens)
                and self.tokens[self.i].lexeme == "es"
                and self.tokens[self.i + 1].type == "IDENT" and self.tokens[self.i + 1].lexeme == "igual"
                and self.tokens[self.i + 2].type == "IDENT" and self.tokens[self.i + 2].lexeme == "a"
            ):
                # consumir 'es igual a'
                self._advance(); self._advance(); self._advance()
                right = self._comparison()
                expr = Binary(expr, "==", right)
                continue
            # Español: "no es igual a" como operador de desigualdad
            if (
                self.i + 3 < len(self.tokens)
                and (
                    (self._check("IDENT") and self.tokens[self.i].lexeme == "no")
                    or self._check("NOT")
                )
                and self.tokens[self.i + 1].type == "IDENT" and self.tokens[self.i + 1].lexeme == "es"
                and self.tokens[self.i + 2].type == "IDENT" and self.tokens[self.i + 2].lexeme == "igual"
                and self.tokens[self.i + 3].type == "IDENT" and self.tokens[self.i + 3].lexeme == "a"
            ):
                # consumir 'no es igual a'
                self._advance(); self._advance(); self._advance(); self._advance()
                right = self._comparison()
                expr = Binary(expr, "!=", right)
                continue
            break
        return expr

    def _comparison(self) -> Expr:
        expr = self._term()
        while True:
            if self._match("LT", "LTE", "GT", "GTE"):
                op = self.tokens[self.i - 1].lexeme
                right = self._term()
                expr = Binary(expr, op, right)
                continue
            # Español: "es igual o mayor a" -> >= ; "es igual o menos/menor a" -> <= (requiere 'a')
            if (
                self.i + 4 < len(self.tokens)
                and self.tokens[self.i].lexeme.lower() == "es"
                and self.tokens[self.i + 1].lexeme.lower() == "igual"
                and self.tokens[self.i + 2].lexeme.lower() == "o"
                and self.tokens[self.i + 3].lexeme.lower() in ("mayor", "menos", "menor")
                and self.tokens[self.i + 4].lexeme.lower() == "a"
            ):
                word = self.tokens[self.i + 3].lexeme.lower()
                self._advance(); self._advance(); self._advance(); self._advance(); self._advance()
                right = self._term()
                op = ">=" if word == "mayor" else "<="
                expr = Binary(expr, op, right)
                continue
            # Español: "es mayor que" -> > ; "es menor que" -> <
            if (
                self._check("IDENT")
                and self.i + 2 < len(self.tokens)
                and self.tokens[self.i].lexeme == "es"
                and self.tokens[self.i + 1].type == "IDENT" and self.tokens[self.i + 1].lexeme in ("mayor", "menor")
                and self.tokens[self.i + 2].type == "IDENT" and self.tokens[self.i + 2].lexeme == "que"
            ):
                word = self.tokens[self.i + 1].lexeme
                self._advance(); self._advance(); self._advance()
                right = self._term()
                op = ">" if word == "mayor" else "<"
                expr = Binary(expr, op, right)
                continue
            break
        return expr

    def _term(self) -> Expr:
        expr = self._factor()
        while self._match("PLUS", "MINUS"):
            op = self.tokens[self.i - 1].lexeme
            right = self._factor()
            expr = Binary(expr, op, right)
        return expr

    def _factor(self) -> Expr:
        expr = self._unary()
        while self._match("STAR", "SLASH", "PERCENT"):
            op = self.tokens[self.i - 1].lexeme
            right = self._unary()
            expr = Binary(expr, op, right)
        return expr

    def _unary(self) -> Expr:
        if self._match("PLUS", "MINUS"):
            op = self.tokens[self.i - 1].lexeme
            right = self._unary()
            return Unary(op, right)
        if self._match("NOT"):
            op = "not "
            right = self._unary()
            return Unary(op, right)
        if self._match("BANG"):
            op = "not "
            right = self._unary()
            return Unary(op, right)
        return self._primary()

    def _primary(self) -> Expr:
        tok = self._peek()
        if self._match("NUMBER"):
            lex = tok.lexeme
            if "." in lex:
                return Literal(float(lex))
            return Literal(int(lex))
        if self._match("STRING"):
            return Literal(tok.lexeme)
        if self._match("TRUE"):
            return Literal(True)
        if self._match("FALSE"):
            return Literal(False)
        if self._match("IDENT"):
            return Var(tok.lexeme)
        if self._match("LPAREN"):
            expr = self._expression()
            self._expect("RPAREN", "Falta ')' de cierre")
            return expr
        raise MiniLangError("Expresión no válida", tok.line, tok.col)

    def _block(self) -> List[Stmt]:
        self._expect("LBRACE", "Se esperaba '{' para iniciar un bloque")
        stmts: List[Stmt] = []
        while not self._check("RBRACE") and not self._check("EOF"):
            stmts.append(self._statement())
            self._match("SEMICOLON")
        self._expect("RBRACE", "Falta '}' de cierre del bloque")
        return stmts


# ----------------- Codegen -----------------
class Codegen:
    def __init__(self, inputs: Optional[List[str]] = None):
        self.lines: List[str] = []
        self.indent = 0
        self.inputs = inputs or []
        self.window_used = False
        self.canvas_used = False
        self.cubes_runtime_emitted = False
        self.wasd_helpers_emitted = False

    def emit(self, s: str):
        self.lines.append("    " * self.indent + s)

    def gen_expr(self, e: Expr) -> str:
        if isinstance(e, Literal):
            if isinstance(e.value, str):
                return repr(e.value)
            return str(e.value)
        if isinstance(e, Var):
            return e.name
        if isinstance(e, Unary):
            return f"({e.op}{self.gen_expr(e.right)})"
        if isinstance(e, Binary):
            return f"({self.gen_expr(e.left)} {e.op} {self.gen_expr(e.right)})"
        raise AssertionError(f"Expr desconocida: {e}")

    def gen_stmt(self, s: Stmt):
        if isinstance(s, Let) or isinstance(s, Assign):
            self.emit(f"{s.name} = {self.gen_expr(s.expr)}")
        elif isinstance(s, PrintStmt):
            args = ", ".join(self.gen_expr(e) for e in s.exprs)
            self.emit(f"print({args})")
        elif isinstance(s, ReadStmt):
            for n in s.names:
                self.emit(f"{n} = __ml_read()")
        elif isinstance(s, IfStmt):
            self.emit(f"if {self.gen_expr(s.condition)}:")
            self.indent += 1
            for st in s.then_branch:
                self.gen_stmt(st)
            self.indent -= 1
            if s.else_branch is not None:
                self.emit("else:")
                self.indent += 1
                for st in s.else_branch:
                    self.gen_stmt(st)
                self.indent -= 1
        elif isinstance(s, WhileStmt):
            self.emit(f"while {self.gen_expr(s.condition)}:")
            self.indent += 1
            for st in s.body:
                self.gen_stmt(st)
            self.indent -= 1
        elif isinstance(s, WindowStmt):
            if not self.window_used:
                self.emit("import tkinter as tk")
                self.emit("root = tk.Tk()")
                self.window_used = True
            title_code = self.gen_expr(s.title)
            self.emit(f"root.title(str({title_code}))")
            # tamaño
            if s.width is not None:
                w_code = f"int({self.gen_expr(s.width)})"
            else:
                w_code = "800"
            if s.height is not None:
                h_code = f"int({self.gen_expr(s.height)})"
            else:
                h_code = "600"
            self.emit(f"root.geometry(str({w_code}) + 'x' + str({h_code}))")
            # asegurar canvas si ya fue solicitado antes
            if self.canvas_used and 'canvas' not in '\n'.join(self.lines):
                self.emit("canvas = tk.Canvas(root, bg='white')")
                self.emit("canvas.pack(fill='both', expand=True)")
        elif isinstance(s, CubeStmt):
            # Asegurar root y canvas
            if not self.window_used:
                self.emit("import tkinter as tk")
                self.emit("root = tk.Tk()")
                self.window_used = True
            if not self.canvas_used:
                self.emit("canvas = tk.Canvas(root, bg='white')")
                self.emit("canvas.pack(fill='both', expand=True)")
                self.canvas_used = True
            if not self.cubes_runtime_emitted:
                self.emit("__ml_cubes = {}")
                self.cubes_runtime_emitted = True
            n = s.name
            x = f"int({self.gen_expr(s.x)})"
            y = f"int({self.gen_expr(s.y)})"
            size = f"int({self.gen_expr(s.size)})"
            color = self.gen_expr(s.color) if s.color is not None else repr("#3498db")
            self.emit(f"__ml_id = canvas.create_rectangle({x}, {y}, {x}+{size}, {y}+{size}, fill=str({color}), outline='')")
            self.emit(f"__ml_cubes[{repr(n)}] = {{'id': __ml_id, 'x': {x}, 'y': {y}, 'size': {size}, 'speed': 5}}")
        elif isinstance(s, WasdStmt):
            # Asegurar root/canvas y runtime
            if not self.window_used:
                self.emit("import tkinter as tk")
                self.emit("root = tk.Tk()")
                self.window_used = True
            if not self.canvas_used:
                self.emit("canvas = tk.Canvas(root, bg='white')")
                self.emit("canvas.pack(fill='both', expand=True)")
                self.canvas_used = True
            if not self.cubes_runtime_emitted:
                self.emit("__ml_cubes = {}")
                self.cubes_runtime_emitted = True
            if not self.wasd_helpers_emitted:
                self.emit("def __ml_bind_wasd(name, speed):")
                self.indent += 1
                self.emit("def _on_key(event):")
                self.indent += 1
                self.emit("k = event.keysym.lower()")
                self.emit("dx = dy = 0")
                self.emit("if k == 'w': dy = -speed")
                self.emit("elif k == 's': dy = speed")
                self.emit("elif k == 'a': dx = -speed")
                self.emit("elif k == 'd': dx = speed")
                self.emit("c = __ml_cubes.get(name)")
                self.emit("if c and (dx or dy):")
                self.indent += 1
                self.emit("canvas.move(c['id'], dx, dy)")
                self.emit("c['x'] += dx; c['y'] += dy")
                self.indent -= 1
                self.indent -= 1
                self.emit("root.bind('<Key>', _on_key)")
                self.indent -= 1
                self.wasd_helpers_emitted = True
            n = s.name
            sp = f"int({self.gen_expr(s.speed)})" if s.speed is not None else "5"
            self.emit(f"__ml_c = __ml_cubes.get({repr(n)})")
            self.emit(f"if __ml_c: __ml_c['speed'] = {sp}")
            self.emit(f"__ml_bind_wasd({repr(n)}, {sp})")
        else:
            raise AssertionError(f"Stmt desconocida: {s}")

    def gen(self, program: Program) -> str:
        self.emit("# Código generado por MiniLang v0")
        # runtime simple para Read
        inputs_code = ", ".join(repr(s) for s in self.inputs)
        self.emit(f"__ml_inputs = [{inputs_code}]")
        self.emit("def __ml_read():")
        self.indent += 1
        self.emit("if not __ml_inputs: raise RuntimeError('No hay más entradas disponibles para Introduce')")
        self.emit("s = __ml_inputs.pop(0)")
        self.emit("try:")
        self.indent += 1
        self.emit("return int(s)")
        self.indent -= 1
        self.emit("except Exception:")
        self.indent += 1
        self.emit("pass")
        self.indent -= 1
        self.emit("try:")
        self.indent += 1
        self.emit("return float(s)")
        self.indent -= 1
        self.emit("except Exception:")
        self.indent += 1
        self.emit("pass")
        self.indent -= 1
        self.emit("return s")
        self.indent -= 1
        self.emit("")
        for st in program.statements:
            self.gen_stmt(st)
        if self.window_used:
            self.emit("root.mainloop()")
        return "\n".join(self.lines) + "\n"


# ----------------- API -----------------
def transpile(source: str, inputs: Optional[List[str]] = None) -> str:
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    program = parser.parse()
    code = Codegen(inputs=inputs).gen(program)
    return code

def collect_read_vars(source: str) -> List[str]:
    """Devuelve los nombres de variables leídas por 'Read' en orden de aparición (estático)."""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    program = parser.parse()

    result: List[str] = []

    def walk_stmts(stmts: List[Stmt]):
        for s in stmts:
            if isinstance(s, ReadStmt):
                result.extend(s.names)
            elif isinstance(s, IfStmt):
                walk_stmts(s.then_branch)
                if s.else_branch:
                    walk_stmts(s.else_branch)
            elif isinstance(s, WhileStmt):
                walk_stmts(s.body)

    walk_stmts(program.statements)
    return result
