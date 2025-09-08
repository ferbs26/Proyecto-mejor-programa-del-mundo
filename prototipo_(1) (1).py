import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import os
import subprocess

# -------------------- Utilidades --------------------

def es_admin_windows():
    if os.name != "nt":
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_powershell(cmd):
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True, text=True
    )

def lista_usuarios_locales_windows():
    cmd = "Get-LocalUser | Select-Object -ExpandProperty Name"
    res = run_powershell(cmd)
    usuarios = []
    if res.returncode == 0 and res.stdout:
        for linea in res.stdout.splitlines():
            nombre = linea.strip()
            if nombre:
                usuarios.append(nombre)
    return usuarios

def obtener_nombre_completo_windows(usuario):
    cmd = f"(Get-LocalUser -Name '{usuario}').FullName"
    res = run_powershell(cmd)
    if res.returncode == 0:
        return res.stdout.strip()
    return ""

def cambiar_nombre_completo_windows(usuario, nuevo_fullname):
    cmd = f"Set-LocalUser -Name '{usuario}' -FullName '{nuevo_fullname}'"
    res = run_powershell(cmd)
    return (res.returncode == 0, (res.stderr or '').strip())

def resolver_nombre_grupo_por_sid(sid):
    ps = (
        f"$g = Get-LocalGroup | Where-Object {{ $_.SID -eq '{sid}' }}; "
        "if ($g) { $g.Name } else { '' }"
    )
    res = run_powershell(ps)
    name = (res.stdout or '').strip() if res.returncode == 0 else ''
    return name

ADMIN_GROUP_SIDS = [
    ("S-1-5-32-544", "Administradores"),              # Administrators
    ("S-1-5-32-551", "Operadores de copia de seguridad"),  # Backup Operators
    ("S-1-5-32-547", "Usuarios avanzados"),           # Power Users
    ("S-1-5-32-555", "Usuarios de Escritorio remoto"), # Remote Desktop Users
    ("S-1-5-32-556", "Operadores de configuración de red"), # Network Configuration Operators
    ("S-1-5-32-550", "Operadores de impresión"),      # Print Operators
    ("S-1-5-32-562", "Usuarios COM distribuidos"),    # Distributed COM Users
    ("S-1-5-32-573", "Lectores de registros de eventos"), # Event Log Readers
    ("S-1-5-32-578", "Administradores de Hyper-V"),   # Hyper-V Administrators
    ("S-1-5-32-580", "Usuarios de administración remota"), # Remote Management Users
]

def grupos_admin_disponibles():
    # Función ya no utilizada, se mantiene por compatibilidad si fuese llamada en el futuro
    grupos = []
    for sid, etiqueta in ADMIN_GROUP_SIDS:
        nombre = resolver_nombre_grupo_por_sid(sid) or etiqueta
        test = run_powershell(f"Get-LocalGroup -Name '{nombre}'")
        if test.returncode == 0:
            grupos.append({"sid": sid, "name": nombre, "label": etiqueta})
    return grupos

def es_miembro_de_grupo(usuario, grupo):
    # Intenta detectar el miembro como EQUIPO\\usuario o solo usuario
    ps = (
        f"$cn=$env:COMPUTERNAME; "
        f"$m=Get-LocalGroupMember -Group '{grupo}' -ErrorAction SilentlyContinue; "
        f"if($m){{ $nombres=$m | Select-Object -ExpandProperty Name; "
        f"if($nombres -contains (\"$cn\\\\{usuario}\") -or $nombres -contains (\"{usuario}\")){{ '1' }} else {{ '0' }} }} else {{ '0' }}"
    )
    res = run_powershell(ps)
    return res.returncode == 0 and (res.stdout or '').strip() == '1'

def agregar_a_grupo(usuario, grupo):
    res = run_powershell(f"Add-LocalGroupMember -Group '{grupo}' -Member '{usuario}'")
    return (res.returncode == 0, (res.stderr or '').strip())

def quitar_de_grupo(usuario, grupo):
    res = run_powershell(f"Remove-LocalGroupMember -Group '{grupo}' -Member '{usuario}'")
    return (res.returncode == 0, (res.stderr or '').strip())

def obtener_sid_usuario(usuario):
    res = run_powershell(f"(Get-LocalUser -Name '{usuario}').SID.Value")
    return (res.stdout or '').strip() if res.returncode == 0 else ''

def renombrar_usuario_windows(nombre_actual, nuevo_nombre):
    cmd = f"Rename-LocalUser -Name '{nombre_actual}' -NewName '{nuevo_nombre}'"
    res = run_powershell(cmd)
    return (res.returncode == 0, (res.stderr or '').strip())

# ---------- Detección robusta de Admin por SID (con recursión local) ----------
def obtener_sid_local_o_vacio(nombre_principal):
    # Intenta local primero; si falla, devuelve cadena vacía
    res = run_powershell(f"(Get-LocalUser -Name '{nombre_principal}' -ErrorAction SilentlyContinue).SID.Value")
    sid = (res.stdout or '').strip() if res.returncode == 0 else ''
    return sid

def obtener_miembros_grupo_detalle(grupo):
    ps = (
        f"$m=Get-LocalGroupMember -Group '{grupo}' -ErrorAction SilentlyContinue | "
        "Select-Object Name,ObjectClass,SID; $m | ForEach-Object {\n"
        "  $n=$_.Name; $c=$_.ObjectClass; $s=$_.SID.Value;\n"
        "  if(-not $s){ try { $s=[System.Security.Principal.NTAccount]$n; $s=$s.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $s='' } }\n"
        "  Write-Output ($n+'|'+$c+'|'+$s)\n"
        "}"
    )
    res = run_powershell(ps)
    miembros = []
    if res.returncode == 0 and res.stdout:
        for line in res.stdout.splitlines():
            parts = line.strip().split('|')
            if len(parts) == 3:
                miembros.append({'Name': parts[0], 'ObjectClass': parts[1], 'SID': parts[2]})
    return miembros

def es_grupo_local(nombre_grupo):
    test = run_powershell(f"Get-LocalGroup -Name '{nombre_grupo}'")
    return test.returncode == 0

def expandir_sids_grupo_local(grupo, _visitados=None):
    if _visitados is None:
        _visitados = set()
    if grupo in _visitados:
        return set(), False
    _visitados.add(grupo)
    miembros = obtener_miembros_grupo_detalle(grupo)
    sids = set()
    hay_grupos_no_locales = False
    for m in miembros:
        sid = m.get('SID') or ''
        if sid:
            sids.add(sid)
        if m.get('ObjectClass','').lower() == 'group':
            nombre_m = m.get('Name','')
            if es_grupo_local(nombre_m):
                s_local, flag = expandir_sids_grupo_local(nombre_m, _visitados)
                sids |= s_local
                hay_grupos_no_locales = hay_grupos_no_locales or flag
            else:
                # Grupo de dominio u otro origen: no podemos expandir
                hay_grupos_no_locales = True
    return sids, hay_grupos_no_locales

def estatus_admin_usuario(usuario):
    """Devuelve (estado, nota_indirecta): estado in {'Si','No'}; nota_indirecta True si hay grupos externos que podrían dar admin indirecto.
    """
    sid_user = obtener_sid_usuario(usuario)
    if not sid_user:
        return 'No', False
    grupo_admin = nombre_grupo_administradores_windows()
    sids_admins, hay_externos = expandir_sids_grupo_local(grupo_admin)
    if sid_user in sids_admins:
        return 'Sí', False
    return 'No', hay_externos

def nombre_grupo_usuarios_windows():
    # Resolver el nombre localizado del grupo BUILTIN Users (SID S-1-5-32-545)
    ps = (
        "$g = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-545' }; "
        "if ($g) { $g.Name } else { '' }"
    )
    res = run_powershell(ps)
    name = (res.stdout or '').strip() if res.returncode == 0 else ''
    if not name:
        # Fallbacks comunes
        for n in ("Usuarios", "Users"):
            test = run_powershell(f"Get-LocalGroup -Name '{n}'")
            if test.returncode == 0:
                return n
    return name or 'Users'

def crear_usuario_windows(nombre, fullname="", password=""):
    grupo = nombre_grupo_usuarios_windows()
    if password:
        cmd = (
            f"$pass = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
            f"New-LocalUser -Name '{nombre}' -Password $pass -FullName '{fullname}' -PasswordNeverExpires -UserMayNotChangePassword; "
            f"Enable-LocalUser -Name '{nombre}'; "
            f"Add-LocalGroupMember -Group '{grupo}' -Member '{nombre}'"
        )
    else:
        cmd = (
            f"New-LocalUser -Name '{nombre}' -NoPassword -FullName '{fullname}'; "
            f"Enable-LocalUser -Name '{nombre}'; "
            f"Add-LocalGroupMember -Group '{grupo}' -Member '{nombre}'"
        )
    res = run_powershell(cmd)
    return (res.returncode == 0, (res.stderr or '').strip())

def nombre_grupo_administradores_windows():
    # Resolver nombre localizado del grupo BUILTIN Administrators (SID S-1-5-32-544)
    ps = (
        "$g = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-544' }; "
        "if ($g) { $g.Name } else { '' }"
    )
    res = run_powershell(ps)
    name = (res.stdout or '').strip() if res.returncode == 0 else ''
    if not name:
        for n in ("Administradores", "Administrators"):
            test = run_powershell(f"Get-LocalGroup -Name '{n}'")
            if test.returncode == 0:
                return n
    return name or 'Administrators'

def agregar_a_administradores_windows(usuario):
    grupo = nombre_grupo_administradores_windows()
    cmd = f"Add-LocalGroupMember -Group '{grupo}' -Member '{usuario}'"
    res = run_powershell(cmd)
    return (res.returncode == 0, (res.stderr or '').strip())

def quitar_de_administradores_windows(usuario):
    grupo = nombre_grupo_administradores_windows()
    cmd = f"Remove-LocalGroupMember -Group '{grupo}' -Member '{usuario}'"
    res = run_powershell(cmd)
    return (res.returncode == 0, (res.stderr or '').strip())

def eliminar_usuario_windows(nombre):
    cmd = f"Remove-LocalUser -Name '{nombre}'"
    res = run_powershell(cmd)
    return (res.returncode == 0, (res.stderr or '').strip())

# -------------------- UI (Tkinter) --------------------

root = tk.Tk()
root.title("Gestión de usuarios locales")
root.geometry("600x400")

notebook = ttk.Notebook(root)
frame1 = ttk.Frame(notebook)

notebook.add(frame1, text="Usuarios locales")
notebook.pack(expand=1, fill="both")

tree = ttk.Treeview(frame1, columns=("Usuario", "Nombre completo", "Admin"), show="headings")
tree.heading("Usuario", text="Usuario")
tree.heading("Nombre completo", text="Nombre completo")
tree.heading("Admin", text="Admin")
tree.pack(expand=1, fill="both")

def es_usuario_protegido(nombre):
    protegidos = {"administrator", "administrador", "guest", "invitado"}
    try:
        actual = os.getlogin()
    except Exception:
        actual = os.environ.get("USERNAME", "")
    nombres = {nombre.lower(), actual.lower()}
    return bool(protegidos.intersection(nombres)) or (nombre.lower() == (actual or "").lower())

def mostrar_usuarios():
    for item in tree.get_children():
        tree.delete(item)
    usuarios = lista_usuarios_locales_windows()
    for usuario in usuarios:
        fullname = obtener_nombre_completo_windows(usuario)
        estado, ind = estatus_admin_usuario(usuario)
        etiqueta = estado if not ind else "¿Indirecto?"
        tree.insert("", "end", values=(usuario, fullname, etiqueta))

mostrar_usuarios()

def modificar_usuario():
    seleccionado = tree.selection()
    if not seleccionado:
        return
    item = seleccionado[0]
    valores = tree.item(item, "values")
    usuario = valores[0]

    opcion = simpledialog.askstring("Modificar", "¿Qué desea modificar? (usuario/nombre completo/admin):", parent=root)

    if opcion == "usuario":
        nuevo_nombre = simpledialog.askstring("Modificar usuario", f"Nuevo nombre de usuario para {usuario}:", parent=root)
        if nuevo_nombre and nuevo_nombre != usuario:
            if es_usuario_protegido(usuario):
                messagebox.showwarning("Restringido", "Este usuario no puede ser renombrado (cuenta protegida o en uso).")
            else:
                ok, err = renombrar_usuario_windows(usuario, nuevo_nombre)
                if ok:
                    messagebox.showinfo("Éxito", f"Usuario renombrado a {nuevo_nombre}")
                else:
                    messagebox.showerror("Error", f"No se pudo renombrar el usuario.\n{err}")
    elif opcion == "fullname":
        nuevo_fullname = simpledialog.askstring("Modificar nombre completo", f"Nuevo nombre completo para {usuario}:", parent=root)
        if nuevo_fullname:
            ok, err = cambiar_nombre_completo_windows(usuario, nuevo_fullname)
            if ok:
                messagebox.showinfo("Éxito", f"Nombre completo de {usuario} cambiado a {nuevo_fullname}")
            else:
                messagebox.showerror("Error", f"No se pudo cambiar el nombre completo.\n{err}")
    elif opcion in ("admin", "administrador", "administradores"):
        accion = simpledialog.askstring("Administradores", "Acción sobre Administradores (agregar/quitar):", parent=root)
        if accion and accion.lower().startswith("agreg"):
            ok, err = agregar_a_administradores_windows(usuario)
            if ok:
                messagebox.showinfo("Éxito", f"{usuario} agregado al grupo de administradores.")
            else:
                messagebox.showerror("Error", f"No se pudo agregar a administradores.\n{err}")
        elif accion and accion.lower().startswith("quita"):
            if es_usuario_protegido(usuario):
                messagebox.showwarning("Restringido", "No se puede quitar privilegios de administrador a una cuenta protegida o la cuenta actual desde aquí.")
            else:
                ok, err = quitar_de_administradores_windows(usuario)
                if ok:
                    messagebox.showinfo("Éxito", f"{usuario} quitado del grupo de administradores.")
                else:
                    messagebox.showerror("Error", f"No se pudo quitar de administradores.\n{err}")
    else:
        messagebox.showinfo("Info", "Opción no válida.")

    mostrar_usuarios()

def agregar_usuario():
    nombre = simpledialog.askstring("Nuevo usuario", "Nombre de usuario:", parent=root)
    if not nombre:
        return
    fullname = simpledialog.askstring("Nuevo usuario", "Nombre completo (opcional):", parent=root)
    password = simpledialog.askstring("Nuevo usuario", "Contraseña (opcional, dejar vacío si no):", parent=root, show="*")

    ok, err = crear_usuario_windows(nombre, fullname or "", password or "")
    if ok:
        messagebox.showinfo("Éxito", f"Usuario {nombre} creado y habilitado.")
        # Ofrecer agregar a administradores
        desea_admin = messagebox.askyesno("Privilegios", "¿Agregar este usuario al grupo de administradores?")
        if desea_admin:
            ok2, err2 = agregar_a_administradores_windows(nombre)
            if ok2:
                messagebox.showinfo("Éxito", f"{nombre} agregado al grupo de administradores.")
            else:
                messagebox.showerror("Error", f"No se pudo agregar a administradores.\n{err2}")
        # Eliminado: configuración de derechos (User Rights)
    else:
        messagebox.showerror("Error", f"No se pudo crear el usuario.\n{err}")
    mostrar_usuarios()


def borrar_usuario():
    seleccionado = tree.selection()
    if not seleccionado:
        return
    item = seleccionado[0]
    valores = tree.item(item, "values")
    usuario = valores[0]

    confirmar = messagebox.askyesno("Confirmar", f"¿Seguro que querés eliminar el usuario {usuario}?")
    if confirmar:
        if es_usuario_protegido(usuario):
            messagebox.showwarning("Restringido", "Este usuario no puede ser eliminado (cuenta protegida o en uso).")
        else:
            ok, err = eliminar_usuario_windows(usuario)
            if ok:
                messagebox.showinfo("Éxito", f"Usuario {usuario} eliminado.")
            else:
                messagebox.showerror("Error", f"No se pudo eliminar el usuario.\n{err}")
        mostrar_usuarios()

# -------------------- Botones --------------------

btn_modificar = ttk.Button(frame1, text="Modificar usuario", command=modificar_usuario)
btn_modificar.pack(side="left", padx=5, pady=5)

btn_agregar = ttk.Button(frame1, text="Agregar usuario", command=agregar_usuario)
btn_agregar.pack(side="left", padx=5, pady=5)

btn_borrar = ttk.Button(frame1, text="Eliminar usuario", command=borrar_usuario)
btn_borrar.pack(side="left", padx=5, pady=5)

# Eliminado: Botón de Permisos (derechos)

# Inspección de miembros de Administradores
def ver_miembros_administradores():
    grp = nombre_grupo_administradores_windows()
    miembros = obtener_miembros_grupo_detalle(grp)
    top = tk.Toplevel(root)
    top.title(f"Miembros de {grp}")
    top.geometry("540x420")
    cols = ("Nombre", "Clase", "SID")
    tv = ttk.Treeview(top, columns=cols, show="headings")
    for c in cols:
        tv.heading(c, text=c)
        tv.column(c, width=160 if c != "SID" else 220)
    tv.pack(expand=1, fill="both")
    hay_externos = False
    for m in miembros:
        nombre = m.get('Name','')
        clase = m.get('ObjectClass','')
        sid = m.get('SID','')
        tv.insert('', 'end', values=(nombre, clase, sid))
        if clase.lower() == 'group' and not es_grupo_local(nombre):
            hay_externos = True
    if hay_externos:
        ttk.Label(top, text="Nota: Hay grupos no locales (posible membresía indirecta por dominio).", foreground="gray").pack(anchor='w', pady=4, padx=6)

btn_ver_admins = ttk.Button(frame1, text="Ver Administradores", command=ver_miembros_administradores)
btn_ver_admins.pack(side="left", padx=5, pady=5)

nota = ttk.Label(frame1, text="Ejecutá como ADMIN para poder agregar/eliminar/modificar usuarios.", foreground="gray")
nota.pack(side="bottom", pady=6)

if not es_admin_windows():
    # Deshabilitar acciones que requieren privilegios
    try:
        btn_modificar.state(["disabled"])  # ttk style
        btn_agregar.state(["disabled"])    
        btn_borrar.state(["disabled"])    
    except Exception:
        btn_modificar.configure(state="disabled")
        btn_agregar.configure(state="disabled")
        btn_borrar.configure(state="disabled")
    nota.configure(text="Abrí y ejecutá este programa como Administrador para realizar cambios.")

root.mainloop()
