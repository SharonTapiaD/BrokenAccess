"""
LABORATORIO OWASP A01:2025 - Broken Access Control
VERSION CORREGIDA. Ejecutar:  python3 app_segura.py   ->  http://127.0.0.1:5000
"""
import os
import sqlite3
import logging
from functools import wraps
from flask import (Flask, request, session, redirect, render_template_string,
                   jsonify, abort, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# CORRECCION: sesión firmada en el servidor (el cliente no puede alterarla)
app.secret_key = os.urandom(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

logging.basicConfig(filename="accesos.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
DB = "segura.db"


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    c = db()
    c.execute("""CREATE TABLE users(
        id INTEGER PRIMARY KEY, username TEXT, password TEXT,
        role TEXT, email TEXT, secreto TEXT)""")
    c.executemany(
        "INSERT INTO users(username,password,role,email,secreto) VALUES (?,?,?,?,?)",
        [
            ("admin", generate_password_hash("Admin#2025"), "admin", "admin@empresa.com", "Tarjeta corporativa: 4111-0000-0000-0001"),
            ("alice", generate_password_hash("alice123"), "user", "alice@empresa.com", "Salario: $45,000 MXN"),
            ("bob", generate_password_hash("bob123"), "user", "bob@empresa.com", "Salario: $38,000 MXN"),
        ],
    )
    c.commit()
    c.close()


# ---------- Control de acceso centralizado y reutilizable (deny by default) ----------
def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    # El rol SIEMPRE se lee de la base de datos, nunca del cliente
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if current_user() is None:
            logging.warning("ACCESO SIN SESION ip=%s ruta=%s", request.remote_addr, request.path)
            return redirect("/")
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*a, **kw):
        u = current_user()
        if u["role"] != "admin":
            logging.warning("DENEGADO user=%s ip=%s ruta=%s", u["username"], request.remote_addr, request.path)
            abort(403)
        return f(*a, **kw)
    return wrapper


# ---------------------------------------------------------------------------
# DISEÑO: estilos compartidos + plantillas
# ---------------------------------------------------------------------------
HEAD = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal de empleados</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #eef1f6;
    --surface: #ffffff;
    --ink: #1c2540;
    --muted: #5d6784;
    --line: #d9dfeb;
    --accent: #2b55d6;
    --accent-dark: #1f3fa8;
    --danger-bg: #fdecec;
    --danger: #a62424;
    --ok-bg: #e7f4ee;
    --ok: #1d6b47;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #11162a;
      --surface: #1a2140;
      --ink: #e9edf9;
      --muted: #9aa5c6;
      --line: #2c3560;
      --accent: #7d9bff;
      --accent-dark: #a5b9ff;
      --danger-bg: #3a1c24;
      --danger: #ff9b9b;
      --ok-bg: #153327;
      --ok: #7fd9ad;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    font-family: "Public Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
    background: var(--bg);
    color: var(--ink);
    line-height: 1.5;
  }
  .shell { max-width: 640px; margin: 0 auto; padding: 48px 20px; }
  .shell.wide { max-width: 860px; }
  .shell.center { min-height: 100vh; display: flex; flex-direction: column; justify-content: center; }
  .brand { font-weight: 700; font-size: 15px; color: var(--muted); margin-bottom: 14px; }
  .card {
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 32px;
    box-shadow: 0 8px 24px rgba(28, 37, 64, .08);
  }
  h2 { margin: 0 0 6px; font-size: 26px; font-weight: 700; letter-spacing: -.01em; }
  .sub { margin: 0 0 24px; color: var(--muted); }
  label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 6px; }
  input {
    width: 100%;
    padding: 11px 12px;
    margin-bottom: 18px;
    font: inherit;
    color: var(--ink);
    background: var(--bg);
    border: 1px solid var(--line);
    border-radius: 8px;
  }
  input:focus-visible, button:focus-visible, a:focus-visible, summary:focus-visible {
    outline: 3px solid var(--accent);
    outline-offset: 2px;
  }
  .btn, button {
    display: inline-block;
    width: 100%;
    padding: 12px 16px;
    font: inherit;
    font-weight: 600;
    text-align: center;
    text-decoration: none;
    color: #fff;
    background: var(--accent);
    border: 0;
    border-radius: 8px;
    cursor: pointer;
  }
  .btn:hover, button:hover { background: var(--accent-dark); }
  .btn.ghost { width: auto; color: var(--accent); background: transparent; border: 1px solid var(--line); }
  .btn.ghost:hover { background: var(--bg); }
  .alert { margin: 0 0 20px; padding: 10px 14px; font-size: 14px; color: var(--danger); background: var(--danger-bg); border-radius: 8px; }
  .menu { list-style: none; margin: 24px 0 0; padding: 0; display: grid; gap: 10px; }
  .menu a {
    display: block;
    padding: 14px 16px;
    color: var(--ink);
    font-weight: 600;
    text-decoration: none;
    background: var(--bg);
    border: 1px solid var(--line);
    border-radius: 8px;
  }
  .menu a:hover { border-color: var(--accent); color: var(--accent); }
  .menu a.exit { color: var(--muted); font-weight: 500; }
  dl { margin: 24px 0; display: grid; gap: 14px; }
  dt { font-size: 13px; color: var(--muted); }
  dd { margin: 2px 0 0; font-weight: 600; }
  details { padding: 12px 14px; background: var(--bg); border: 1px solid var(--line); border-radius: 8px; }
  summary { cursor: pointer; font-weight: 600; }
  details p { margin: 10px 0 0; }
  .table-wrap { overflow-x: auto; margin-top: 20px; border: 1px solid var(--line); border-radius: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 15px; }
  th, td { padding: 12px 14px; text-align: left; }
  th { font-size: 13px; color: var(--muted); background: var(--bg); }
  tr + tr td { border-top: 1px solid var(--line); }
  .pill { display: inline-block; padding: 2px 10px; font-size: 13px; font-weight: 600; color: var(--muted); background: var(--bg); border-radius: 999px; }
  .pill.admin, .pill.ok { color: var(--ok); background: var(--ok-bg); }
  .back { display: inline-block; margin-top: 8px; }
  .avatar { display: block; width: 112px; height: 112px; object-fit: cover; border-radius: 50%; border: 3px solid var(--line); margin: 0 0 16px; }
  .avatar.sm { width: 64px; height: 64px; border-width: 2px; }
</style>
</head>
<body>
"""

FOOT = """
</body>
</html>
"""

LOGIN = HEAD + """
<main class="shell center">
  <div class="brand">Portal de empleados <span class="pill ok">Versión segura</span></div>
  <div class="card">
    <h2>Iniciar sesión</h2>
    <p class="sub">Ingresa con tu usuario y clave de la empresa.</p>
    {% if error %}<p class="alert" role="alert">{{ error }}</p>{% endif %}
    <form method="post">
      <label for="username">Usuario</label>
      <input id="username" name="username" autocomplete="username" required autofocus>
      <label for="password">Clave</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Entrar</button>
    </form>
  </div>
</main>
""" + FOOT

DASH = HEAD + """
<main class="shell center">
  <div class="brand">Portal de empleados</div>
  <div class="card">
    <img class="avatar sm" src="/random" alt="Foto de perfil de {{ u['username'] }}">
    <h2>Bienvenido, {{ u['username'] }}</h2>
    <p class="sub">¿Qué quieres hacer hoy?</p>
    <ul class="menu">
      <li><a href="/perfil">Mi perfil</a></li>
      {% if u['role'] == 'admin' %}<li><a href="/admin">Panel de administración</a></li>{% endif %}
      <li><a class="exit" href="/logout">Cerrar sesión</a></li>
    </ul>
  </div>
</main>
""" + FOOT

PERFIL = HEAD + """
<main class="shell center">
  <div class="brand">Portal de empleados</div>
  <div class="card">
    <img class="avatar" src="/random" alt="Foto de perfil de {{ u['username'] }}">
    <h2>Perfil</h2>
    <p class="sub">Empleado n.º {{ u['id'] }}</p>
    <dl>
      <div><dt>Usuario</dt><dd>{{ u['username'] }}</dd></div>
      <div><dt>Correo</dt><dd>{{ u['email'] }}</dd></div>
    </dl>
    <details>
      <summary>Ver dato confidencial</summary>
      <p>{{ u['secreto'] }}</p>
    </details>
    <p class="back"><a class="btn ghost" href="/dashboard">Volver al inicio</a></p>
  </div>
</main>
""" + FOOT

ADMIN = HEAD + """
<main class="shell wide">
  <div class="brand">Portal de empleados</div>
  <div class="card">
    <h2>Panel de administración</h2>
    <p class="sub">{{ users|length }} usuarios registrados.</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>ID</th><th>Usuario</th><th>Correo</th><th>Rol</th></tr>
        </thead>
        <tbody>
          {% for u in users %}
          <tr>
            <td>{{ u['id'] }}</td>
            <td>{{ u['username'] }}</td>
            <td>{{ u['email'] }}</td>
            <td><span class="pill {{ 'admin' if u['role'] == 'admin' }}">{{ u['role'] }}</span></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <p class="back"><a class="btn ghost" href="/dashboard">Volver al inicio</a></p>
  </div>
</main>
""" + FOOT

# Página de error con el mismo estilo (se usa para 403 y 404)
ERROR = HEAD + """
<main class="shell center">
  <div class="brand">Portal de empleados</div>
  <div class="card">
    <h2>{{ titulo }}</h2>
    <p class="sub">{{ detalle }}</p>
    <a class="btn ghost" href="/dashboard">Volver al inicio</a>
  </div>
</main>
""" + FOOT


@app.errorhandler(403)
def prohibido(_e):
    return render_template_string(
        ERROR, titulo="Acceso denegado",
        detalle="No tienes permiso para ver esta página. El intento quedó registrado."), 403


@app.errorhandler(404)
def no_encontrado(_e):
    return render_template_string(
        ERROR, titulo="Página no encontrada",
        detalle="El recurso que buscas no existe."), 404


@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE username=?",
                         (request.form["username"],)).fetchone()
        if u and check_password_hash(u["password"], request.form["password"]):
            session.clear()
            session["uid"] = u["id"]  # solo el id, dentro de una sesión firmada
            return redirect("/dashboard")
        logging.warning("LOGIN FALLIDO usuario=%s ip=%s", request.form["username"], request.remote_addr)
        error = "Credenciales inválidas"
    return render_template_string(LOGIN, error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(DASH, u=current_user())


@app.route("/perfil")
@login_required
def perfil():
    me = current_user()
    # CORRECCION IDOR: si piden otro id y no son admin -> 403 y se registra
    pedido = request.args.get("id", type=int, default=me["id"])
    if pedido != me["id"] and me["role"] != "admin":
        logging.warning("IDOR BLOQUEADO user=%s pidio id=%s ip=%s", me["username"], pedido, request.remote_addr)
        abort(403)
    u = db().execute("SELECT * FROM users WHERE id=?", (pedido,)).fetchone()
    if not u:
        abort(404)
    return render_template_string(PERFIL, u=u)


@app.route("/admin")
@admin_required
def admin():
    users = db().execute("SELECT id,username,email,role FROM users").fetchall()
    return render_template_string(ADMIN, users=users)


@app.route("/api/usuarios")
@admin_required
def api_usuarios():
    # CORRECCION: requiere admin y ya no expone claves ni datos confidenciales
    rows = db().execute("SELECT id,username,email,role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/random")
@login_required
def random_img():
    return send_from_directory(app.root_path, "random.jpeg")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
