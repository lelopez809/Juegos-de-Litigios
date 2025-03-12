from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import random
import string
import os
import json
from werkzeug.utils import secure_filename

print("Iniciando la aplicación...")

app = Flask(__name__, template_folder='templates')
app.secret_key = os.getenv("SECRET_KEY", "Diosesamor")

print(f"SECRET_KEY: {app.secret_key}")

# Configuración de la base de datos y carpeta de subidas
DB_PATH = "/data/casos.db"
UPLOAD_FOLDER = os.path.join(os.getcwd(), "static/uploads")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Credenciales de correo desde variables de entorno
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
print(f"EMAIL_USER: {EMAIL_USER}")
print(f"EMAIL_PASSWORD: {EMAIL_PASSWORD}")

# Crear la carpeta de subidas si no existe
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    print(f"Carpeta de subidas creada: {UPLOAD_FOLDER}")

# Definir el usuario autorizado
AUTHORIZED_USERNAME = "lelopez"

def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, inicia sesión primero.")
            return redirect(url_for('login'))
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM usuarios WHERE id = ?", (session['user_id'],))
            current_username = cursor.fetchone()[0]
            conn.close()
            if current_username != AUTHORIZED_USERNAME:
                flash("No tienes permiso para acceder a esta página.")
                return redirect(url_for('inicio'))
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
            return redirect(url_for('inicio'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def init_db():
    try:
        print(f"Intentando acceder a {DB_PATH}")
        data_dir = os.path.dirname(DB_PATH)
        if not os.path.exists(data_dir):
            print(f"El directorio {data_dir} no existe")
            os.makedirs(data_dir, exist_ok=True)
            print(f"Directorio {data_dir} creado")
        else:
            print(f"El directorio {data_dir} ya existe")

        if not os.access(data_dir, os.W_OK):
            print(f"No hay permisos de escritura en {data_dir}")
            raise PermissionError(f"No se pueden escribir en {data_dir}")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                real_name TEXT NOT NULL,
                points INTEGER DEFAULT 0,
                photo_path TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alegatos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                tabla TEXT,
                caso_id INTEGER,
                rol TEXT,
                alegato TEXT,
                puntos INTEGER,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES usuarios(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS juicios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tabla TEXT,
                caso_id INTEGER,
                fiscal_id INTEGER,
                defensor_id INTEGER,
                fiscal_alegato TEXT,
                defensor_alegato TEXT,
                estado TEXT DEFAULT 'pendiente',
                fiscal_puntos INTEGER,
                defensor_puntos INTEGER,
                ganador_id INTEGER,
                resultado TEXT,
                FOREIGN KEY(fiscal_id) REFERENCES usuarios(id),
                FOREIGN KEY(defensor_id) REFERENCES usuarios(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS casos_penales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                hechos TEXT,
                pruebas TEXT,
                testigos TEXT,
                defensa TEXT,
                ley TEXT,
                procedimiento TEXT,
                dificultad INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS casos_civil (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                hechos TEXT,
                pruebas TEXT,
                testigos TEXT,
                defensa TEXT,
                ley TEXT,
                procedimiento TEXT,
                dificultad INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS casos_tierras (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                hechos TEXT,
                pruebas TEXT,
                testigos TEXT,
                defensa TEXT,
                ley TEXT,
                procedimiento TEXT,
                dificultad INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS casos_administrativo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                hechos TEXT,
                pruebas TEXT,
                testigos TEXT,
                defensa TEXT,
                ley TEXT,
                procedimiento TEXT,
                dificultad INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS casos_familia (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                hechos TEXT,
                pruebas TEXT,
                testigos TEXT,
                defensa TEXT,
                ley TEXT,
                procedimiento TEXT,
                dificultad INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS casos_ninos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                hechos TEXT,
                pruebas TEXT,
                testigos TEXT,
                defensa TEXT,
                ley TEXT,
                procedimiento TEXT,
                dificultad INTEGER
            )
        ''')

        conn.commit()
        print("Base de datos inicializada correctamente.")
    except (sqlite3.Error, PermissionError) as e:
        print(f"Error al inicializar la base de datos: {e}")
        raise
    finally:
        if 'conn' in locals():
            conn.close()

init_db()

print("Configuración inicial completada.")

@app.route('/test')
def test():
    return "¡La aplicación está funcionando!"

print("Rutas cargadas correctamente:")
for rule in app.url_map.iter_rules():
    print(f" - {rule}")

print("Flask está listo para recibir solicitudes.")

def generate_recovery_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def get_user_info(user_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT real_name, points, photo_path FROM usuarios WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if user:
            points = user[1] if user[1] else 0
            if points < 50:
                rank = "Abogado Novato"
            elif points < 150:
                rank = "Abogado Junior"
            elif points < 300:
                rank = "Abogado Senior"
            elif points < 500:
                rank = "Fiscal Experto"
            else:
                rank = "Maestro del Derecho"
            return {"real_name": user[0], "points": points, "photo_path": user[2], "rank": rank}
        print(f"No se encontró usuario con id {user_id}")
        return None
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        return None

def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, inicia sesión primero.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def evaluar_alegato(alegato, caso):
    puntos = 0
    retroalimentacion = []
    alegato = alegato.lower().strip()

    ley = caso['ley'].lower()
    if ley in alegato:
        puntos += 25
        retroalimentacion.append("+25 puntos: Mencionaste la ley aplicable correctamente.")
    else:
        retroalimentacion.append("0 puntos: No mencionaste la ley aplicable (" + caso['ley'] + "). Es fundamental citar la normativa correspondiente.")

    pruebas = caso['pruebas']
    pruebas_mencionadas = sum(1 for prueba in pruebas.keys() if prueba.lower() in alegato)
    puntos_pruebas = min(pruebas_mencionadas * 5, 20)
    puntos += puntos_pruebas
    if pruebas_mencionadas > 0:
        retroalimentacion.append(f"+{puntos_pruebas} puntos: Mencionaste {pruebas_mencionadas} de {len(pruebas)} pruebas disponibles.")
    else:
        retroalimentacion.append("0 puntos: No mencionaste ninguna prueba. Debes usar las pruebas disponibles para respaldar tu alegato.")

    testigos = caso['testigos']
    testigos_mencionados = sum(1 for testigo in testigos.keys() if testigo.lower() in alegato)
    puntos_testigos = min(testigos_mencionados * 5, 20)
    puntos += puntos_testigos
    if testigos_mencionados > 0:
        retroalimentacion.append(f"+{puntos_testigos} puntos: Mencionaste {testigos_mencionados} de {len(testigos)} testigos disponibles.")
    else:
        retroalimentacion.append("0 puntos: No mencionaste ningún testigo. Los testigos son clave para fortalecer tu argumento.")

    palabras_solicitud = ["solicito", "pido", "requiero", "sentencia", "fallo"]
    if any(palabra in alegato for palabra in palabras_solicitud):
        puntos += 15
        retroalimentacion.append("+15 puntos: Incluiste una solicitud clara en tu alegato.")
    else:
        retroalimentacion.append("0 puntos: No hiciste una solicitud clara (ej. 'solicito', 'pido'). Debes especificar qué buscas.")

    roles_validos = ["fiscal", "defensor", "abogado", "demandante", "demandado", "recurrente", "administración", "ministerio", "público"]
    if any(rol in alegato for rol in roles_validos):
        puntos += 20
        retroalimentacion.append("+20 puntos: Mencionaste tu rol y el alegato parece coherente con él.")
    else:
        retroalimentacion.append("0 puntos: No mencionaste tu rol. Es crucial identificar tu posición.")

    if len(alegato.split()) < 20:
        puntos -= 10
        retroalimentacion.append("-10 puntos: Alegato demasiado corto (< 20 palabras). Debes desarrollar más tus argumentos.")
    else:
        retroalimentacion.append("+0 puntos: Longitud adecuada (>= 20 palabras).")

    puntos = max(0, min(puntos, 100))
    resultado = f"Puntuación total: {puntos}/100\n\nDetalles de la evaluación:\n" + "\n".join(retroalimentacion)
    return puntos, resultado

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM usuarios WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['real_name'] = user[4]
                return redirect(url_for('inicio'))
            else:
                flash("Usuario o contraseña incorrectos")
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('real_name', None)
    flash("Has cerrado sesión")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        real_name = request.form.get('real_name')
        if not all([username, password, email, real_name]):
            flash("Faltan datos")
            return render_template('register.html'), 400
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM usuarios WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                conn.close()
                flash("El usuario o correo ya están registrados")
                return render_template('register.html'), 400
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO usuarios (username, password, email, real_name, points) VALUES (?, ?, ?, ?, 0)", 
                           (username, hashed_password, email, real_name))
            conn.commit()
            conn.close()
            flash("Registro exitoso, ahora puedes iniciar sesión")
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
            return render_template('register.html'), 500
    return render_template('register.html')

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    reset = False
    if request.method == 'POST':
        if 'email' in request.form:
            email = request.form['email']
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
                user = cursor.fetchone()
                conn.close()
                if user:
                    code = generate_recovery_code()
                    session['recovery_code'] = code
                    session['recovery_email'] = email
                    msg = MIMEText(f'Tu código de recuperación es: {code}')
                    msg['Subject'] = 'Recuperación de contraseña'
                    msg['From'] = EMAIL_USER
                    msg['To'] = email
                    try:
                        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
                        server.login(EMAIL_USER, EMAIL_PASSWORD)
                        server.sendmail(EMAIL_USER, email, msg.as_string())
                        server.quit()
                        flash("Código de recuperación enviado a tu correo.")
                        reset = True
                    except Exception as e:
                        flash(f"Error enviando el correo: {e}")
                else:
                    flash("Correo no encontrado.")
            except sqlite3.Error as e:
                flash(f"Error en la base de datos: {e}")
        elif 'code' in request.form and 'new_password' in request.form:
            code = request.form['code']
            new_password = request.form['new_password']
            if code == session.get('recovery_code'):
                email = session.get('recovery_email')
                hashed_password = generate_password_hash(new_password)
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("UPDATE usuarios SET password = ? WHERE email = ?", (hashed_password, email))
                    conn.commit()
                    conn.close()
                    flash("Contraseña cambiada correctamente.")
                    return redirect(url_for('login'))
                except sqlite3.Error as e:
                    flash(f"Error en la base de datos: {e}")
            else:
                flash("Código incorrecto.")
                reset = True
    return render_template('recover.html', reset=reset)

@app.route('/inicio')
@login_required
def inicio():
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('logout'))
    return render_template('inicio.html', user_info=user_info)

@app.route('/penal')
@login_required
def penal():
    return lista_casos('casos_penales', 'penal.html')

@app.route('/civil')
@login_required
def civil():
    return lista_casos('casos_civil', 'civil.html')

@app.route('/tierras')
@login_required
def tierras():
    return lista_casos('casos_tierras', 'tierras.html')

@app.route('/administrativo')
@login_required
def administrativo():
    return lista_casos('casos_administrativo', 'administrativo.html')

@app.route('/familia')
@login_required
def familia():
    return lista_casos('casos_familia', 'familia.html')

@app.route('/ninos')
@login_required
def ninos():
    return lista_casos('casos_ninos', 'ninos.html')

def lista_casos(tabla, template_name):
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        print(f"Intentando conectar a {DB_PATH} para {tabla}")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad FROM {tabla}")
        casos_data = cursor.fetchall()
        print(f"Tabla {tabla}: {len(casos_data)} casos encontrados: {casos_data}")
        casos = [dict(id=row[0], titulo=row[1], hechos=row[2], pruebas=json.loads(row[3]) if row[3] else {},
                      testigos=json.loads(row[4]) if row[4] else {}, defensa=row[5], ley=row[6], procedimiento=row[7],
                      dificultad=row[8] if row[8] is not None else 0)
                 for row in casos_data]
        conn.close()
        if not casos_data:
            flash(f"No se encontraron casos en {tabla}")
        print(f"Enviando {len(casos)} casos a {template_name}: {casos}")
        return render_template(template_name, casos=casos, user_info=user_info)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        return redirect(url_for('inicio'))

@app.route('/caso/<tabla>/<int:caso_id>', methods=['GET', 'POST'])
@login_required
def caso(tabla, caso_id):
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        print(f"Intentando conectar a {DB_PATH} para caso {caso_id} en {tabla}")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento FROM {tabla} WHERE id = ?", (caso_id,))
        caso_data = cursor.fetchone()
        print(f"Buscando caso {caso_id} en {tabla}: {'Encontrado' if caso_data else 'No encontrado'}, datos: {caso_data}")
        if not caso_data:
            conn.close()
            flash("Caso no encontrado")
            return redirect(url_for('inicio'))
        caso = {
            'id': caso_data[0],
            'titulo': caso_data[1],
            'hechos': caso_data[2],
            'pruebas': json.loads(caso_data[3]) if caso_data[3] else {},
            'testigos': json.loads(caso_data[4]) if caso_data[4] else {},
            'defensa': caso_data[5],
            'ley': caso_data[6],
            'procedimiento': caso_data[7]
        }
        resultado = None
        if request.method == 'POST':
            rol = request.form.get('rol')
            alegato = request.form.get('argumento')
            if not rol or not alegato:
                flash("Faltan datos en el formulario")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'error': 'Faltan datos en el formulario'}), 400
            else:
                puntos, evaluacion = evaluar_alegato(alegato, caso)
                nuevos_puntos = user_info['points'] + puntos
                cursor.execute("UPDATE usuarios SET points = ? WHERE id = ?", (nuevos_puntos, session['user_id']))
                cursor.execute("INSERT INTO alegatos (user_id, tabla, caso_id, rol, alegato, puntos) VALUES (?, ?, ?, ?, ?, ?)",
                               (session['user_id'], tabla, caso_id, rol, alegato, puntos))
                conn.commit()
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'puntos': puntos, 'evaluacion': evaluacion})
                resultado = evaluacion
        conn.close()
        endpoint_map = {
            'casos_penales': 'penal',
            'casos_civil': 'civil',
            'casos_tierras': 'tierras',
            'casos_administrativo': 'administrativo',
            'casos_familia': 'familia',
            'casos_ninos': 'ninos'
        }
        endpoint = endpoint_map.get(tabla, 'inicio')
        print(f"Enviando caso a casos.html: {caso}, endpoint: {endpoint}")
        return render_template('casos.html', caso=caso, user_info=user_info, resultado=resultado, tabla=tabla, endpoint=endpoint)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': str(e)}), 500
        return redirect(url_for('inicio'))

@app.route('/caso_multi/<tabla>/<int:caso_id>', methods=['GET', 'POST'])
@login_required
def caso_multi(tabla, caso_id):
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento FROM {tabla} WHERE id = ?", (caso_id,))
        caso_data = cursor.fetchone()
        if not caso_data:
            conn.close()
            flash("Caso no encontrado")
            return redirect(url_for('inicio'))
        caso = {
            'id': caso_data[0],
            'titulo': caso_data[1],
            'hechos': caso_data[2],
            'pruebas': json.loads(caso_data[3]) if caso_data[3] else {},
            'testigos': json.loads(caso_data[4]) if caso_data[4] else {},
            'defensa': caso_data[5],
            'ley': caso_data[6],
            'procedimiento': caso_data[7]
        }

        # Buscar o crear un juicio para este caso
        cursor.execute("SELECT id, fiscal_id, defensor_id, fiscal_alegato, defensor_alegato, estado, resultado FROM juicios WHERE tabla = ? AND caso_id = ? AND estado = 'pendiente'", (tabla, caso_id))
        juicio = cursor.fetchone()
        juicio_id = None
        fiscal_id = None
        defensor_id = None
        resultado = None

        if juicio:
            juicio_id, fiscal_id, defensor_id, fiscal_alegato, defensor_alegato, estado, resultado = juicio
        else:
            cursor.execute("INSERT INTO juicios (tabla, caso_id) VALUES (?, ?)", (tabla, caso_id))
            conn.commit()
            cursor.execute("SELECT id FROM juicios WHERE tabla = ? AND caso_id = ? AND estado = 'pendiente'", (tabla, caso_id))
            juicio_id = cursor.fetchone()[0]

        rol1 = "Fiscal"
        rol2 = "Defensor"

        if request.method == 'POST':
            rol = request.form.get('rol')
            alegato = request.form.get('argumento')
            if not rol or not alegato:
                flash("Faltan datos en el formulario")
            elif rol not in [rol1, rol2]:
                flash("Rol inválido")
            else:
                if rol == rol1 and not fiscal_id:
                    cursor.execute("UPDATE juicios SET fiscal_id = ?, fiscal_alegato = ? WHERE id = ?", (session['user_id'], alegato, juicio_id))
                    fiscal_id = session['user_id']
                elif rol == rol2 and not defensor_id:
                    cursor.execute("UPDATE juicios SET defensor_id = ?, defensor_alegato = ? WHERE id = ?", (session['user_id'], alegato, juicio_id))
                    defensor_id = session['user_id']
                else:
                    flash("El rol seleccionado ya está ocupado")
                    conn.close()
                    return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))

                conn.commit()

                # Si ambos roles están ocupados, evaluar los alegatos
                if fiscal_id and defensor_id:
                    fiscal_puntos, fiscal_evaluacion = evaluar_alegato(fiscal_alegato, caso) if fiscal_alegato else (0, "No presentado")
                    defensor_puntos, defensor_evaluacion = evaluar_alegato(defensor_alegato, caso) if defensor_alegato else (0, "No presentado")
                    ganador_id = fiscal_id if fiscal_puntos > defensor_puntos else defensor_id if defensor_puntos > fiscal_puntos else None
                    resultado = f"Fiscal: {fiscal_puntos}/100\n{evaluacion}\n\nDefensor: {defensor_puntos}/100\n{defensor_evaluacion}\n\nGanador: {'Fiscal' if ganador_id == fiscal_id else 'Defensor' if ganador_id == defensor_id else 'Empate'}"
                    cursor.execute("UPDATE juicios SET estado = 'completado', fiscal_puntos = ?, defensor_puntos = ?, ganador_id = ?, resultado = ? WHERE id = ?",
                                   (fiscal_puntos, defensor_puntos, ganador_id, resultado, juicio_id))
                    cursor.execute("UPDATE usuarios SET points = points + ? WHERE id = ?", (fiscal_puntos, fiscal_id))
                    cursor.execute("UPDATE usuarios SET points = points + ? WHERE id = ?", (defensor_puntos, defensor_id))
                    conn.commit()

        conn.close()
        endpoint_map = {
            'casos_penales': 'penal',
            'casos_civil': 'civil',
            'casos_tierras': 'tierras',
            'casos_administrativo': 'administrativo',
            'casos_familia': 'familia',
            'casos_ninos': 'ninos'
        }
        endpoint = endpoint_map.get(tabla, 'inicio')
        return render_template('casos_multi.html', caso=caso, user_info=user_info, juicio_id=juicio_id, fiscal_id=fiscal_id, defensor_id=defensor_id, rol1=rol1, rol2=rol2, resultado=resultado, endpoint=endpoint, tabla=tabla)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        return redirect(url_for('inicio'))

@app.route('/perfil')
@login_required
def perfil():
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*), AVG(puntos) FROM alegatos WHERE user_id = ?", (session['user_id'],))
        total_casos, promedio_puntos = cursor.fetchone()
        total_casos = total_casos or 0
        promedio_puntos = round(promedio_puntos or 0, 2)
        cursor.execute("""
            SELECT a.tabla, a.caso_id, c.titulo, a.rol, a.puntos, a.fecha
            FROM alegatos a
            LEFT JOIN (
                SELECT id, titulo, 'casos_penales' AS tabla FROM casos_penales UNION
                SELECT id, titulo, 'casos_civil' FROM casos_civil UNION
                SELECT id, titulo, 'casos_tierras' FROM casos_tierras UNION
                SELECT id, titulo, 'casos_administrativo' FROM casos_administrativo UNION
                SELECT id, titulo, 'casos_familia' FROM casos_familia UNION
                SELECT id, titulo, 'casos_ninos' FROM casos_ninos
            ) c ON a.tabla = c.tabla AND a.caso_id = c.id
            WHERE a.user_id = ?
            ORDER BY a.fecha DESC
        """, (session['user_id'],))
        casos_resueltos = cursor.fetchall()
        casos_resueltos = [dict(tabla=row[0], caso_id=row[1], titulo=row[2], rol=row[3], puntos=row[4], fecha=row[5]) for row in casos_resueltos]
        cursor.execute("SELECT id, real_name, points FROM usuarios ORDER BY points DESC LIMIT 5")
        ranking = cursor.fetchall()
        ranking = [dict(id=row[0], real_name=row[1], points=row[2]) for row in ranking]
        conn.close()
        return render_template('perfil.html', user_info=user_info, total_casos=total_casos, promedio_puntos=promedio_puntos, casos_resueltos=casos_resueltos, ranking=ranking)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        return redirect(url_for('inicio'))

@app.route('/edit_caso/<tabla>/<int:caso_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_caso(tabla, caso_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Obtener los datos del caso existente
        cursor.execute(f"SELECT titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad FROM {tabla} WHERE id = ?", (caso_id,))
        caso_data = cursor.fetchone()
        if not caso_data:
            conn.close()
            flash("Caso no encontrado")
            return redirect(url_for('inicio'))
        
        caso = {
            'titulo': caso_data[0],
            'hechos': caso_data[1],
            'pruebas': caso_data[2] if caso_data[2] else '{}',
            'testigos': caso_data[3] if caso_data[3] else '{}',
            'defensa': caso_data[4],
            'ley': caso_data[5],
            'procedimiento': caso_data[6],
            'dificultad': caso_data[7] if caso_data[7] is not None else 0
        }

        if request.method == 'POST':
            # Actualizar los datos del caso
            titulo = request.form.get('titulo')
            hechos = request.form.get('hechos')
            pruebas = request.form.get('pruebas', '{}')
            testigos = request.form.get('testigos', '{}')
            defensa = request.form.get('defensa')
            ley = request.form.get('ley')
            procedimiento = request.form.get('procedimiento')
            dificultad = int(request.form.get('dificultad', 0))

            if not tabla or not titulo:
                flash("Faltan datos obligatorios (tabla y título)")
                return render_template('edit_caso.html', caso=caso, tabla=tabla)

            cursor.execute(f"""
                UPDATE {tabla} SET titulo = ?, hechos = ?, pruebas = ?, testigos = ?, defensa = ?, ley = ?, procedimiento = ?, dificultad = ?
                WHERE id = ?
            """, (titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad, caso_id))
            conn.commit()
            conn.close()
            flash("Caso actualizado correctamente")
            return redirect(url_for('inicio'))

        conn.close()
        return render_template('edit_caso.html', caso=caso, tabla=tabla)

    except sqlite3.Error as e:
        flash(f"Error al editar el caso: {e}")
        return render_template('edit_caso.html', caso=caso, tabla=tabla) if 'caso' in locals() else redirect(url_for('inicio'))

@app.route('/add_caso', methods=['GET', 'POST'])
@login_required
@admin_required
def add_caso():
    if request.method == 'POST':
        tabla = request.form.get('tabla')
        titulo = request.form.get('titulo')
        hechos = request.form.get('hechos')
        pruebas = request.form.get('pruebas', '{}')
        testigos = request.form.get('testigos', '{}')
        defensa = request.form.get('defensa')
        ley = request.form.get('ley')
        procedimiento = request.form.get('procedimiento')
        dificultad = int(request.form.get('dificultad', 0))

        if not tabla or not titulo:
            flash("Faltan datos obligatorios (tabla y título)")
            return render_template('add_caso.html')

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(f"""
                INSERT INTO {tabla} (titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad))
            conn.commit()
            conn.close()
            flash("Caso agregado correctamente")
            return redirect(url_for('inicio'))
        except sqlite3.Error as e:
            flash(f"Error al agregar el caso: {e}")
            return render_template('add_caso.html')

    return render_template('add_caso.html')

if __name__ == "__main__":
    if os.getenv("FLASK_ENV") != "production":
        port = int(os.getenv("PORT", 5000))
        app.run(host="0.0.0.0", port=port)
    else:
        import time
        print("Manteniendo el contenedor activo...")
