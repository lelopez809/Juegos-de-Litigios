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
import nltk
from nltk.tokenize import sent_tokenize  # Import explícito para sent_tokenize

# Configurar la ruta de los datos de NLTK en Render
nltk_data_dir = os.path.join(os.path.dirname(__file__), 'nltk_data')
os.makedirs(nltk_data_dir, exist_ok=True)  # Crear el directorio si no existe
nltk.data.path.append(nltk_data_dir)

# Descargar datos de NLTK si no están presentes
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    print("Descargando punkt...")
    nltk.download('punkt', download_dir=nltk_data_dir)
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    print("Descargando stopwords...")
    nltk.download('stopwords', download_dir=nltk_data_dir)

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

def evaluar_alegato(alegato, caso, rol="Jugador"):
    oraciones = sent_tokenize(alegato)
    num_oraciones = len(oraciones)
    dificultad = caso['dificultad']
    max_puntaje = 100  # Máximo puntaje en enteros

    # Inicializar puntaje
    puntaje = 0

    # Puntuación base por longitud del alegato (entero)
    puntaje_base = min(num_oraciones * 5, 20)  # Máximo 20 puntos por oraciones
    puntaje += puntaje_base

    # Puntuación según rol y dificultad (enteros)
    if rol == "Fiscal":
        bonus_rol = 15 if dificultad > 5 else 10
    elif rol == "Defensor":
        bonus_rol = 20 if dificultad > 7 else 15
    else:  # Jugador
        bonus_rol = 5
    puntaje += bonus_rol

    # Evaluación de pruebas y testigos (enteros)
    total_pruebas = len(caso['pruebas'])
    total_testigos = len(caso['testigos'])
    pruebas_mencionadas = 0
    testigos_mencionados = 0
    argumentos_logicos = 0

    alegato_lower = alegato.lower()
    for prueba, detalle in caso['pruebas'].items():
        if prueba.lower() in alegato_lower or detalle.lower() in alegato_lower:
            puntaje += 10  # 10 puntos por prueba mencionada
            pruebas_mencionadas += 1
            if any("porque" in oracion or "prueba" in oracion for oracion in sent_tokenize(alegato_lower) if prueba.lower() in oracion):
                puntaje += 5  # Bonus por contexto lógico
                argumentos_logicos += 1

    for testigo, detalle in caso['testigos'].items():
        if testigo.lower() in alegato_lower or detalle.lower() in alegato_lower:
            puntaje += 8  # 8 puntos por testigo mencionado
            testigos_mencionados += 1
            if any("según" in oracion or "declara" in oracion for oracion in sent_tokenize(alegato_lower) if testigo.lower() in oracion):
                puntaje += 4  # Bonus por contexto lógico
                argumentos_logicos += 1

    # Evaluación de ley y procedimiento (enteros)
    if caso['ley'].lower() in alegato_lower:
        puntaje += 15
        if any("según el artículo" in oracion or "la ley" in oracion for oracion in sent_tokenize(alegato_lower)):
            puntaje += 5
    if caso['procedimiento'].lower() in alegato_lower:
        puntaje += 10
        if any("el tribunal" in oracion or "solicito" in oracion for oracion in sent_tokenize(alegato_lower)):
            puntaje += 5

    # Penalizaciones (enteros)
    if pruebas_mencionadas < total_pruebas / 2:
        puntaje -= 10
    if testigos_mencionados < total_testigos / 2:
        puntaje -= 8
    if len(oraciones) < 3:
        puntaje -= 5

    # Normalizar puntaje a un máximo de 100
    puntaje = max(0, min(puntaje, max_puntaje))
    porcentaje = (puntaje / max_puntaje) * 100

    # Mensaje de evaluación
    dificultad_texto = "Fácil" if dificultad <= 3 else "Medio" if dificultad <= 7 else "Difícil"
    mensaje = (
        f"Puntuación: {puntaje}/{max_puntaje} ({int(porcentaje)}%)\n"
        f"Rol: {rol}\n"
        f"Dificultad: {dificultad}/10 ({dificultad_texto})\n"
        f"Pruebas mencionadas: {pruebas_mencionadas}/{total_pruebas}\n"
        f"Testigos mencionados: {testigos_mencionados}/{total_testigos}\n"
        f"Argumentos lógicos: {argumentos_logicos}"
    )
    return puntaje, mensaje

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
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (tabla,))
        if not cursor.fetchone():
            conn.close()
            flash(f"La tabla {tabla} no existe en la base de datos")
            return redirect(url_for('inicio'))
        cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad FROM {tabla} WHERE id = ?", (caso_id,))
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
            'procedimiento': caso_data[7],
            'dificultad': caso_data[8]
        }
        # Ajustar los roles válidos según la tabla
        valid_roles = ['Fiscal', 'Defensor'] if tabla == 'casos_penales' else ['Demandante', 'Demandado']
        rol = request.args.get('rol') if request.method == 'GET' and request.args.get('rol') in valid_roles else request.form.get('rol')
        if not rol or rol not in valid_roles:
            rol = "Jugador"
        resultado = None
        if request.method == 'POST':
            alegato = request.form.get('argumento')
            if not alegato:
                flash("Faltan datos en el formulario")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'error': 'Faltan datos en el formulario'}), 400
            else:
                try:
                    puntos, evaluacion = evaluar_alegato(alegato, caso, rol=rol)
                    nuevos_puntos = user_info['points'] + puntos
                    cursor.execute("UPDATE usuarios SET points = ? WHERE id = ?", (nuevos_puntos, session['user_id']))
                    cursor.execute("INSERT INTO alegatos (user_id, tabla, caso_id, rol, alegato, puntos) VALUES (?, ?, ?, ?, ?, ?)",
                                   (session['user_id'], tabla, caso_id, rol, alegato, puntos))
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    flash(f"Error al evaluar el alegato: {str(e)}")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'error': str(e)}), 500
                    return redirect(url_for('inicio'))
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
        return render_template('casos.html', caso=caso, user_info=user_info, resultado=resultado, tabla=tabla, endpoint=endpoint, rol=rol)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': str(e)}), 500
        return redirect(url_for('inicio'))
    except Exception as e:
        flash(f"Error inesperado: {str(e)}")
        return redirect(url_for('inicio'))

@app.route('/estado_juicio/<juicio_id>', methods=['GET'])
@login_required
def estado_juicio(juicio_id):
    try:
        # Conectar a la base de datos
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Contar cuántos alegatos hay para este juicio_id
        cursor.execute("SELECT rol, user_id FROM alegatos WHERE juicio_id = ?", (str(juicio_id),))
        alegatos = cursor.fetchall()

        # Determinar el estado del juicio
        num_alegatos = len(alegatos)
        if num_alegatos == 0:
            conn.close()
            return jsonify({'error': 'Juicio no encontrado'}), 404
        elif num_alegatos == 1:
            estado = "Esperando"
            oponente_unido = False
            rol_oponente = None
        else:  # num_alegatos == 2
            estado = "En Progreso"
            oponente_unido = True
            # Determinar el rol del oponente
            user_id_actual = session['user_id']
            for rol, user_id in alegatos:
                if user_id != user_id_actual:
                    rol_oponente = rol
                    break
            else:
                rol_oponente = None  # Esto no debería pasar si hay 2 alegatos

        conn.close()

        # Devolver el resultado en formato JSON
        return jsonify({
            'estado': estado,
            'oponente_unido': oponente_unido,
            'rol_oponente': rol_oponente
        })

    except sqlite3.Error as e:
        return jsonify({'error': f'Error en la base de datos: {str(e)}'}), 500

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
