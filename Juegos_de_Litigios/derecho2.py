import os
import json
import sqlite3
import random
import string
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import nltk
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords

# Configuración de NLTK
nltk_data_dir = os.path.join(os.path.dirname(__file__), 'nltk_data')
os.makedirs(nltk_data_dir, exist_ok=True)
nltk.data.path.append(nltk_data_dir)

# Descargar datos de NLTK si no están presentes
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', download_dir=nltk_data_dir)
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', download_dir=nltk_data_dir)

# Inicialización de la app
app = Flask(__name__, template_folder='templates')

# Configuración de la SECRET_KEY
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set in environment. Please define it in Render's Environment Variables.")
app.config['SECRET_KEY'] = SECRET_KEY

# Configuración de la base de datos y carpeta de subidas
DB_PATH = "/data/casos.db"
UPLOAD_FOLDER = os.path.join(os.getcwd(), "static/uploads")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Credenciales de correo (aunque no se usan, las dejamos por si las necesitas en el futuro)
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Definir el usuario autorizado
AUTHORIZED_USERNAME = "lelopez"

# Decoradores de autenticación
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, inicia sesión primero.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, inicia sesión primero.")
            return redirect(url_for('login'))
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username FROM usuarios WHERE id = ?", (session['user_id'],))
                current_username = cursor.fetchone()[0]
                if current_username != AUTHORIZED_USERNAME:
                    flash("No tienes permiso para acceder a esta página.")
                    return redirect(url_for('inicio'))
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
            return redirect(url_for('inicio'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Inicialización de la base de datos
def init_db():
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            tables = {
                'usuarios': '''
                    CREATE TABLE IF NOT EXISTS usuarios (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        real_name TEXT NOT NULL,
                        points INTEGER DEFAULT 0,
                        photo_path TEXT
                    )
                ''',
                'alegatos': '''
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
                ''',
                'juicios': '''
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
                ''',
                'casos_penales': '''
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
                ''',
                'casos_civil': '''
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
                ''',
                'casos_tierras': '''
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
                ''',
                'casos_administrativo': '''
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
                ''',
                'casos_familia': '''
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
                ''',
                'casos_ninos': '''
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
                '''
            }
            for table_name, query in tables.items():
                cursor.execute(query)
            conn.commit()
    except Exception as e:
        print(f"Error al inicializar la base de datos: {e}")
        raise

# Funciones auxiliares
def get_user_info(user_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, real_name, points, photo_path FROM usuarios WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if user:
                rank = "Novato" if user[4] < 100 else "Intermedio" if user[4] < 500 else "Experto"
                return {'id': user[0], 'username': user[1], 'email': user[2], 'real_name': user[3], 'points': user[4], 'photo_path': user[5], 'rank': rank}
        return None
    except sqlite3.Error as e:
        print(f"Error al obtener información del usuario: {e}")
        return None
def evaluar_alegato(alegato, caso, rol="Jugador"):
    # Limitar el tamaño del alegato
    if len(alegato) > 5000:
        alegato = alegato[:5000]

    # Validar la estructura del caso
    if not isinstance(caso.get('pruebas'), dict) or not isinstance(caso.get('testigos'), dict):
        return 0, "Error: Estructura de caso inválida."

    # Procesar el alegato con NLTK desde el inicio
    try:
        stop_words = set(stopwords.words('spanish'))
        alegato_lower = alegato.lower()
        tokens = word_tokenize(alegato_lower)
        tokens_sin_stopwords = [token for token in tokens if token not in stop_words]
        alegato_limpio = ' '.join(tokens_sin_stopwords)
        oraciones = sent_tokenize(alegato_limpio)
    except Exception as e:
        return 0, f"Error al procesar el alegato: {str(e)}"

    # Chequeo de contenido mínimo usando NLTK
    if len(tokens_sin_stopwords) < 5:  # Mínimo 5 palabras significativas (sin stopwords)
        return 0, (
            "Puntuación: 0/100 (0%)\n"
            f"Rol: {rol}\n"
            f"Dificultad: {caso['dificultad']}/10 ({'Fácil' if caso['dificultad'] <= 3 else 'Medio' if caso['dificultad'] <= 7 else 'Difícil'})\n"
            "\nPuntos que fallaste:\n"
            "Tu alegato es demasiado corto o no tiene contenido relevante.\n"
            "\nCómo mejorar:\n"
            "Escribe un alegato más detallado (mínimo 5 palabras significativas).\n"
            "Menciona pruebas, testigos, la ley y el procedimiento del caso.\n"
            "Usa argumentos lógicos con palabras como 'porque' o 'según'.\n"
            "\nConsejos de ética en audiencias:\n"
            "Dirígete al magistrado o magistrada con respeto, usando 'Honorable Magistrado/a'.\n"
            "Mantén la compostura en el salón, sin interrumpir ni alzar la voz.\n"
            "Presenta tus argumentos con honestidad, sin alterar los hechos pa’ beneficiar a tu cliente.\n"
            f"{'Defiende a tu cliente con ética, evitando acusaciones falsas contra otros.' if rol in ['Defensor', 'Demandado'] else 'Busca justicia con integridad, sin exagerar cargos pa’ presionar.'}"
        )

    num_oraciones = len(oraciones)
    dificultad = caso['dificultad']
    max_puntaje = 100

    puntaje = 0
    # Reducir el puntaje base
    puntaje_base = min(num_oraciones * 3, 15)  # 3 puntos por oración, máximo 15
    puntaje += puntaje_base

    # Reducir el bonus por rol
    if rol in ["Fiscal", "Demandante"]:
        bonus_rol = 10 if dificultad > 5 else 5
    elif rol in ["Defensor", "Demandado"]:
        bonus_rol = 12 if dificultad > 7 else 8
    else:
        bonus_rol = 3
    puntaje += bonus_rol

    total_pruebas = len(caso['pruebas'])
    total_testigos = len(caso['testigos'])
    pruebas_mencionadas = 0
    testigos_mencionados = 0
    argumentos_logicos = 0

    # Comparar pruebas y testigos usando NLTK, pero de forma más precisa
    for prueba, detalle in caso['pruebas'].items():
        prueba_lower = prueba.lower()
        detalle_lower = str(detalle).lower()
        prueba_tokens = word_tokenize(prueba_lower)
        detalle_tokens = word_tokenize(detalle_lower)
        # Contar solo si hay una coincidencia significativa (mínimo 2 tokens coincidentes)
        coincidencias_prueba = sum(1 for token in tokens_sin_stopwords if token in prueba_tokens)
        coincidencias_detalle = sum(1 for token in tokens_sin_stopwords if token in detalle_tokens)
        if coincidencias_prueba >= 2 or coincidencias_detalle >= 2 or prueba_lower in alegato_limpio or detalle_lower in alegato_limpio:
            puntaje += 10
            pruebas_mencionadas += 1
            if any("porque" in oracion or "prueba" in oracion for oracion in sent_tokenize(alegato_lower) if prueba_lower in oracion):
                puntaje += 5
                argumentos_logicos += 1

    for testigo, detalle in caso['testigos'].items():
        testigo_lower = testigo.lower()
        detalle_lower = str(detalle).lower()
        testigo_tokens = word_tokenize(testigo_lower)
        detalle_tokens = word_tokenize(detalle_lower)
        # Contar solo si hay una coincidencia significativa (mínimo 2 tokens coincidentes)
        coincidencias_testigo = sum(1 for token in tokens_sin_stopwords if token in testigo_tokens)
        coincidencias_detalle = sum(1 for token in tokens_sin_stopwords if token in detalle_tokens)
        if coincidencias_testigo >= 2 or coincidencias_detalle >= 2 or testigo_lower in alegato_limpio or detalle_lower in alegato_limpio:
            puntaje += 8
            testigos_mencionados += 1
            if any("según" in oracion or "declara" in oracion for oracion in sent_tokenize(alegato_lower) if testigo_lower in oracion):
                puntaje += 4
                argumentos_logicos += 1

    ley_lower = caso['ley'].lower()
    ley_mencionada = ley_lower in alegato_lower and len(ley_lower.split()) > 1
    if ley_mencionada:
        puntaje += 15
        if any("según el artículo" in oracion or "la ley" in oracion for oracion in sent_tokenize(alegato_lower)):
            puntaje += 5
    
    proc_lower = caso['procedimiento'].lower()
    proc_mencionado = proc_lower in alegato_lower and len(proc_lower.split()) > 1
    if proc_mencionado:
        puntaje += 10
        if any("el tribunal" in oracion or "solicito" in oracion for oracion in sent_tokenize(alegato_lower)):
            puntaje += 5

    penalizacion_pruebas = total_pruebas > 0 and pruebas_mencionadas < total_pruebas / 2
    if penalizacion_pruebas:
        puntaje -= 5
    penalizacion_testigos = total_testigos > 0 and testigos_mencionados < total_testigos / 2
    if penalizacion_testigos:
        puntaje -= 4
    penalizacion_oraciones = len(oraciones) < 3
    if penalizacion_oraciones:
        puntaje -= 5  # Aumentar la penalización

    frecuencias = {}
    for token in tokens_sin_stopwords:  # Usar tokens sin stopwords para la variedad
        frecuencias[token] = frecuencias.get(token, 0) + 1
    max_repeticion = max(frecuencias.values()) if frecuencias else 0
    num_palabras_unicas = len(frecuencias)

    puntaje_variedad = 0
    if max_repeticion > 5:
        puntaje_variedad = -5
    elif num_palabras_unicas > 10:
        puntaje_variedad = 5
    puntaje += puntaje_variedad

    puntaje = max(0, min(puntaje, max_puntaje))
    porcentaje = (puntaje / max_puntaje) * 100

    dificultad_texto = "Fácil" if dificultad <= 3 else "Medio" if dificultad <= 7 else "Difícil"

    fallos = []
    mejoras = []
    
    if pruebas_mencionadas < total_pruebas:
        fallos.append(f"No mencionaste {total_pruebas - pruebas_mencionadas} pruebas.")
        mejoras.append("Incluye más pruebas específicas del caso.")
    if penalizacion_pruebas:
        fallos.append("Mencionaste menos de la mitad de las pruebas (-5 puntos).")
    
    if testigos_mencionados < total_testigos:
        fallos.append(f"No mencionaste {total_testigos - testigos_mencionados} testigos.")
        mejoras.append("Nombra más testigos o usa sus declaraciones.")
    if penalizacion_testigos:
        fallos.append("Mencionaste menos de la mitad de los testigos (-4 puntos).")
    
    if not ley_mencionada:
        fallos.append("No mencionaste la ley aplicable.")
        mejoras.append(f"Cita la ley del caso, por ejemplo: '{caso['ley']}'.")
    
    if not proc_mencionado:
        fallos.append("No mencionaste el procedimiento.")
        mejoras.append(f"Menciona el procedimiento, por ejemplo: '{caso['procedimiento']}'.")
    
    if penalizacion_oraciones:
        fallos.append(f"Tu alegato tiene solo {num_oraciones} oración(es) (-5 puntos).")
        mejoras.append("Escribe al menos 3 oraciones para desarrollar mejor tu argumento.")
    
    if argumentos_logicos < max(total_pruebas, total_testigos):
        mejoras.append("Usa más 'porque', 'según' o 'declara' para construir argumentos lógicos.")
    
    if max_repeticion > 5:
        fallos.append("Repetiste una palabra más de 5 veces (-5 puntos).")
        mejoras.append("Varía tu vocabulario para que tu alegato sea más claro.")
    elif num_palabras_unicas <= 10:
        mejoras.append("Usa más de 10 palabras distintas para obtener un bonus (+5).")

    consejos_eticos = [
        "Dirígete al magistrado o magistrada con respeto, usando 'Honorable Magistrado/a'.",
        "Mantén la compostura en el salón, sin interrumpir ni alzar la voz.",
        "Presenta tus argumentos con honestidad, sin alterar los hechos pa’ beneficiar a tu cliente."
    ]
    if rol in ["Defensor", "Demandado"]:
        consejos_eticos.append("Defiende a tu cliente con ética, evitando acusaciones falsas contra otros.")
    elif rol in ["Fiscal", "Demandante"]:
        consejos_eticos.append("Busca justicia con integridad, sin exagerar cargos pa’ presionar.")

    mensaje = (
        f"Puntuación: {puntaje}/{max_puntaje} ({int(porcentaje)}%)\n"
        f"Rol: {rol}\n"
        f"Dificultad: {dificultad}/10 ({dificultad_texto})\n"
        f"Pruebas mencionadas: {pruebas_mencionadas}/{total_pruebas}\n"
        f"Testigos mencionados: {testigos_mencionados}/{total_testigos}\n"
        f"Argumentos lógicos: {argumentos_logicos}\n"
        f"Variedad de palabras: {puntaje_variedad}\n"
        "\nPuntos que fallaste:\n" + ("\n".join(fallos) if fallos else "Ninguno, ¡bien hecho!") + "\n"
        "\nCómo mejorar:\n" + ("\n".join(mejoras) if mejoras else "Sigue así, ¡perfecto!") + "\n"
        "\nConsejos de ética en audiencias:\n" + "\n".join(consejos_eticos)
    )
    return puntaje, mensaje

# Configuración de CSRF
csrf = CSRFProtect(app)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Rutas
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('inicio'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, password FROM usuarios WHERE username = ?", (username,))
                user = cursor.fetchone()
                if user and check_password_hash(user[1], password):
                    session['user_id'] = user[0]
                    flash("Inicio de sesión exitoso!")
                    return redirect(url_for('inicio'))
                flash("Usuario o contraseña incorrectos.")
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('inicio'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        real_name = request.form.get('real_name')
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM usuarios WHERE username = ? OR email = ?", (username, email))
                if cursor.fetchone():
                    flash("El usuario o correo ya existe.")
                    return render_template('register.html')
                hashed_password = generate_password_hash(password)
                cursor.execute("INSERT INTO usuarios (username, password, email, real_name) VALUES (?, ?, ?, ?)",
                               (username, hashed_password, email, real_name))
                conn.commit()
                flash("Registro exitoso! Por favor, inicia sesión.")
                return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Has cerrado sesión.")
    return redirect(url_for('login'))

@app.route('/inicio')
@login_required
def inicio():
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    return render_template('inicio.html', user_info=user_info)

def lista_casos(tabla, template_name):
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad FROM {tabla}")
            casos_data = cursor.fetchall()
            casos = [dict(id=row[0], titulo=row[1], hechos=row[2], pruebas=json.loads(row[3]) if row[3] else {},
                          testigos=json.loads(row[4]) if row[4] else {}, defensa=row[5], ley=row[6], procedimiento=row[7],
                          dificultad=row[8] if row[8] is not None else 0)
                     for row in casos_data]
        if not casos_data:
            flash(f"No se encontraron casos en {tabla}")
        return render_template(template_name, casos=casos, user_info=user_info, tabla=tabla)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        return redirect(url_for('inicio'))

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

@app.route('/caso/<tabla>/<int:caso_id>', methods=['GET', 'POST'])
@login_required
def caso(tabla, caso_id):
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (tabla,))
            if not cursor.fetchone():
                flash(f"La tabla {tabla} no existe en la base de datos")
                return redirect(url_for('inicio'))
            cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad FROM {tabla} WHERE id = ?", (caso_id,))
            caso_data = cursor.fetchone()
            if not caso_data:
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
        endpoint_map = {
            'casos_penales': 'penal',
            'casos_civil': 'civil',
            'casos_tierras': 'tierras',
            'casos_administrativo': 'administrativo',
            'casos_familia': 'familia',
            'casos_ninos': 'ninos'
        }
        endpoint = endpoint_map.get(tabla, 'inicio')
        return render_template('casos.html', caso=caso, user_info=user_info, resultado=resultado, tabla=tabla, endpoint=endpoint, rol=rol)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': str(e)}), 500
        return redirect(url_for('inicio'))
    except Exception as e:
        flash(f"Error inesperado: {str(e)}")
        return redirect(url_for('inicio'))

@app.route('/caso_multi/<tabla>/<int:caso_id>', methods=['GET', 'POST'])
@login_required
def caso_multi(tabla, caso_id):
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad FROM {tabla} WHERE id = ?", (caso_id,))
            caso_data = cursor.fetchone()
            if not caso_data:
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

            cursor.execute("SELECT id, fiscal_id, defensor_id, estado, fiscal_alegato, defensor_alegato, fiscal_puntos, defensor_puntos, ganador_id FROM juicios WHERE tabla = ? AND caso_id = ?", (tabla, caso_id))
            juicio = cursor.fetchone()

            if not juicio:
                cursor.execute("INSERT INTO juicios (tabla, caso_id, fiscal_id, defensor_id, estado) VALUES (?, ?, ?, ?, ?)",
                               (tabla, caso_id, None, None, 'pendiente'))
                conn.commit()
                cursor.execute("SELECT id, fiscal_id, defensor_id, estado, fiscal_alegato, defensor_alegato, fiscal_puntos, defensor_puntos, ganador_id FROM juicios WHERE tabla = ? AND caso_id = ?", (tabla, caso_id))
                juicio = cursor.fetchone()

            rol1 = "Fiscal" if tabla == 'casos_penales' else "Demandante"
            rol2 = "Defensor" if tabla == 'casos_penales' else "Demandado"

            rol = None
            demandante_id = None
            demandado_id = None
            fiscal_name = None
            defensor_name = None
            resultado = None

            if juicio:
                juicio_id, fiscal_id, defensor_id, estado, fiscal_alegato, defensor_alegato, fiscal_puntos, defensor_puntos, ganador_id = juicio
                demandante_id = fiscal_id
                demandado_id = defensor_id
                if fiscal_id == session['user_id'] and not fiscal_alegato:
                    rol = "Fiscal" if tabla == 'casos_penales' else "Demandante"
                elif defensor_id == session['user_id'] and not defensor_alegato:
                    rol = "Defensor" if tabla == 'casos_penales' else "Demandado"
                elif fiscal_id == defensor_id == session['user_id']:
                    rol = "Defensor" if fiscal_alegato and not defensor_alegato else "Fiscal"
                if fiscal_id:
                    cursor.execute("SELECT username FROM usuarios WHERE id = ?", (fiscal_id,))
                    fiscal_name = cursor.fetchone()[0]
                if defensor_id:
                    cursor.execute("SELECT username FROM usuarios WHERE id = ?", (defensor_id,))
                    defensor_name = cursor.fetchone()[0]
                if estado == 'completado' and fiscal_puntos and defensor_puntos:
                    ganador_name = fiscal_name if ganador_id == fiscal_id else defensor_name if ganador_id == defensor_id else "Empate"
                    fiscal_puntos, fiscal_evaluacion = evaluar_alegato(fiscal_alegato, caso, "Fiscal")
                    defensor_puntos, defensor_evaluacion = evaluar_alegato(defensor_alegato, caso, "Defensor")
                    resultado = (f"Fiscal ({fiscal_name}):\nAlegato: {fiscal_alegato}\n{fiscal_evaluacion}\n\n"
                                f"Defensor ({defensor_name}):\nAlegato: {defensor_alegato}\n{defensor_evaluacion}\n\n"
                                f"Ganador: {ganador_name}")
                elif fiscal_alegato or defensor_alegato:
                    resultado = (f"Fiscal ({fiscal_name}): {fiscal_alegato or 'No enviado aún'}\n"
                                f"Defensor ({defensor_name}): {defensor_alegato or 'No enviado aún'}")

            if request.method == 'POST':
                rol_seleccionado = request.form.get('rol')
                argumento = request.form.get('argumento')
                reiniciar = request.form.get('reiniciar')
                valid_roles = ['Fiscal', 'Defensor'] if tabla == 'casos_penales' else ['Demandante', 'Demandado']

                if reiniciar == 'true':
                    if juicio:
                        cursor.execute("DELETE FROM juicios WHERE id = ?", (juicio[0],))
                        conn.commit()
                        flash("Juicio reiniciado con éxito")
                    return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))

                if rol_seleccionado in valid_roles:
                    if not juicio or juicio[3] == 'completado':
                        cursor.execute("INSERT INTO juicios (tabla, caso_id, fiscal_id, defensor_id, estado) VALUES (?, ?, ?, ?, ?)",
                                       (tabla, caso_id, session['user_id'] if rol_seleccionado in ['Fiscal', 'Demandante'] else None,
                                        session['user_id'] if rol_seleccionado in ['Defensor', 'Demandado'] else None, 'pendiente'))
                        conn.commit()
                        cursor.execute("SELECT id, fiscal_id, defensor_id, estado, fiscal_alegato, defensor_alegato, fiscal_puntos, defensor_puntos, ganador_id FROM juicios WHERE tabla = ? AND caso_id = ?", (tabla, caso_id))
                        juicio = cursor.fetchone()
                    elif juicio[3] == 'pendiente':
                        juicio_id, fiscal_id, defensor_id = juicio[0], juicio[1], juicio[2]
                        if rol_seleccionado in ['Fiscal', 'Demandante'] and not fiscal_id:
                            cursor.execute("UPDATE juicios SET fiscal_id = ? WHERE id = ?", (session['user_id'], juicio_id))
                            conn.commit()
                        elif rol_seleccionado in ['Defensor', 'Demandado'] and not defensor_id:
                            cursor.execute("UPDATE juicios SET defensor_id = ? WHERE id = ?", (session['user_id'], juicio_id))
                            conn.commit()
                        else:
                            flash("Rol ya ocupado")
                            return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))
                    rol = rol_seleccionado
                    return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))

                if argumento and juicio and juicio[3] == 'pendiente':
                    juicio_id, fiscal_id, defensor_id = juicio[0], juicio[1], juicio[2]
                    if fiscal_id and defensor_id:
                        if session['user_id'] == fiscal_id and not juicio[4]:
                            cursor.execute("UPDATE juicios SET fiscal_alegato = ? WHERE id = ?", (argumento, juicio_id))
                            conn.commit()
                            flash("Alegato de fiscal enviado")
                        elif session['user_id'] == defensor_id and not juicio[5]:
                            cursor.execute("UPDATE juicios SET defensor_alegato = ? WHERE id = ?", (argumento, juicio_id))
                            conn.commit()
                            flash("Alegato de defensor enviado")
                        else:
                            flash("Ya enviaste tu alegato o no eres parte")
                            return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))

                        cursor.execute("SELECT fiscal_alegato, defensor_alegato FROM juicios WHERE id = ?", (juicio_id,))
                        fiscal_alegato, defensor_alegato = cursor.fetchone()
                        if fiscal_alegato and defensor_alegato:
                            fiscal_puntos, fiscal_evaluacion = evaluar_alegato(fiscal_alegato, caso, "Fiscal")
                            defensor_puntos, defensor_evaluacion = evaluar_alegato(defensor_alegato, caso, "Defensor")
                            ganador_id = fiscal_id if fiscal_puntos > defensor_puntos else defensor_id if defensor_puntos > fiscal_puntos else None
                            ganador_name = fiscal_name if ganador_id == fiscal_id else defensor_name if ganador_id == defensor_id else "Empate"
                            cursor.execute("UPDATE juicios SET fiscal_puntos = ?, defensor_puntos = ?, ganador_id = ?, estado = ?, resultado = ? WHERE id = ?",
                                           (fiscal_puntos, defensor_puntos, ganador_id, 'completado', f"Ganador: {ganador_name}", juicio_id))
                            conn.commit()
                            resultado = (f"Fiscal ({fiscal_name}):\nAlegato: {fiscal_alegato}\n{fiscal_evaluacion}\n\n"
                                        f"Defensor ({defensor_name}):\nAlegato: {defensor_alegato}\n{defensor_evaluacion}\n\n"
                                        f"Ganador: {ganador_name}")
                            flash("Juicio completado")
                    else:
                        flash("Faltan jugadores pa’ enviar alegatos")
                    return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))

                flash("Acción no válida")
                return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))

        endpoint = {'casos_penales': 'penal', 'casos_civil': 'civil', 'casos_tierras': 'tierras',
                    'casos_administrativo': 'administrativo', 'casos_familia': 'familia', 'casos_ninos': 'ninos'}.get(tabla, 'inicio')
        juicio_completo = juicio and demandante_id and demandado_id if juicio else False
        return render_template('casos_multi.html', caso=caso, user_info=user_info, juicio=juicio, rol=rol, tabla=tabla, endpoint=endpoint,
                              juicio_completo=juicio_completo, demandante_id=demandante_id, demandado_id=demandado_id, rol1=rol1, rol2=rol2,
                              fiscal_name=fiscal_name, defensor_name=defensor_name, resultado=resultado)

    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        return redirect(url_for('inicio'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT real_name, points FROM usuarios ORDER BY points DESC")
            all_users = [{'real_name': row[0], 'points': row[1], 
                          'rank': 'Principiante' if row[1] <= 50 else 'Medio' if row[1] <= 150 else 'Pro'} 
                         for row in cursor.fetchall()]
    except sqlite3.Error as e:
        flash(f"Error al cargar el ranking: {e}")
        all_users = []

    if request.method == 'POST':
        real_name = request.form.get('real_name')
        email = request.form.get('email')
        photo = request.files.get('photo')
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                if photo:
                    filename = secure_filename(photo.filename)
                    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    photo.save(photo_path)
                    cursor.execute("UPDATE usuarios SET real_name = ?, email = ?, photo_path = ? WHERE id = ?",
                                   (real_name, email, photo_path, session['user_id']))
                else:
                    cursor.execute("UPDATE usuarios SET real_name = ?, email = ? WHERE id = ?",
                                   (real_name, email, session['user_id']))
                conn.commit()
                flash("Perfil actualizado exitosamente!")
                return redirect(url_for('profile'))
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
    
    return render_template('profile.html', user_info=user_info, all_users=all_users)

@app.route('/add_caso', methods=['GET', 'POST'])
@admin_required
def admin():
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    if request.method == 'POST':
        tabla = request.form.get('tabla')
        titulo = request.form.get('titulo')
        hechos = request.form.get('hechos')
        pruebas = request.form.get('pruebas')
        testigos = request.form.get('testigos')
        defensa = request.form.get('defensa')
        ley = request.form.get('ley')
        procedimiento = request.form.get('procedimiento')
        dificultad = int(request.form.get('dificultad', 0))
        try:
            pruebas_json = json.dumps(dict(prueba.split(':') for prueba in pruebas.split(',') if ':' in prueba))
            testigos_json = json.dumps(dict(testigo.split(':') for testigo in testigos.split(',') if ':' in testigo))
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(f"INSERT INTO {tabla} (titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                               (titulo, hechos, pruebas_json, testigos_json, defensa, ley, procedimiento, dificultad))
                conn.commit()
                flash("Caso añadido exitosamente!")
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
        except Exception as e:
            flash(f"Error al procesar los datos: {e}")
    return render_template('add_caso.html', user_info=user_info)

@app.route('/edit_caso/<string:tabla>/<int:caso_id>', methods=['GET', 'POST'])
@admin_required
def edit_caso(tabla, caso_id):
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad FROM {tabla} WHERE id = ?", (caso_id,))
            caso_data = cursor.fetchone()
            if not caso_data:
                flash("Caso no encontrado")
                return redirect(url_for('inicio'))
            caso = {
                'id': caso_data[0],
                'titulo': caso_data[1],
                'hechos': caso_data[2],
                'pruebas': caso_data[3] if caso_data[3] else '{}',
                'testigos': caso_data[4] if caso_data[4] else '{}',
                'defensa': caso_data[5],
                'ley': caso_data[6],
                'procedimiento': caso_data[7],
                'dificultad': caso_data[8]
            }

            if request.method == 'POST':
                tabla = request.form.get('tabla')
                titulo = request.form.get('titulo')
                hechos = request.form.get('hechos')
                pruebas = request.form.get('pruebas')
                testigos = request.form.get('testigos')
                defensa = request.form.get('defensa')
                ley = request.form.get('ley')
                procedimiento = request.form.get('procedimiento')
                dificultad = int(request.form.get('dificultad', 0))

                try:
                    pruebas_dict = json.loads(pruebas) if pruebas else {}
                    testigos_dict = json.loads(testigos) if testigos else {}
                    pruebas_json = json.dumps(pruebas_dict)
                    testigos_json = json.dumps(testigos_dict)

                    cursor.execute(f"UPDATE {tabla} SET titulo = ?, hechos = ?, pruebas = ?, testigos = ?, defensa = ?, ley = ?, procedimiento = ?, dificultad = ? WHERE id = ?",
                                   (titulo, hechos, pruebas_json, testigos_json, defensa, ley, procedimiento, dificultad, caso_id))
                    conn.commit()
                    flash("Caso actualizado exitosamente!")
                    return redirect(url_for('inicio'))
                except json.JSONDecodeError as e:
                    conn.rollback()
                    flash(f"Error en el formato JSON de pruebas o testigos: {e}")
                except sqlite3.Error as e:
                    conn.rollback()
                    flash(f"Error en la base de datos: {e}")
                except Exception as e:
                    conn.rollback()
                    flash(f"Error al actualizar el caso: {e}")

        return render_template('edit_caso.html', user_info=user_info, caso=caso, tabla=tabla)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        return redirect(url_for('inicio'))

@app.route('/estado_juicio/<tabla>/<int:caso_id>')
@login_required
def estado_juicio(tabla, caso_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, fiscal_id, defensor_id FROM juicios WHERE tabla = ? AND caso_id = ? AND estado = 'pendiente'", (tabla, caso_id))
            juicio = cursor.fetchone()
            if juicio:
                juicio_id, fiscal_id, defensor_id = juicio
                user_in_juicio = session['user_id'] in [fiscal_id, defensor_id] if fiscal_id or defensor_id else False
                oponente_unido = (fiscal_id is not None and defensor_id is not None)
                rol_oponente = None
                fiscal_name = None
                defensor_name = None
                if fiscal_id:
                    cursor.execute("SELECT username FROM usuarios WHERE id = ?", (fiscal_id,))
                    fiscal_result = cursor.fetchone()
                    fiscal_name = fiscal_result[0] if fiscal_result else "Desconocido"
                if defensor_id:
                    cursor.execute("SELECT username FROM usuarios WHERE id = ?", (defensor_id,))
                    defensor_result = cursor.fetchone()
                    defensor_name = defensor_result[0] if defensor_result else "Desconocido"
                if not oponente_unido and user_in_juicio:
                    if fiscal_id and not defensor_id:
                        rol_oponente = "Defensor" if tabla == 'casos_penales' else "Demandado"
                    elif defensor_id and not fiscal_id:
                        rol_oponente = "Fiscal" if tabla == 'casos_penales' else "Demandante"
                if not user_in_juicio:
                    oponente_unido = False
                return jsonify({
                    'oponente_unido': oponente_unido,
                    'rol_oponente': rol_oponente,
                    'fiscal_name': fiscal_name,
                    'defensor_name': defensor_name
                })
            return jsonify({
                'oponente_unido': False,
                'rol_oponente': None,
                'fiscal_name': None,
                'defensor_name': None
            }), 200
    except sqlite3.Error as e:
        return jsonify({'error': f'Error en la base de datos: {e}'}), 500

@app.route('/download_db')
@admin_required
def download_db():
    try:
        return send_file(DB_PATH, as_attachment=True, download_name='casos.db')
    except Exception as e:
        flash(f"Error al descargar la base de datos: {str(e)}")
        return redirect(url_for('inicio'))

@app.route('/upload_db', methods=['GET', 'POST'])
@admin_required
def upload_db():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No se seleccionó ningún archivo.")
            return redirect(url_for('upload_db'))
        file = request.files['file']
        if file.filename != 'casos.db':
            flash("El archivo debe llamarse 'casos.db'.")
            return redirect(url_for('upload_db'))
        try:
            file.save(DB_PATH)
            flash("Base de datos subida exitosamente.")
        except Exception as e:
            flash(f"Error al subir la base de datos: {str(e)}")
        return redirect(url_for('upload_db'))
    return render_template('upload_db.html')

# Ejecución de la app
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
