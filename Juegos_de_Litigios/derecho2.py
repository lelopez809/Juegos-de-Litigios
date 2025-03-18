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
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords

# Configurar la ruta de los datos de NLTK en Render
nltk_data_dir = os.path.join(os.path.dirname(__file__), 'nltk_data')
os.makedirs(nltk_data_dir, exist_ok=True)
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
        conn.close()
        print("Base de datos inicializada correctamente.")
    except Exception as e:
        print(f"Error al inicializar la base de datos: {e}")
        raise

def get_user_info(user_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, real_name, points, photo_path FROM usuarios WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if user:
            rank = "Novato" if user[4] < 100 else "Intermedio" if user[4] < 500 else "Experto"
            return {'id': user[0], 'username': user[1], 'email': user[2], 'real_name': user[3], 'points': user[4], 'photo_path': user[5], 'rank': rank}
        return None
    except sqlite3.Error as e:
        print(f"Error al obtener información del usuario: {e}")
        return None

def evaluar_alegato(alegato, caso, rol="Jugador"):
    stop_words = set(stopwords.words('spanish'))
    palabras = word_tokenize(alegato)
    alegato_limpio = ' '.join([palabra for palabra in palabras if palabra.lower() not in stop_words])
    
    oraciones = sent_tokenize(alegato_limpio)
    num_oraciones = len(oraciones)
    tokens = word_tokenize(alegato_limpio.lower())
    dificultad = caso['dificultad']
    max_puntaje = 100

    puntaje = 0
    puntaje_base = min(num_oraciones * 5, 20)
    puntaje += puntaje_base

    if rol in ["Fiscal", "Demandante"]:
        bonus_rol = 15 if dificultad > 5 else 10
    elif rol in ["Defensor", "Demandado"]:
        bonus_rol = 20 if dificultad > 7 else 15
    else:
        bonus_rol = 5
    puntaje += bonus_rol

    total_pruebas = len(caso['pruebas'])
    total_testigos = len(caso['testigos'])
    pruebas_mencionadas = 0
    testigos_mencionados = 0
    argumentos_logicos = 0

    alegato_lower = alegato.lower()
    for prueba, detalle in caso['pruebas'].items():
        prueba_lower = prueba.lower()
        detalle_lower = detalle.lower()
        if (prueba_lower in alegato_lower or detalle_lower in alegato_lower or 
            any(token in prueba_lower or token in detalle_lower for token in tokens)):
            puntaje += 10
            pruebas_mencionadas += 1
            if any("porque" in oracion or "prueba" in oracion for oracion in sent_tokenize(alegato_lower) if prueba_lower in oracion):
                puntaje += 5
                argumentos_logicos += 1

    for testigo, detalle in caso['testigos'].items():
        testigo_lower = testigo.lower()
        detalle_lower = detalle.lower()
        if (testigo_lower in alegato_lower or detalle_lower in alegato_lower or 
            any(token in testigo_lower or token in detalle_lower for token in tokens)):
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
        puntaje -= 3

    frecuencias = {}
    for token in tokens:
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

    # Feedback de fallos y mejoras
    fallos = []
    mejoras = []
    
    if pruebas_mencionadas < total_pruebas:
        fallos.append(f"No mencionaste {total_pruebas - pruebas_mencionadas} pruebas.")
        mejoras.append("Incluye más pruebas específicas como 'ventana forzada' o 'bolsa sospechosa'.")
    if penalizacion_pruebas:
        fallos.append("Mencionaste menos de la mitad de las pruebas (-5 puntos).")
    
    if testigos_mencionados < total_testigos:
        fallos.append(f"No mencionaste {total_testigos - testigos_mencionados} testigos.")
        mejoras.append("Nombra más testigos o usa sus declaraciones.")
    if penalizacion_testigos:
        fallos.append("Mencionaste menos de la mitad de los testigos (-4 puntos).")
    
    if not ley_mencionada:
        fallos.append("No mencionaste la ley aplicable.")
        mejoras.append("Cita la ley, ej: 'robo agravado'.")
    
    if not proc_mencionado:
        fallos.append("No mencionaste el procedimiento.")
        mejoras.append("Menciona el procedimiento, ej: 'tribunal de primera instancia'.")
    
    if penalizacion_oraciones:
        fallos.append(f"Tu alegato tiene solo {num_oraciones} oración(es) (-3 puntos).")
        mejoras.append("Escribe al menos 3 oraciones pa’ más puntos.")
    
    if argumentos_logicos < max(total_pruebas, total_testigos):
        mejoras.append("Usa más 'porque', 'según' o 'declara' pa’ argumentos lógicos.")
    
    if max_repeticion > 5:
        fallos.append("Repetiste una palabra más de 5 veces (-5 puntos).")
        mejoras.append("Varía tu vocabulario.")
    elif num_palabras_unicas <= 10:
        mejoras.append("Usa más de 10 palabras distintas pa’ un bonus (+5).")

    # Consejos éticos con "magistrado/a"
    consejos_eticos = [
        "Dirígete al magistrado o magistrada con respeto, usando 'Honorable Magistrado/a'.",
        "Mantén la compostura en el salón, sin interrumpir ni alzar la voz.",
        "Presenta tus argumentos con honestidad, sin alterar los hechos pa’ beneficiar a tu cliente."
    ]
    if rol in ["Defensor", "Demandado"]:
        consejos_eticos.append("Defiende a tu cliente con ética, evitando acusaciones falsas contra otros.")
    elif rol in ["Fiscal", "Demandante"]:
        consejos_eticos.append("Busca justicia con integridad, sin exagerar cargos pa’ presionar.")

    # Mensaje corregido con formato limpio
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
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM usuarios WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()
            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                flash("Inicio de sesión exitoso!")
                return redirect(url_for('inicio'))
            else:
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
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM usuarios WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                conn.close()
                flash("El usuario o correo ya existe.")
                return render_template('register.html')
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO usuarios (username, password, email, real_name) VALUES (?, ?, ?, ?)",
                           (username, hashed_password, email, real_name))
            conn.commit()
            conn.close()
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

@app.route('/caso_multi/<tabla>/<int:caso_id>', methods=['GET', 'POST'])
@login_required
def caso_multi(tabla, caso_id):
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad FROM {tabla} WHERE id = ?", (caso_id,))
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
            'procedimiento': caso_data[7],
            'dificultad': caso_data[8]
        }
        juicio = None
        rol = None
        demandante_id = None
        demandado_id = None
        # Limpiar juicios obsoletos o inválidos
        cursor.execute("SELECT id, fiscal_id, defensor_id, estado FROM juicios WHERE tabla = ? AND caso_id = ? AND estado = 'pendiente'", (tabla, caso_id))
        juicio = cursor.fetchone()
        print(f"Juicio encontrado al inicio: {juicio}")
        if juicio:
            juicio_id, fiscal_id, defensor_id, estado = juicio
            # Limpiar si el juicio es inválido (mismo usuario en ambos roles o usuario no presente)
            if (fiscal_id == defensor_id) or (fiscal_id and defensor_id and session['user_id'] not in [fiscal_id, defensor_id]):
                print(f"Limpiando juicio inválido ID {juicio_id} para {tabla}/{caso_id}")
                cursor.execute("DELETE FROM juicios WHERE id = ?", (juicio_id,))
                conn.commit()
                juicio = None
            else:
                demandante_id = fiscal_id
                demandado_id = defensor_id
        # Procesar el formulario POST
        if request.method == 'POST':
            rol_seleccionado = request.form.get('rol')
            argumento = request.form.get('argumento')
            valid_roles = ['Fiscal', 'Defensor'] if tabla == 'casos_penales' else ['Demandante', 'Demandado']
            if rol_seleccionado and rol_seleccionado in valid_roles:
                cursor.execute("SELECT id, fiscal_id, defensor_id, estado FROM juicios WHERE tabla = ? AND caso_id = ? AND estado = 'pendiente'", (tabla, caso_id))
                juicio = cursor.fetchone()
                print(f"Juicio encontrado en POST (rol): {juicio}")
                if not juicio:
                    print(f"Creando nuevo juicio para {tabla}/{caso_id} con rol {rol_seleccionado}")
                    cursor.execute("INSERT INTO juicios (tabla, caso_id, fiscal_id, defensor_id, estado) VALUES (?, ?, ?, ?, ?)",
                                   (tabla, caso_id, session['user_id'] if rol_seleccionado in ['Fiscal', 'Demandante'] else None,
                                    session['user_id'] if rol_seleccionado in ['Defensor', 'Demandado'] else None, 'pendiente'))
                    conn.commit()
                    cursor.execute("SELECT id, fiscal_id, defensor_id, estado FROM juicios WHERE tabla = ? AND caso_id = ? AND estado = 'pendiente'", (tabla, caso_id))
                    juicio = cursor.fetchone()
                    print(f"Juicio creado con ID: {juicio[0]}")
                else:
                    juicio_id, fiscal_id, defensor_id, estado = juicio
                    print(f"Juicio existente: ID={juicio_id}, fiscal_id={fiscal_id}, defensor_id={defensor_id}")
                    if rol_seleccionado in ['Fiscal', 'Demandante'] and not fiscal_id:
                        print(f"Asignando fiscal_id={session['user_id']} a juicio {juicio_id}")
                        cursor.execute("UPDATE juicios SET fiscal_id = ? WHERE id = ?", (session['user_id'], juicio_id))
                        conn.commit()
                    elif rol_seleccionado in ['Defensor', 'Demandado'] and not defensor_id:
                        print(f"Asignando defensor_id={session['user_id']} a juicio {juicio_id}")
                        cursor.execute("UPDATE juicios SET defensor_id = ? WHERE id = ?", (session['user_id'], juicio_id))
                        conn.commit()
                    else:
                        flash("El rol seleccionado ya está ocupado o no puedes unirte a este juicio.")
                        return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))
                rol = rol_seleccionado
            elif argumento and juicio and fiscal_id and defensor_id:  # Solo procesar alegato si ambos roles están ocupados
                # Aquí iría la lógica para guardar el alegato (falta implementarla)
                flash("Alegato enviado (funcionalidad pendiente)")
                return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))
            else:
                flash("Rol no válido o no puedes enviar un alegato aún")
                return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))
            return redirect(url_for('caso_multi', tabla=tabla, caso_id=caso_id))
        else:
            cursor.execute("SELECT id, fiscal_id, defensor_id, estado FROM juicios WHERE tabla = ? AND caso_id = ? AND estado = 'pendiente'", (tabla, caso_id))
            juicio = cursor.fetchone()
            if juicio:
                juicio_id, fiscal_id, defensor_id, estado = juicio
                demandante_id = fiscal_id
                demandado_id = defensor_id
                if fiscal_id == session['user_id']:
                    rol = "Fiscal" if tabla == 'casos_penales' else "Demandante"
                elif defensor_id == session['user_id']:
                    rol = "Defensor" if tabla == 'casos_penales' else "Demandado"
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
        juicio_completo = False
        if juicio:
            juicio_id, fiscal_id, defensor_id, estado = juicio
            juicio_completo = (fiscal_id is not None and defensor_id is not None and fiscal_id != defensor_id)
        rol1 = "Fiscal" if tabla == 'casos_penales' else "Demandante"
        rol2 = "Defensor" if tabla == 'casos_penales' else "Demandado"
        return render_template('casos_multi.html', caso=caso, user_info=user_info, juicio=juicio, rol=rol, tabla=tabla, endpoint=endpoint, juicio_completo=juicio_completo, demandante_id=demandante_id, demandado_id=demandado_id, rol1=rol1, rol2=rol2)
    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {e}")
        return redirect(url_for('inicio'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_info = get_user_info(session['user_id'])
    if not user_info:
        return redirect(url_for('login'))
    
    # Obtener lista de todos los usuarios para el ranking
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT real_name, points FROM usuarios ORDER BY points DESC")
        all_users = [{'real_name': row[0], 'points': row[1], 
                      'rank': 'Principiante' if row[1] <= 50 else 'Medio' if row[1] <= 150 else 'Pro'} 
                     for row in cursor.fetchall()]
        conn.close()
    except sqlite3.Error as e:
        flash(f"Error al cargar el ranking: {e}")
        all_users = []

    if request.method == 'POST':
        real_name = request.form.get('real_name')
        email = request.form.get('email')
        photo = request.files.get('photo')
        try:
            conn = sqlite3.connect(DB_PATH)
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
            conn.close()
            flash("Perfil actualizado exitosamente!")
            return redirect(url_for('profile'))
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
    
    return render_template('profile.html', user_info=user_info, all_users=all_users)

@app.route('/admin', methods=['GET', 'POST'])
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
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(f"INSERT INTO {tabla} (titulo, hechos, pruebas, testigos, defensa, ley, procedimiento, dificultad) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (titulo, hechos, pruebas_json, testigos_json, defensa, ley, procedimiento, dificultad))
            conn.commit()
            conn.close()
            flash("Caso añadido exitosamente!")
        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {e}")
        except Exception as e:
            flash(f"Error al procesar los datos: {e}")
    return render_template('admin.html', user_info=user_info)
    
@app.route('/estado_juicio/<tabla>/<int:caso_id>')
@login_required
def estado_juicio(tabla, caso_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, fiscal_id, defensor_id FROM juicios WHERE tabla = ? AND caso_id = ? AND estado = 'pendiente'", (tabla, caso_id))
        juicio = cursor.fetchone()
        if juicio:
            juicio_id, fiscal_id, defensor_id = juicio
            # Verificar si el usuario actual es parte del juicio
            user_in_juicio = session['user_id'] in [fiscal_id, defensor_id] if fiscal_id or defensor_id else False
            oponente_unido = (fiscal_id is not None and defensor_id is not None)
            rol_oponente = None
            fiscal_name = None
            defensor_name = None
            # Obtener nombres de los usuarios
            if fiscal_id:
                cursor.execute("SELECT username FROM usuarios WHERE id = ?", (fiscal_id,))
                fiscal_result = cursor.fetchone()
                fiscal_name = fiscal_result[0] if fiscal_result else "Desconocido"
            if defensor_id:
                cursor.execute("SELECT username FROM usuarios WHERE id = ?", (defensor_id,))
                defensor_result = cursor.fetchone()
                defensor_name = defensor_result[0] if defensor_result else "Desconocido"
            # Determinar rol oponente si no están ambos roles ocupados
            if not oponente_unido and user_in_juicio:
                if fiscal_id and not defensor_id:
                    rol_oponente = "Defensor" if tabla == 'casos_penales' else "Demandado"
                elif defensor_id and not fiscal_id:
                    rol_oponente = "Fiscal" if tabla == 'casos_penales' else "Demandante"
            # Si el usuario no está en el juicio, forzamos oponente_unido a false
            if not user_in_juicio:
                oponente_unido = False
            conn.close()
            return jsonify({
                'oponente_unido': oponente_unido,
                'rol_oponente': rol_oponente,
                'fiscal_name': fiscal_name,
                'defensor_name': defensor_name
            })
        conn.close()
        return jsonify({
            'oponente_unido': False,
            'rol_oponente': None,
            'fiscal_name': None,
            'defensor_name': None
        }), 200
    except sqlite3.Error as e:
        return jsonify({'error': f'Error en la base de datos: {e}'}), 500

if __name__ == '__main__':
    print("Inicializando base de datos...")
    init_db()
    port = int(os.getenv("PORT", 5000))
    print(f"Corriendo en puerto {port}")
    app.run(host='0.0.0.0', port=port)
