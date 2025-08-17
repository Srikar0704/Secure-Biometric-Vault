import os
import sqlite3
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import face_recognition
import cv2
import numpy as np
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
socketio = SocketIO(app)

DB_PATH = 'vault.db'
USER_FILES_PATH = 'vault/user_files/'
if not os.path.exists(USER_FILES_PATH):
    os.makedirs(USER_FILES_PATH)

# Encryption key (in production, store securely!)
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- Database Setup ----------
def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        face_encoding BLOB
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        site TEXT,
        login TEXT,
        password_encrypted TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')
    conn.commit()
    conn.close()

init_db()

# ---------- Registration ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (
                username, generate_password_hash(password)
            ))
            conn.commit()
            session['username'] = username
            flash('Registration successful! Please capture your face.')
            return redirect(url_for('face_capture'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
            return render_template('register.html')
    return render_template('register.html')

# ---------- Face Capture ----------
@app.route('/face_capture')
def face_capture():
    return render_template('face_capture.html')

@socketio.on('face_image')
def handle_face_image(data):
    username = session.get('username')
    if username is None:
        emit('face_status', {'success': False, 'msg': 'Not logged in.'})
        return
    img_data = np.frombuffer(data['img'], np.uint8)
    img = cv2.imdecode(img_data, cv2.IMREAD_COLOR)
    encodings = face_recognition.face_encodings(img)
    if len(encodings) == 0:
        emit('face_status', {'success': False, 'msg': 'No face detected.'})
        return
    face_encoding = encodings[0].tobytes()
    conn = get_db()
    conn.execute('UPDATE users SET face_encoding=? WHERE username=?', (face_encoding, username))
    conn.commit()
    emit('face_status', {'success': True, 'msg': 'Face registered!'})
    return

# ---------- Login ----------
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            session['user_id'] = user['id']
            # Go to face verification step
            return redirect(url_for('face_verify'))
        else:
            flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/face_verify')
def face_verify():
    return render_template('face_capture.html', verify=True)

@socketio.on('verify_face')
def verify_face(data):
    username = session.get('username')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    img_data = np.frombuffer(data['img'], np.uint8)
    img = cv2.imdecode(img_data, cv2.IMREAD_COLOR)
    encodings = face_recognition.face_encodings(img)
    if len(encodings) == 0 or user is None or user['face_encoding'] is None:
        emit('face_status', {'success': False, 'msg': 'Face not matched.'})
        return
    match = face_recognition.compare_faces(
        [np.frombuffer(user['face_encoding'], dtype=np.float64)], encodings[0]
    )[0]
    if match:
        session['authenticated'] = True
        emit('face_status', {'success': True, 'msg': 'Face verified!'})
    else:
        emit('face_status', {'success': False, 'msg': 'Face not matched.'})

# ---------- Dashboard ----------
@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    user_id = session['user_id']
    username = session['username']
    user_dir = os.path.join(USER_FILES_PATH, username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)  # Create folder if not present
    files = os.listdir(user_dir)
    conn = get_db()
    credentials = conn.execute('SELECT * FROM credentials WHERE user_id=?', (user_id,)).fetchall()
    return render_template('dashboard.html', credentials=credentials, files=files)

# ---------- File Upload ----------
@app.route('/upload', methods=['POST'])
def upload():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    file = request.files['file']
    username = session['username']
    user_dir = os.path.join(USER_FILES_PATH, username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    file.save(os.path.join(user_dir, file.filename))
    flash('File uploaded!')
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download(filename):
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    username = session['username']
    user_dir = os.path.join(USER_FILES_PATH, username)
    return send_from_directory(user_dir, filename, as_attachment=True)

# ---------- Password Manager ----------
@app.route('/password_manager', methods=['GET', 'POST'])
def password_manager():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db()
    if request.method == 'POST':
        site = request.form['site']
        login = request.form['login']
        password = request.form['password']
        encrypted = fernet.encrypt(password.encode())
        conn.execute('INSERT INTO credentials (user_id, site, login, password_encrypted) VALUES (?, ?, ?, ?)',
                     (user_id, site, login, encrypted))
        conn.commit()
        flash('Credential saved!')
    credentials = conn.execute('SELECT * FROM credentials WHERE user_id=?', (user_id,)).fetchall()
    # Decrypt passwords to show
    decrypted = []
    for cred in credentials:
        dec = fernet.decrypt(cred['password_encrypted']).decode()
        decrypted.append({'site': cred['site'], 'login': cred['login'], 'password': dec})
    return render_template('password_manager.html', credentials=decrypted)

# ---------- Logout ----------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/face_verified')
def face_verified():
    session['authenticated'] = True
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    socketio.run(app, debug=True)