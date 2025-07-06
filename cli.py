from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from flask_bcrypt import Bcrypt
import sqlite3
import configparser
import os
import re
from datetime import datetime
from tqdm import tqdm
import time

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Замените на случайный ключ в продакшене
bcrypt = Bcrypt(app)

# Конфигурация
config = configparser.ConfigParser()
config.read('config.ini')
if not config.sections():
    config['Database'] = {'URI': 'sqlite:///logs.db'}
    config['Logs'] = {'Directory': 'logs', 'Pattern': 'access.log'}
    with open('config.ini', 'w') as f:
        config.write(f)

db_path = config['Database']['URI'].replace('sqlite:///', '')

def init_db():
    """Инициализация базы данных"""
    if os.path.dirname(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Таблица пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')
    
    # Таблица логов
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            date TEXT,
            method TEXT,
            url TEXT,
            status INTEGER,
            size INTEGER,
            user_agent TEXT,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    # Создаем администратора по умолчанию, если его нет
    cursor.execute('SELECT * FROM users WHERE username = "admin"')
    if not cursor.fetchone():
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        cursor.execute('''
            INSERT INTO users (username, password_hash, is_admin)
            VALUES (?, ?, 1)
        ''', ('admin', hashed_password))
    
    conn.commit()
    conn.close()

init_db()

# Декоратор для проверки авторизации
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему для доступа к этой странице', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Декоратор для проверки прав администратора
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute('''
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
            ''', (username, hashed_password))
            conn.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Это имя пользователя уже занято', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = bool(user[3])
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/parse-logs')
@login_required
def parse_logs():
    log_path = os.path.join(
        config['Logs']['Directory'],
        config['Logs']['Pattern']
    )
    
    if not os.path.exists(log_path):
        flash(f'Файл логов не найден по пути: {log_path}', 'danger')
        return redirect(url_for('dashboard'))
    
    with open(log_path, 'r', encoding='utf-8') as f:
        total_lines = sum(1 for _ in f)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    parsed_count = 0
    
    with tqdm(total=total_lines, desc="Прогресс", unit="стр") as pbar:
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    parsed = parse_line(line.strip())
                    if parsed:
                        cursor.execute('''
                            INSERT INTO log_entries 
                            (ip, date, method, url, status, size, user_agent, user_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', parsed + (session['user_id'],))
                        parsed_count += 1
                except Exception as e:
                    print(f"Ошибка в строке: {e}")
                finally:
                    pbar.update(1)
                    time.sleep(0.001)
    
    conn.commit()
    conn.close()
    flash(f'Успешно обработано строк: {parsed_count}/{total_lines}', 'success')
    return redirect(url_for('view_logs'))

def parse_line(line):
    """Парсинг одной строки лога"""
    match = re.match(
        r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
        line
    )
    if not match:
        return None

    ip, date_str, req, status, size, referrer, ua = match.groups()
    method, url, _ = req.split(' ', 2)
    
    try:
        date = datetime.strptime(date_str, '%d/%b/%Y:%H:%M:%S %z').isoformat()
    except:
        date = date_str

    return (
        ip,
        date,
        method,
        url,
        int(status),
        int(size),
        ua if ua != '-' else None
    )

@app.route('/view-logs')
@login_required
def view_logs():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Базовый запрос с JOIN для получения имени пользователя
    query = '''
        SELECT l.*, u.username 
        FROM log_entries l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY l.date DESC
        LIMIT 100
    '''
    cursor.execute(query)
    logs = cursor.fetchall()
    conn.close()
    
    return render_template('view_logs.html', logs=logs)

@app.route('/filter-logs', methods=['POST'])
@login_required
def filter_logs():
    ip = request.form.get('ip')
    keyword = request.form.get('keyword')
    date_from = request.form.get('date_from')
    date_to = request.form.get('date_to')
    
    where_clauses = []
    params = []
    
    if ip:
        where_clauses.append("l.ip = ?")
        params.append(ip)
    if keyword:
        where_clauses.append("l.url LIKE ?")
        params.append(f"%{keyword}%")
    if date_from:
        where_clauses.append("l.date >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("l.date <= ?")
        params.append(date_to)
    
    where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    query = f'''
        SELECT l.*, u.username 
        FROM log_entries l
        LEFT JOIN users u ON l.user_id = u.id
        {where}
        ORDER BY l.date DESC
        LIMIT 100
    '''
    
    cursor.execute(query, params)
    logs = cursor.fetchall()
    conn.close()
    
    return render_template('view_logs.html', logs=logs)

@app.route('/manage-users')
@login_required
@admin_required
def manage_users():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, is_admin FROM users')
    users = cursor.fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)
