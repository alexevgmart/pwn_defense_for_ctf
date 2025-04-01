from flask import Flask, render_template, send_file, request, redirect, url_for, session, jsonify
from sqlalchemy import create_engine, Column, Integer, Text, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.future import select
from base64 import b64decode as b64d
import json
import os
import re
import hashlib
from functools import wraps
from dotenv import load_dotenv

# Загрузка переменных окружения
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(32))

# Конфигурация
SITE_PASSWORD = hashlib.sha256(os.environ['SITE_PASSWORD'].encode()).hexdigest()
EDITOR_PASSWORD = hashlib.sha256(os.environ['EDITOR_PASSWORD'].encode()).hexdigest()
EDITABLE_DIRECTORY = os.environ.get('EDITABLE_DIRECTORY', './rules')
os.makedirs(EDITABLE_DIRECTORY, exist_ok=True)
DB_URL = os.environ['DB_URL']
WEB_PORT = int(os.environ.get('WEB_PORT', 8080))

# Инициализация базы данных
engine = create_engine(DB_URL, echo=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Streams(Base):
    __tablename__ = 'streams'
    id = Column(Integer, primary_key=True, autoincrement=True)
    stream = Column(Text, nullable=False)

# Функции для работы с паттернами
def load_patterns():
    patterns = []
    for filename in os.listdir(EDITABLE_DIRECTORY):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(EDITABLE_DIRECTORY, filename), 'r') as f:
                    pattern = json.load(f)
                    # Валидация паттерна
                    if not all(key in pattern for key in ['pattern', 'flag', 'std', 'active', 'action']):
                        continue
                    # if pattern['action'] != 'mark' or pattern['active'] != True:
                    if pattern['active'] != True:
                        continue
                    pattern['compiled'] = re.compile(pattern['pattern'])
                    patterns.append(pattern)
            except Exception as e:
                print(f"Error loading pattern {filename}: {e}")
    return patterns

# Декораторы для проверки авторизации
def site_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('site_logged_in'):
            return redirect(url_for('site_login'))
        return f(*args, **kwargs)
    return decorated_function

def editor_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('editor_logged_in'):
            return redirect(url_for('editor_login'))
        return f(*args, **kwargs)
    return decorated_function

# Маршруты авторизации
@app.route('/login', methods=['GET', 'POST'])
def site_login():
    if request.method == 'POST':
        if SITE_PASSWORD == request.form.get('password'):
            session['site_logged_in'] = True
            return redirect(url_for('get_streams'))
        return render_template('login.html', error='Неверный пароль сайта', login_type='site')
    return render_template('login.html', login_type='site')

@app.route('/editor-login', methods=['GET', 'POST'])
def editor_login():
    if request.method == 'POST':
        if EDITOR_PASSWORD == request.form.get('password'):
            session['editor_logged_in'] = True
            return redirect(url_for('editor'))
        return render_template('login.html', error='Неверный пароль редактора', login_type='editor')
    return render_template('login.html', login_type='editor')

@app.route('/logout')
def logout():
    session.pop('site_logged_in', None)
    session.pop('editor_logged_in', None)
    return redirect(url_for('site_login'))

# Функции для работы с потоками
def get_flags_in_stream(stream):
    patterns = load_patterns()  # Загружаем актуальные паттерны
    parsed_data = json.loads(b64d(stream).decode())
    flags = set()
    marks = set()

    for item in parsed_data:
        std, length, base64_str = item
        decoded_str = str(b64d(base64_str))[2:-1]

        for pattern in patterns:
            if not pattern['active']:
                continue

            if pattern['compiled'].search(decoded_str):
                if pattern['std'] is None or pattern['std'] == std:
                    flags.add(pattern['flag'])
                    if pattern['action'] == 'mark':
                        marks.add(pattern['flag'])

        try:
            b64d(base64_str).decode()
        except:
            flags.add('non_printable')

    return {
        'flags': list(flags),
        'marks': list(marks)
    }

# Маршруты для работы с потоками
@app.route('/')
@app.route('/streams', methods=['GET'])
@site_login_required
def get_streams():
    session_db = SessionLocal()
    try:
        result = session_db.execute(text("SELECT id, stream FROM streams"))
        streams = result.fetchall()

        streams_data = []
        for row in streams:
            id, data = row
            try:
                result = get_flags_in_stream(data)
                streams_data.append({
                    "id": id,
                    "flags": result['flags'],
                    "marks": result['marks']
                })
            except Exception as e:
                streams_data.append({
                    "id": id,
                    "flags": [],
                    "marks": []
                })

        return render_template('streams.html', streams=streams_data[::-1])
    finally:
        session_db.close()

@app.route('/streams/<int:id>', methods=['GET'])
@site_login_required
def get_stream_by_id(id):
    session_db = SessionLocal()
    try:
        result = session_db.execute(select(Streams).filter_by(id=id))
        stream_info = result.scalar_one_or_none()
        if stream_info:
            return render_template('stream.html', data=stream_info.stream)
        return "Stream not found", 404
    finally:
        session_db.close()

# Функции и маршруты для редактора JSON
def get_json_files():
    return [f for f in os.listdir(EDITABLE_DIRECTORY) 
            if f.endswith('.json') and os.path.isfile(os.path.join(EDITABLE_DIRECTORY, f))]

def valid_filename(filename):
    return (filename and filename.endswith('.json') 
            and not '/' in filename and not '\\' in filename)

@app.route('/editor')
@editor_login_required
def editor():
    return render_template('editor.html', files=get_json_files())

@app.route('/api/files')
@editor_login_required
def api_files():
    return jsonify({'files': get_json_files()})

@app.route('/api/file', methods=['GET'])
@editor_login_required
def api_get_file():
    filename = request.args.get('filename')
    if not valid_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400
    
    filepath = os.path.join(EDITABLE_DIRECTORY, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        with open(filepath, 'r') as f:
            return jsonify({'content': f.read()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/new', methods=['POST'])
@editor_login_required
def api_create_file():
    filename = request.json.get('filename')
    if not valid_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400
    
    filepath = os.path.join(EDITABLE_DIRECTORY, filename)
    if os.path.exists(filepath):
        return jsonify({'error': 'File already exists'}), 400
    
    # Шаблон нового файла
    new_file_content = {
        "pattern": "",
        "flag": "",
        "std": None,
        "active": True,
        "action": "mark"
    }
    
    try:
        with open(filepath, 'w') as f:
            json.dump(new_file_content, f, indent=2)
        return jsonify({'success': True, 'filename': filename})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file', methods=['POST'])
@editor_login_required
def api_save_file():
    data = request.json
    filename = data.get('filename')
    content = data.get('content')
    
    if not valid_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400
    
    try:
        # Валидация JSON и обязательных полей
        pattern_data = json.loads(content)
        required_fields = ['pattern', 'flag', 'std', 'active', 'action']
        if not all(field in pattern_data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        if pattern_data['action'] not in ['mark', 'ban']:
            return jsonify({'error': 'Invalid action type'}), 400
        re.compile(pattern_data['pattern'])  # Проверка regex
    except re.error as e:
        return jsonify({'error': f'Invalid regex: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Invalid JSON: {str(e)}'}), 400
    
    try:
        with open(os.path.join(EDITABLE_DIRECTORY, filename), 'w') as f:
            f.write(content)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file', methods=['DELETE'])
@editor_login_required
def api_delete_file():
    filename = request.json.get('filename')
    if not valid_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400
    
    filepath = os.path.join(EDITABLE_DIRECTORY, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        os.remove(filepath)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Функции и маршруты для экспорта
def should_print(text):
    pattern_flag = r'[A-Z0-9]{31}='
    pattern_addr = r'0x[a-f0-9]+'

    non_printable = False
    for i in text:
        if (i < 0x20 and (i < 0x07 or i > 0x0d)) or i > 0x7e:
            non_printable = True
            break

    return non_printable or re.search(pattern_flag, text.decode()) or re.search(pattern_addr, text.decode())

def generate_export_data(id):
    session_db = SessionLocal()
    try:
        result = session_db.execute(select(Streams).filter_by(id=id))
        if not (stream_info := result.scalar_one_or_none()):
            raise Exception('Stream not found')
        
        process = json.loads(b64d(stream_info.stream).decode())
        if len(process) == 1 and process[0][0] == 1:
            raise Exception('Nothing to do')

        file_data = 'import sys\nfrom pwn import *\n\n'
        file_data += 'io = remote(sys.argv[1], target_port)\n# io = process(["./binary_name"])\n\n'

        if len(process) == 1 and process[0][0] == 0:
            return file_data + f"io.send(b'{str(b64d(process[0][2]))[2:-1]}')\n\nio.interactive()"

        skip = False
        for i in range(len(process)):
            if skip:
                skip = False
                continue
                
            if process[i][0] == 0:
                if i == 0:
                    file_data += f"io.send(b'{str(b64d(process[i][2]))[2:-1]}')\n"
                else:
                    prev_data = str(b64d(process[i-1][2]))[2:-1]
                    curr_data = str(b64d(process[i][2]))[2:-1]
                    suffix = prev_data[-10:] if process[i-1][1] > 10 else prev_data
                    file_data += f"io.sendafter(b'{suffix}', b'{curr_data}')\n"
            else:
                if should_print(b64d(process[i][2])):
                    file_data += 'print(io.recv(), flush=True)\n'
                    if i+1 < len(process) and process[i+1][0] == 0:
                        file_data += f"io.send(b'{str(b64d(process[i+1][2]))[2:-1]}')\n"
                        skip = True

        return file_data + '\nio.interactive()'
    except Exception as e:
        raise Exception(f'Export error: {str(e)}')
    finally:
        session_db.close()

@app.route('/export_sploit/<int:id>')
@site_login_required
def export_text(id):
    try:
        data = generate_export_data(id)
        filename = f"splo_{id}.py"
        filepath = os.path.join("/tmp", filename)

        with open(filepath, "w", encoding="utf-8") as file:
            file.write(data)

        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype="text/plain"
        )
    except Exception as e:
        return f"Ошибка при экспорте: {str(e)}", 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=WEB_PORT)