import socket
import base64
import struct
import json
import os
import re
from sqlalchemy import create_engine, Column, Integer, Text, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv

load_dotenv()

TCP_PORT = int(os.environ.get('TCP_PORT', 8081))
DB_URL = os.environ['DB_URL']
EDITABLE_DIRECTORY = os.environ['EDITABLE_DIRECTORY']

Base = declarative_base()

class Streams(Base):
    __tablename__ = 'streams'
    id = Column(Integer, primary_key=True, autoincrement=True)
    stream = Column(Text, nullable=False)

# Синхронный движок и сессия
engine = create_engine(DB_URL, echo=True)
SessionLocal = sessionmaker(bind=engine)

# Функции для работы с паттернами
def load_banned_patterns():
    patterns = []
    for filename in os.listdir(EDITABLE_DIRECTORY):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(EDITABLE_DIRECTORY, filename), 'r') as f:
                    pattern = json.load(f)
                    if not all(key in pattern for key in ['pattern', 'flag', 'std', 'active', 'action']):
                        continue
                    if pattern['action'] != 'ban' or pattern['active'] != True:
                        continue
                    try:
                        re.compile(pattern['pattern'])
                        patterns.append(pattern)
                    except:
                        continue
            except Exception as e:
                print(f"Error loading pattern {filename}: {e}")
    return patterns

def create_tables():
    Base.metadata.create_all(bind=engine)

def insert_stream(stream):
    session = SessionLocal()
    try:
        new_stream = Streams(stream=stream)
        session.add(new_stream)
        session.commit()
    finally:
        session.close()

def start_server(host='0.0.0.0', port=TCP_PORT):
    create_tables()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Сервер запущен на {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        # print(f"Подключен клиент: {client_address}")
        stream = []

        while True:
            try:
                std_data = client_socket.recv(1)
                if not std_data or std_data == b'\xff':
                    break

                data_len_data = client_socket.recv(8)
                if not data_len_data:
                    break

                data_len = struct.unpack('<Q', data_len_data)[0]

                data = client_socket.recv(data_len)
                if not data:
                    break

                std = std_data[0]
                data = base64.b64encode(data).decode()
                stream.append([std, data_len, data])

            except Exception as e:
                print(f"Ошибка при обработке данных: {e}")
                break

        stream_to_db = base64.b64encode(str(json.dumps(stream)).encode())
        insert_stream(stream_to_db)

        banned_patterns = load_banned_patterns()
        client_socket.send(bytes([len(banned_patterns)]))

        if len(banned_patterns) == 0:
            client_socket.close()
            continue

        for item in banned_patterns:
            if item['std'] in [0, 1]:
                client_socket.send(bytes([item['std']]))
            else:
                client_socket.send(bytes([2]))
            client_socket.send(bytes([len(item['pattern'])]))
            client_socket.send(item['pattern'].encode())

        client_socket.close()

        session = SessionLocal()
        try:
            result = session.execute(text('SELECT COUNT(*) FROM streams'))
            print('number of streams: ', result.scalar())
        finally:
            session.close()

if __name__ == "__main__":
    while True:
        try:
            start_server()
        except Exception as ex:
            print(f'error: {ex}')