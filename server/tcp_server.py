import socket
import base64
import struct
import json
import asyncio

from config import config

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, Text, text

Base = declarative_base()
class Streams(Base):
    __tablename__ = 'streams'

    id = Column(Integer, primary_key=True, autoincrement=True)
    stream = Column(Text, nullable=False)


engine = create_async_engine(config['db_url_tcp'], echo=True)
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def insert_stream(stream):
    async with AsyncSessionLocal() as session:
        new_stream = Streams(stream=stream)
        session.add(new_stream)
        await session.commit()


async def start_server(host='0.0.0.0', port=config['tcp_port']):
    await create_tables()

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
                if not std_data:
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
                # print(f"Получено сообщение: std={std}, data_len={data_len}, data={data}")
                stream.append([std, data_len, data])

            except Exception as e:
                print(f"Ошибка при обработке данных: {e}")
                break

        client_socket.close()
        # print(f"Клиент {client_address} отключился")
        stream_to_db = base64.b64encode(str(json.dumps(stream)).encode()) # так будут храниться в бд
        await insert_stream(stream_to_db)

        async with AsyncSessionLocal() as session:
            result = await session.execute(text(f'SELECT COUNT(*) FROM streams'))
            print('number of streams: ', result.scalar())

        # print(json.loads(base64.b64decode(stream_to_db).decode())) # такие будут отправляться на фронт

if __name__ == "__main__":
    asyncio.run(start_server())