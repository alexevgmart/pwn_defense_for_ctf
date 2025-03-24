from flask import Flask, render_template, send_file
from sqlalchemy import create_engine, Column, Integer, Text, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.future import select
from config import config
from base64 import b64decode as b64d
import json
import os
import re

app = Flask(__name__)

engine = create_engine(config['db_url_web'], echo=True)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()
class Streams(Base):
    __tablename__ = 'streams'
    id = Column(Integer, primary_key=True, autoincrement=True)
    stream = Column(Text, nullable=False)


def get_flags_in_stream(stream):
    pattern_flag = r'[A-Z0-9]{31}='
    pattern_addr = r'0x[a-f0-9]+'

    parsed_data = json.loads(b64d(stream).decode())
    flags = set()

    for item in parsed_data:
        std, length, base64_str = item
        decoded_str = str(b64d(base64_str))[2:-1]

        if re.search(pattern_flag, decoded_str):
            if std == 0:
                flags.add('inbound_flag')
            elif std == 1:
                flags.add('flag')

        if re.search(pattern_addr, decoded_str):
            flags.add('addr')

        try:
            b64d(base64_str).decode()
        except:
            flags.add('non_printable')

    return flags

@app.route('/streams', methods=['GET'])
def get_streams():
    session = SessionLocal()
    try:
        result = session.execute(text("SELECT id, stream FROM streams"))
        streams = result.fetchall()

        if streams:
            streams_data = []
            for row in streams:
                id, data = row
                try:
                    flags = get_flags_in_stream(data)

                    streams_data.append({
                        "id": id,
                        "flags": list(flags) if flags else []
                    })
                except Exception as e:
                    streams_data.append({
                        "id": id,
                        "flags": []
                    })

            return render_template('streams.html', streams=streams_data[::-1])
        else:
            return "No streams found"
    finally:
        session.close()

@app.route('/streams/<int:id>', methods=['GET'])
def get_stream_by_id(id):
    session = SessionLocal()
    try:
        result = session.execute(select(Streams).filter_by(id=id))
        stream_info = result.scalar_one_or_none()
        if stream_info:
            return render_template('stream.html', data=stream_info.stream)
        else:
            return "Stream not found", 404
    finally:
        session.close()

def should_print(text):
    pattern_flag = r'[A-Z0-9]{31}='
    pattern_addr = r'0x[a-f0-9]+'

    non_printable = False
    for i in text:
        if (i < 0x20 and (i < 0x07 or i > 0x0d)) or i > 0x7e:
            non_printable = True
            break

    if non_printable:
        return True
    else:
        return re.search(pattern_flag, text.decode()) or re.search(pattern_addr, text.decode())

def generate_export_data(id):
    process = None
    session = SessionLocal()
    try:
        result = session.execute(select(Streams).filter_by(id=id))
        stream_info = result.scalar_one_or_none()
        if stream_info:
            process = stream_info.stream
        else:
            raise Exception('DB error')
    except:
        raise Exception('DB error')

    process = json.loads(b64d(process).decode())

    if len(process) == 1 and process[0][0] == 1:
        raise Exception('nothing to do')

    file_data = 'import sys\n'
    file_data += 'from pwn import *\n\n'
    file_data += 'io = remote(sys.argv[1], target_port)\n# io = process(["./binary_name"])\n\n'

    if len(process) == 1 and process[0][0] == 0:
        file_data += f"io.send(b'{str(b64d(process[0][2]))[2:-1]}')\n\nio.interactive()"
        return file_data

    skip = False
    for i in range(len(process)):
        if skip:
            skip = False
            continue
        if process[i][0] == 0:
            if i == 0:
                file_data += f"io.send(b'{str(b64d(process[0][2]))[2:-1]}')\n"
            else:
                if process[i - 1][1] > 10:
                    file_data += f"io.sendafter(b'{str(b64d(process[i - 1][2]))[2:-1][-10:]}', b'{str(b64d(process[i][2]))[2:-1]}')\n"
                else:
                    file_data += f"io.sendafter(b'{str(b64d(process[i - 1][2]))[2:-1]}', b'{str(b64d(process[i][2]))[2:-1]}')\n"
        else:
            if i == 0 and should_print(b64d(process[0][2])):
                file_data += 'print(io.recv())\n'
            elif i > 0 and should_print(b64d(process[i][2])) and i + 1 < len(process):
                file_data += 'print(io.recv())\n'
                file_data += f"io.send(b'{str(b64d(process[i + 1][2]))[2:-1]}')\n"
                skip = True
            elif i + 1 == len(process):
                file_data += 'print(io.recv())\n'

    file_data += '\nio.interactive()'
    return file_data

@app.route('/export_sploit/<int:id>')
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
    app.run(host='0.0.0.0', port=config['web_port'])