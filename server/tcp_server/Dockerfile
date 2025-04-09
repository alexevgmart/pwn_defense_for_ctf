FROM python:3.9

WORKDIR /app
COPY . .

RUN pip install pymysql sqlalchemy dotenv

CMD ["python", "tcp_server.py"]
