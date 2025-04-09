FROM python:3.9

WORKDIR /app
COPY . .

RUN pip install flask pymysql sqlalchemy dotenv

CMD ["python", "web_server.py"]
