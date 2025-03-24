import multiprocessing
import subprocess

def start_web_server():
    subprocess.run(['python3', 'web_server.py'])

def start_tcp_server():
    subprocess.run(['python3', 'tcp_server.py'])

if __name__ == '__main__':
    tcp_process = multiprocessing.Process(target=start_tcp_server)
    tcp_process.start()

    web_process = multiprocessing.Process(target=start_web_server)
    web_process.start()

    tcp_process.join()
    web_process.join()