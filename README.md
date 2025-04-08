## Защита от атак на бинарные сервисы на CTF

Изначально задуманная программа переросла в систему мониторинга для использования в attack-defense ctf.

---

Добавлен модуль для ядра Линукс, который будет перехватывать системные вызовы sys_read и sys_write, чтобы нельзя было писать или читать non printable символы (чтобы не переписывать сервис на питон).
Для запуска [kernel_module](https://github.com/alexevgmart/pwn_defense_for_ctf/tree/main/kernel_module) необходимо выполнить:
```bash
sudo apt install build-essential linux-headers-$(uname -r) kmod
make
sudo insmod read_and_write.ko target=имена_файлов_через_запятую monitor=имя_файла_в_который_скомпилировали_user.c
```

---

Далее запускаем программу которая будет передавать данные на сервер:
```bash
./user server_ip server_port
```

---

Модуль был дополнен программой в пользовательском пространстве, в которую приходит весь ввод и вывод (взаимодействие пользователя с программой). На данный момент все это дело дополнилось веб интерфейсом([server](https://github.com/alexevgmart/pwn_defense_for_ctf/tree/main/server)) для удобного взаимодействия, необходимые зависимости: `pip install flask sqlalchemy pymysql`.
Запуск сервера:
```bash
python3 -m venv server_env
source server_env/bin/activate
pip install flask sqlalchemy pymysql
python3 main.py # запускает web_server.py и tcp_server.py одновременно
```

---

Для сервисов работающих по HTTP была написана небольшая прокси:
```bash
go build .
./pseudo_http_proxy
```

---

Программа вряд ли подойдет для использования в реальных задачах, но будут примитивы которые как правило используются в CTF.
