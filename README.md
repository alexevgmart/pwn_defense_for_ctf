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
Его нужно запускать на одном хосте со всеми сервисами

---

Далее запускаем программу которая будет передавать данные на сервер:
```bash
./user server_ip server_port
```
Нужно запускать там же где и модуль ядра

---

Веб интерфейс собирается через
```bash
docker-compose up -d --build
```
Нужно запускать на отдельном хосте, чтобы не было доступа из общей сетки

---

Для сервисов работающих по HTTP была написана небольшая прокси:
```bash
go build .
./pseudo_http_proxy <web_app_ip> <web_app_port>
```
На данный момент нужно запсукать на одном хосте с сервисами, потому что пока что нет прокси которая будет прокидывать не только http пакеты (из-за этого в services.json в [server/web_app](https://github.com/alexevgmart/pwn_defense_for_ctf/tree/main/server/web_app) пока что для не http сервисов `service_addr` нужно указывать `127.0.0.1`)

---
