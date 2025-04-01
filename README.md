## Защита от атак на бинарные сервисы на CTF

Программа представляет собой динамическую библиотеку, которая загружается через LD_PRELOAD и перехватывает вызовы функций из libc.
На данный момент есть защита от форматной строки в printf, double free и небезопасного strcpy (но это не точно). Дальше больше ...
По поводу strcpy: Если за переменной которую хотят переполнить на стеке не лежит никаких данных или в ней уже есть данные, то переполнение получится сделать (но будет запрещено писать не печатающиеся символы), в остальных случаях нет.

---

Добавлен модуль для ядра Линукс, который будет перехватывать системные вызовы sys_read и sys_write, чтобы нельзя было писать или читать non printable символы.
Для запуска [kernel_module](https://github.com/alexevgmart/pwn_defense_for_ctf/tree/main/kernel_module) необходимо выолпнить:
```shell
sudo apt install build-essential linux-headers-$(uname -r) kmod
make
sudo insmod read_and_write.ko target_file=имя_файла_для_которого_применять_правила
```
Модуль был дополнен программой в пользовательском пространстве, в которую приходит весь ввод и вывод (взаимодействие пользователя с программой). На данный момент все это дело дополнилось веб интерфейсом([server](https://github.com/alexevgmart/pwn_defense_for_ctf/tree/main/server)) для удобного взаимодействия, необходимые зависимости: `pip install flask sqlalchemy pymysql aiomysql`.

---

Программа вряд ли подойдет для использования в реальных задачах, но будут примитивы которые как правило используются в CTF.
