FROM python:3.13-slim

# Установка необходимых пакетов
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Установка рабочей директории
WORKDIR /

# Копирование файлов в контейнер
COPY requirements.txt ./
COPY base.sql ./
COPY wait-for-it.sh /usr/bin/wait-for-it.sh
RUN chmod +x /usr/bin/wait-for-it.sh

# Создание виртуального окружения
RUN python -m venv venv

# Установка зависимостей
RUN . venv/bin/activate && pip install --no-cache-dir -r requirements.txt

# Открытие порта
EXPOSE 5000

# Копирование всего содержимого приложения
COPY app ./app

# Установка переменных окружения
ENV NETWORK="192.168.1.0/24"
ENV PORTS="22,443,80"
ENV INTERVAL="1.0"
ENV DB_HOST="db"
ENV DB_USER="root"
ENV DB_PASSWORD="mysecretpassword"
ENV DB_NAME="network_monitoring"
ENV FLASK_HOST="0.0.0.0"
ENV FLASK_PORT="5000"
ENV FLASK_DEBUG="True"
ENV SPD_TEST="True"

# Команда запуска приложения
CMD ["/bin/bash", "-c", "echo \"Waiting db...\" && /usr/bin/wait-for-it.sh db:3306 -- && . venv/bin/activate && python ./app/network_monitor.py --config --db_host $DB_HOST --db_user $DB_USER --db_password $DB_PASSWORD --db_name $DB_NAME --flask_host $FLASK_HOST --flask_port $FLASK_PORT --flask_debug $FLASK_DEBUG --default_network $NETWORK --default_ports $PORTS --default_interval $INTERVAL --spd_test $SPD_TEST && . venv/bin/activate && python ./app/network_monitor.py --scan --network $NETWORK --ports $PORTS --interval $INTERVAL --no-progressbar || { echo 'Error occurred during configuration'; exit 1; }"]