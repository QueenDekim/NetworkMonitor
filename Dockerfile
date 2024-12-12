FROM python:3.13-slim

RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /

COPY requirements.txt ./
COPY base.sql ./
COPY wait-for-it.sh /usr/bin/wait-for-it.sh
RUN chmod +x /usr/bin/wait-for-it.sh

RUN python -m venv venv

RUN . venv/bin/activate && pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

COPY . .

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

CMD ["/bin/bash", "-c", "echo \"Waiting db...\" && /usr/bin/wait-for-it.sh db:3306 -- && . venv/bin/activate && python network_monitor.py --db_host $DB_HOST --db_user $DB_USER --db_password $DB_PASSWORD --db_name $DB_NAME --venv_path \"./venv\" --flask_host $FLASK_HOST --flask_port $FLASK_PORT --flask_debug $FLASK_DEBUG --default_network $NETWORK --default_ports $PORTS --default_interval $INTERVAL --spd_test $SPD_TEST && . venv/bin/activate && python network_monitor.py --network $NETWORK --ports $PORTS --interval $INTERVAL || { echo 'Error occurred during configuration'; exit 1; }"]