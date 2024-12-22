import os

DB_CONFIG = {
    "host": "db",
    "user": "root",
    "password": "mysecretpassword",
    "database": "network_monitoring"
}

VENV = {
    "PATH": os.path.join(".", "venv"),
    "API_KEY": "",
    "VERSION": "1.1.4"
}

FLASK_CONFIG = {
    'HOST': '0.0.0.0', 
    'PORT': 5000, 
    'DEBUG': True
}

SCAN_CONFIG = {
    'DEFAULT_NETWORK': '192.168.1.0/24',
    'DEFAULT_PORTS': '22,80,443',
    'DEFAULT_INTERVAL': 1.0,
    'SPD_TEST': True
}