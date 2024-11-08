![GitHub top language](https://img.shields.io/github/languages/top/QueenDekim/NetworkMonitor)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/QueenDekim/NetworkMonitor?label=commits)
![GitHub Repo stars](https://img.shields.io/github/stars/QueenDekim/NetworkMonitor)

# NetworkMonitor(nmap) + RestAPI(flusk)

```shell
git clone https://github.com/QueenDekim/NetworkMonitor.git
cd ./NetworkMonitor
pip install -r requirements.txt
```

Install `mysql` and execute the command from the `base.sql` file in it

Install `nmap`:
 - Windows - [installer (exe)](https://nmap.org/dist/nmap-7.95-setup.exe)
 - Ubuntu - `sudo apt install nmap`

In the `config.py` file change the login details in `MySQL` and flask configuration:
```py
DB_CONFIG = {
    'host': 'localhost',
    'user': 'user',
    'password': 'password',
    'database': 'network_monitoring'
}

FLASK_CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 5000,
    'DEBUG': True
}
```

first run `network_monitor.py` and specify the network and ports to scan
For example:
```shell
Enter the network to scan (e.g., 192.168.1.0/24): 10.10.123.0/24
Enter the ports to scan (e.g., 22,80,443): 22,80,443
Scan interval (minutes)  (e.g., 1): 0.33
[nmap] Starting scan on network 10.10.123.0/24 with ports 22,80,443...
[nmap] Scan completed.
[db] Connecting to Database...
[db] Database connection established.
[nmap] Found device: 10.10.123.1
[db] Updated information about 10.10.123.1
[nmap] Found device: 10.10.123.7
[db] Updated information about 10.10.123.7
[nmap] Found device: 10.10.123.8
[db] Updated information about 10.10.123.8
[nmap] Found device: 10.10.123.9
[db] Updated information about 10.10.123.9
[db] Database updated successfully.
[db] Connection closed.
[Info] Waiting for 19.8 seconds before next scan...
```
Then run `rest_api.py`

after information about the found devices appears in the `network_monitor.py` console, try making a `GET` request to `<your ip>:<port(default 5000)>/api/scans`

We receive the response in `Json` format:
```json
[
  1,
  "10.10.123.1",
  "up",
  "{\"ports\": [{\"name\": \"ssh\", \"port\": 22, \"state\": \"closed\", \"product\": \"\", \"version\": \"\"}, {\"name\": \"http\", \"port\": 80, \"state\": \"closed\", \"product\": \"\", \"version\": \"\"}, {\"name\": \"https\", \"port\": 443, \"state\": \"closed\", \"product\": \"\", \"version\": \"\"}], \"hostname\": \"\"}",
  "Fri, 08 Nov 2024 07:07:50 GMT"
],
```

|                                                links                                                                         |                                 description                                         |
|:----------------------------------------------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------:|
|[![Static Badge](https://img.shields.io/badge/Discord-from__russia__with__love-purple)](https://about:blank)                  |                                My Discord tag                                       |
|[![Static Badge](https://img.shields.io/badge/Telegram-%40QueenDek1m-blue)](https://t.me/QueenDek1m)                          |                                  My telegram                                        |
