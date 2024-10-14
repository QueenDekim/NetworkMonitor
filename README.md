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

In the `.py` files change the login details in `MySQL`:
```py
conn = mysql.connector.connect(
    host='localhost',
    user='username',
    password='password',
    database='network_monitoring'
)
```

in the `rest_api.py` file we configure `Flusk`, or leave it as is:
```
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5150)
```

first run `network_monitor.py` and specify the network and ports to scan, then run `rest_api.py`
For example:
```
Enter the network to scan (e.g., 192.168.1.0/24): 192.168.0.0/24
Enter the ports to scan (e.g., 22,80,443): 21,22,80,443,137-139
Starting scan on network 192.168.0.0/24 with ports 21,22,80,443,137-139...
Scan completed.
Found device: 192.168.0.1
Found device: 192.168.0.100
Found device: 192.168.0.101
Found device: 192.168.0.102
Found device: 192.168.0.103
Found device: 192.168.0.104
Found device: 192.168.0.106
Found device: 192.168.0.107
Found device: 192.168.0.128
Found device: 192.168.0.129
Found device: 192.168.0.140
Waiting for 2 minutes before next scan...
```

after information about the found devices appears in the `network_monitor.py` console, try making a `GET` request to `<your ip>:<port(default 5150)>/api/scans`

We receive the response in `Json` format:
```
{
    "device_info": "{\"ports\": [{\"name\": \"ftp\", \"port\": 21, \"state\": \"filtered\", \"product\": \"\", \"version\": \"\"}], \"hostname\": \"\"}",
    "id": 1,
    "ip": "192.168.0.1",
    "status": "up",
    "timestamp": "Mon, 14 Oct 2024 09:38:47 GMT"
},
```

|                                                links                                                                         |                                 description                                         |
|:----------------------------------------------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------:|
|[![Static Badge](https://img.shields.io/badge/Discord-from__russia__with__love-purple)](https://about:blank)                  |                                My Discord tag                                       |
|[![Static Badge](https://img.shields.io/badge/Telegram-%40QueenDek1m-blue)](https://t.me/QueenDek1m)                          |                                  My telegram                                        |
